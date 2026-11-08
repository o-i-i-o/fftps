//! 首次启动 setup 引导：一次性令牌与回环校验
//!
//! 未配置管理员账户时，服务只允许绑定回环地址并进入引导模式。启动时生成
//! 一次性令牌写入运行时/状态目录（0600），`fftp-http launch` 读取后把
//! `?token=...` 拼到 `/setup` 链接。设置完成后令牌立即删除，setup 路由失效。
//!
//! 令牌文件位置：
//! - Linux/macOS: `$XDG_RUNTIME_DIR/fftpd/setup-token`（无 XDG 时 /tmp/fftpd-<uid>）
//! - Windows: `%ProgramData%\fftpd\setup-token`

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Context, Result};

/// 令牌文件路径（父目录由 [`ensure_token`] 创建）
#[must_use]
pub fn token_path() -> PathBuf {
    #[cfg(windows)]
    {
        fftp_common::paths::state_dir().join("setup-token")
    }
    #[cfg(not(windows))]
    {
        fftp_common::paths::runtime_dir().join("setup-token")
    }
}

/// 确保存在一次性令牌并返回；已有非空令牌时复用
///
/// # Errors
/// 目录创建或文件写入失败时返回错误
pub fn ensure_token() -> Result<String> {
    if let Some(token) = read_token() {
        return Ok(token);
    }
    let token = format!(
        "{:032x}{:032x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    );
    let path = token_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建 setup 令牌目录失败: {}", parent.display()))?;
    }
    std::fs::write(&path, &token)
        .with_context(|| format!("写入 setup 令牌失败: {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}

/// 读取令牌（不存在或为空时返回 `None`）
#[must_use]
pub fn read_token() -> Option<String> {
    std::fs::read_to_string(token_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// 删除令牌（setup 完成后调用）
pub fn clear_token() {
    let _ = std::fs::remove_file(token_path());
}

/// 请求是否来自回环地址（含 IPv4-mapped IPv6）
#[must_use]
pub fn is_loopback(peer: SocketAddr) -> bool {
    match peer.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback("127.0.0.1:1".parse().unwrap()));
        assert!(is_loopback("[::1]:1".parse().unwrap()));
        assert!(!is_loopback("192.168.1.2:1".parse().unwrap()));
    }
}

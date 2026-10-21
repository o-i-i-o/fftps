//! 跨平台路径解析（用户态运行模型，docs/design.md §5.3）
//!
//! 前后端程序均以当前桌面登录用户运行，路径解析按平台分支：
//!
//! | 用途     | Linux                                                          | Windows                      |
//! |----------|----------------------------------------------------------------|------------------------------|
//! | 配置     | env 覆盖 > 二进制同目录 `config.toml`（存在即用、可写即默认生成，便于测试）> `$XDG_CONFIG_HOME/fftpd`（默认 `~/.config/fftpd`） | env 覆盖 > 二进制同目录 > `%ProgramData%\fftpd` |
//! | 持久状态 | `$XDG_STATE_HOME/fftpd`（默认 `~/.local/state/fftpd`，日志、SSH 主机密钥） | `%ProgramData%\fftpd`        |
//! | 运行时   | `$XDG_RUNTIME_DIR/fftpd/fftpd.sock`（默认 `/tmp/fftpd-$UID`）   | 命名管道 `\\.\pipe\fftpd`    |
//!
//! 环境变量 `FFTPD_CONFIG_DIR` / `FFTPD_STATE_DIR` 可强制覆盖配置与状态目录，
//! 便于测试与多实例共存。

use std::path::PathBuf;

/// 环境变量覆盖目录（`FFTPD_CONFIG_DIR` / `FFTPD_STATE_DIR`），空值视为未设置
fn override_dir(env_var: &str) -> Option<PathBuf> {
    std::env::var_os(env_var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

// ---------- Linux（XDG 规范） ----------

/// 当前用户主目录（`HOME` 未设置时回退到 `/`）
#[cfg(unix)]
#[must_use]
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("/"), PathBuf::from)
}

#[cfg(unix)]
fn xdg_dir(env_var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(env_var)
        .filter(|v| !v.is_empty())
        .map_or_else(|| home_dir().join(fallback), PathBuf::from)
}

/// 配置目录（users.json、用户公钥目录；config.toml 见 [`config_path`]）
#[cfg(unix)]
#[must_use]
pub fn config_dir() -> PathBuf {
    override_dir("FFTPD_CONFIG_DIR")
        .unwrap_or_else(|| xdg_dir("XDG_CONFIG_HOME", ".config").join("fftpd"))
}

/// 配置文件路径，按顺序解析：
///
/// 1. `FFTPD_CONFIG_DIR` 环境变量覆盖（测试/多实例）；
/// 2. 二进制同目录 `config.toml`——存在即使用；目录可写（如 `cargo build`
///    产物所在的 `target/`）时，缺失的默认配置也生成到这里，便于直接运行
///    二进制做测试。安装形态的二进制位于 `/usr/bin`，对桌面用户不可写，
///    自然落到 3；root 跳过本层，避免污染系统目录；
/// 3. 用户 XDG 配置目录（deb 安装形态，postinst 已预置初始配置）。
#[cfg(unix)]
#[must_use]
pub fn config_path() -> PathBuf {
    if let Some(dir) = override_dir("FFTPD_CONFIG_DIR") {
        return dir.join("config.toml");
    }

    if !nix::unistd::getuid().is_root()
        && let Some(exe_dir) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
    {
        let candidate = exe_dir.join("config.toml");
        let dir_writable = nix::unistd::access(&exe_dir, nix::unistd::AccessFlags::W_OK).is_ok();
        if candidate.is_file() || dir_writable {
            return candidate;
        }
    }

    config_dir().join("config.toml")
}

/// 持久状态目录（日志、SSH 主机密钥等跨重启保留的数据）
#[cfg(unix)]
#[must_use]
pub fn state_dir() -> PathBuf {
    override_dir("FFTPD_STATE_DIR")
        .unwrap_or_else(|| xdg_dir("XDG_STATE_HOME", ".local/state").join("fftpd"))
}

/// 运行时目录（UDS 套接字等生命周期与登录会话一致的数据）
#[cfg(unix)]
#[must_use]
pub fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        PathBuf::from(dir).join("fftpd")
    } else {
        let uid = nix::unistd::getuid();
        PathBuf::from(format!("/tmp/fftpd-{uid}"))
    }
}

/// 前后端 UDS 套接字路径
#[cfg(unix)]
#[must_use]
pub fn socket_path() -> PathBuf {
    runtime_dir().join("fftpd.sock")
}

// ---------- Windows（ProgramData + 命名管道） ----------

/// `%ProgramData%` 根目录（环境变量缺失时回退 `C:\ProgramData`）
#[cfg(windows)]
#[must_use]
pub fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
}

/// 当前用户主目录（`USERPROFILE` 未设置时回退 `C:\`）
#[cfg(windows)]
#[must_use]
pub fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from(r"C:\"), PathBuf::from)
}

/// 配置目录（users.json、用户公钥目录；config.toml 见 [`config_path`]）
#[cfg(windows)]
#[must_use]
pub fn config_dir() -> PathBuf {
    override_dir("FFTPD_CONFIG_DIR").unwrap_or_else(|| program_data_dir().join("fftpd"))
}

/// 配置文件路径，按顺序解析：
///
/// 1. `FFTPD_CONFIG_DIR` 环境变量覆盖（测试/多实例）；
/// 2. 二进制同目录 `config.toml`——存在即使用；目录可写时缺失的默认配置也
///    生成到这里，便于直接运行二进制做测试（绿色版/便携版形态）；
/// 3. `%ProgramData%\fftpd`（服务安装形态）。
#[cfg(windows)]
#[must_use]
pub fn config_path() -> PathBuf {
    if let Some(dir) = override_dir("FFTPD_CONFIG_DIR") {
        return dir.join("config.toml");
    }

    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
    {
        let candidate = exe_dir.join("config.toml");
        let dir_writable = std::fs::metadata(&exe_dir)
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false);
        if candidate.is_file() || dir_writable {
            return candidate;
        }
    }

    config_dir().join("config.toml")
}

/// 持久状态目录（日志、SSH 主机密钥等跨重启保留的数据）
#[cfg(windows)]
#[must_use]
pub fn state_dir() -> PathBuf {
    override_dir("FFTPD_STATE_DIR").unwrap_or_else(|| program_data_dir().join("fftpd"))
}

/// 运行时目录（Windows 命名管道不占用文件系统路径，仅给出管道所在“目录”）
#[cfg(windows)]
#[must_use]
pub fn runtime_dir() -> PathBuf {
    PathBuf::from(r"\\.\pipe")
}

/// 前后端命名管道路径（`\\.\pipe\fftpd`）
#[cfg(windows)]
#[must_use]
pub fn socket_path() -> PathBuf {
    PathBuf::from(r"\\.\pipe\fftpd")
}

// ---------- 跨平台派生路径 ----------

#[must_use]
pub fn users_path() -> PathBuf {
    config_dir().join("users.json")
}

/// SFTP 公钥认证的用户密钥目录（`<keys_dir>/<username>/authorized_keys`）
#[must_use]
pub fn keys_dir() -> PathBuf {
    config_dir().join("keys")
}

#[must_use]
pub fn default_log_dir() -> PathBuf {
    state_dir().join("logs")
}

#[must_use]
pub fn default_host_key_path() -> PathBuf {
    state_dir().join("ssh").join("ssh_host_ed25519_key")
}

#[must_use]
pub fn audit_log_path() -> PathBuf {
    default_log_dir().join("audit.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paths_are_scoped_to_fftpd() {
        assert!(config_path().ends_with("config.toml"));
        assert!(users_path().ends_with("users.json"));
        assert!(default_host_key_path().ends_with("ssh_host_ed25519_key"));
        assert!(config_dir().ends_with("fftpd"));
    }

    #[test]
    #[cfg(unix)]
    fn test_socket_path_uses_fftpd_sock() {
        assert!(socket_path().ends_with("fftpd.sock"));
    }

    #[test]
    #[cfg(windows)]
    fn test_socket_path_uses_named_pipe() {
        assert!(socket_path().ends_with("fftpd"));
    }

    #[test]
    #[cfg(unix)]
    fn test_config_path_binary_dir_resolution() {
        // cargo test 的二进制位于 target/ 下：目录可写且非 root 时，
        // 配置解析到二进制同目录；否则（如 root、只读目录）落到用户 XDG 目录
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let binary_dir_usable = !nix::unistd::getuid().is_root()
            && nix::unistd::access(&exe_dir, nix::unistd::AccessFlags::W_OK).is_ok();

        if binary_dir_usable {
            assert_eq!(config_path(), exe_dir.join("config.toml"));
        } else {
            assert_eq!(config_path(), config_dir().join("config.toml"));
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_config_path_binary_dir_resolution() {
        // 与 Unix 版对应：二进制同目录可写时配置解析到该目录，否则落到 ProgramData
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let binary_dir_usable = std::fs::metadata(&exe_dir)
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false);

        if binary_dir_usable {
            assert_eq!(config_path(), exe_dir.join("config.toml"));
        } else {
            assert_eq!(config_path(), config_dir().join("config.toml"));
        }
    }
}

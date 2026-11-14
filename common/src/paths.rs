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
///
/// 优先 `$XDG_RUNTIME_DIR/fftpd`；缺失时若 `/run/user/<uid>` 存在则使用，
/// 最后才退回 `/tmp/fftpd-<uid>`。实际创建/校验请用 [`ensure_runtime_dir`]。
#[cfg(unix)]
#[must_use]
pub fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir).join("fftpd");
    }

    let uid = nix::unistd::getuid();
    let run_user = PathBuf::from(format!("/run/user/{uid}"));
    if run_user.is_dir() {
        run_user.join("fftpd")
    } else {
        PathBuf::from(format!("/tmp/fftpd-{uid}"))
    }
}

/// 创建并校验运行时目录（0700、属主为当前用户、拒绝符号链接）
///
/// 返回实际使用的目录（与 [`runtime_dir`] 一致）。目录不可信时返回错误，
/// 而不是静默回退，避免 `/tmp/fftpd-<uid>` 被其他用户抢占后劫持套接字/令牌。
///
/// # Errors
/// 目录无法创建，或已存在但属主/类型/权限不可信时返回错误。
#[cfg(unix)]
pub fn ensure_runtime_dir() -> std::io::Result<PathBuf> {
    let dir = runtime_dir();
    ensure_private_dir(&dir, nix::unistd::getuid().as_raw())?;
    Ok(dir)
}

/// 以 0700 创建目录并校验其真实属性
#[cfg(unix)]
fn ensure_private_dir(dir: &std::path::Path, uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    // 父目录（/tmp 除外）必须属于当前用户，防止在他人可控目录中建运行时目录
    if let Some(parent) = dir.parent()
        && parent != std::path::Path::new("/tmp")
    {
        let meta = std::fs::symlink_metadata(parent)?;
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != uid {
            return Err(std::io::Error::other(format!(
                "runtime base directory {} is not a trusted directory",
                parent.display()
            )));
        }
    }

    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(std::io::Error::other(format!(
            "runtime path {} is not a real directory",
            dir.display()
        )));
    }
    if meta.uid() != uid {
        return Err(std::io::Error::other(format!(
            "runtime directory {} is not owned by current user",
            dir.display()
        )));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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

/// 目录是否可写（实际创建探针文件；`readonly` 位在 Windows 上不可靠，
/// 例如 `C:\Program Files` 对普通用户不可写但该位仍为 false）
#[cfg(windows)]
fn dir_writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(".fftpd-write-probe");
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
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
        if candidate.is_file() || dir_writable(&exe_dir) {
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

/// 桌面目录：单用户桌面环境下前端默认建议的 FTP/SFTP 用户根目录
///
/// Linux 为 `~/Desktop`，Windows 为 `C:\Users\<用户>\Desktop`。仅用于
/// 快速填充，管理端仍可填写任意有权限的目录。
#[must_use]
pub fn desktop_dir() -> PathBuf {
    home_dir().join("Desktop")
}

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

/// IPC 认证令牌文件路径
///
/// Unix 位于 0700 运行时目录（随登录会话失效）；Windows 位于状态目录
/// （命名管道无文件系统路径，令牌需跨进程共享）。
#[must_use]
pub fn ipc_token_path() -> PathBuf {
    #[cfg(unix)]
    {
        runtime_dir().join("ipc.token")
    }
    #[cfg(windows)]
    {
        state_dir().join("ipc.token")
    }
}

/// 读取（缺失时生成）IPC 握手令牌
///
/// fftpd 与 fftp-http 以同一用户运行，本文件仅作为纵深防御：它能阻止
/// 其他用户（Unix 权限）或误连的进程调用管理面，但无法抵御已在本用户
/// 上下文执行的攻击者（其本就可读取令牌或直接操作进程）。
///
/// # Errors
/// 运行时目录/状态目录或令牌文件无法创建、读取时返回错误
pub fn load_or_create_ipc_token() -> std::io::Result<String> {
    let path = ipc_token_path();

    if let Ok(existing) = std::fs::read_to_string(&path) {
        let token = existing.trim().to_string();
        if token.len() >= 32 {
            harden_token_permissions(&path)?;
            return Ok(token);
        }
    }

    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("IPC 令牌路径缺少父目录"))?;
    #[cfg(unix)]
    {
        // 令牌与套接字同处 0700 运行时目录
        ensure_runtime_dir()?;
    }
    std::fs::create_dir_all(parent)?;

    let token = format!(
        "{:032x}{:032x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    );
    write_private_file(&path, &token)?;
    Ok(token)
}

/// 以 0600（Unix）原子创建令牌文件；并发创建时复用已存在文件
fn write_private_file(path: &std::path::Path, token: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            file.write_all(token.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // 另一进程已生成：读取并收紧权限
            let existing = std::fs::read_to_string(path)?;
            if existing.trim().len() < 32 {
                return Err(std::io::Error::other("已存在的 IPC 令牌内容非法"));
            }
            harden_token_permissions(path)
        }
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn harden_token_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn harden_token_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// fftp-http 独立配置文件路径（Web 管理前端专用，fftpd 不读取）
///
/// 环境变量 `FFTPD_HTTP_CONFIG` 可整体覆盖（测试/多实例）；
/// 默认与 `config.toml` 同目录（复用 [`config_path`] 的解析规则）。
#[must_use]
pub fn http_config_path() -> PathBuf {
    std::env::var_os("FFTPD_HTTP_CONFIG")
        .filter(|v| !v.is_empty())
        .map_or_else(
            || config_path().with_file_name("fftp-http.toml"),
            PathBuf::from,
        )
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
        assert!(http_config_path().ends_with("fftp-http.toml"));
        assert!(ipc_token_path().ends_with("ipc.token"));
    }

    #[test]
    fn test_desktop_dir_is_under_home() {
        let desktop = desktop_dir();
        assert!(desktop.ends_with("Desktop"));
        assert!(desktop.starts_with(home_dir()));
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
    fn test_ensure_private_dir_creates_0700_and_rejects_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("fftpd");
        let uid = nix::unistd::getuid().as_raw();
        ensure_private_dir(&dir, uid).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // 符号链接不能作为运行时目录
        let link = base.path().join("fftpd-link");
        symlink(&dir, &link).unwrap();
        assert!(ensure_private_dir(&link, uid).is_err());
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
        let binary_dir_usable = dir_writable(&exe_dir);

        if binary_dir_usable {
            assert_eq!(config_path(), exe_dir.join("config.toml"));
        } else {
            assert_eq!(config_path(), config_dir().join("config.toml"));
        }
    }
}

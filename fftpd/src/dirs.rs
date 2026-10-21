//! 目录辅助命令面：用户主目录创建与权限设置
//!
//! 后端是配置/用户数据的唯一写入者，目录准备统一由守护进程完成：
//! Linux 设置属主为当前用户、权限 `0700`（nix）；Windows 仅创建目录。

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use fftp_ipc::server::HandlerError;

use crate::state::AppState;

/// `EnsureUserDirectories`：补齐守护进程目录与各用户主目录
///
/// 返回 `{"created": [...]}`（本次新建的目录列表）。
///
/// # Errors
/// 目录创建失败时返回错误
pub fn ensure_user_directories(state: &AppState) -> Result<Value, HandlerError> {
    let mut candidates: Vec<PathBuf> = vec![
        fftp_common::paths::config_dir(),
        fftp_common::paths::state_dir(),
        fftp_common::paths::default_log_dir(),
        fftp_common::paths::keys_dir(),
    ];

    let users = state.users.lock().unwrap();
    for user in users.get_users().values() {
        if !user.home_dir.trim().is_empty() {
            candidates.push(PathBuf::from(&user.home_dir));
        }
    }
    drop(users);

    let mut created = Vec::new();
    for dir in &candidates {
        if dir.is_dir() {
            continue;
        }
        create_dir(dir)?;
        set_owner_and_mode(dir)?;
        created.push(dir.display().to_string());
    }

    Ok(json!({ "created": created }))
}

/// `CreateUserDirectory`：创建用户目录（含父目录）
///
/// # Errors
/// 路径为空或创建失败时返回错误
pub fn create_user_directory(path: &str) -> Result<Value, HandlerError> {
    let dir = PathBuf::from(path);
    if path.trim().is_empty() {
        return Err(HandlerError::validation("目录路径不能为空"));
    }
    if !dir.is_dir() {
        create_dir(&dir)?;
        set_owner_and_mode(&dir)?;
    }
    Ok(json!({ "path": dir.display().to_string() }))
}

/// `SetupDirectoryPermissions`：设置目录属主与权限
///
/// Linux：属主为当前用户、权限 `0700`；Windows：无需属主概念，保持现状。
///
/// # Errors
/// 路径为空、目录不存在或权限设置失败时返回错误
pub fn setup_directory_permissions(path: &str) -> Result<Value, HandlerError> {
    let dir = PathBuf::from(path);
    if path.trim().is_empty() {
        return Err(HandlerError::validation("目录路径不能为空"));
    }
    if !dir.is_dir() {
        return Err(HandlerError::not_found(format!(
            "目录不存在: {}",
            dir.display()
        )));
    }
    set_owner_and_mode(&dir)?;
    Ok(json!({
        "path": dir.display().to_string(),
        "permissions": permissions_label(),
    }))
}

/// 创建目录（含父目录）
fn create_dir(dir: &Path) -> Result<(), HandlerError> {
    std::fs::create_dir_all(dir).map_err(|e| {
        HandlerError::internal(format!("创建目录 {} 失败: {e}", dir.display()))
    })
}

/// Linux：属主设为当前用户、权限 `0700`；Windows：空实现（合理简化）
fn set_owner_and_mode(dir: &Path) -> Result<(), HandlerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let uid = nix::unistd::Uid::current();
        let gid = nix::unistd::Gid::current();
        nix::unistd::chown(dir, Some(uid), Some(gid)).map_err(|e| {
            HandlerError::internal(format!(
                "设置目录 {} 属主失败: {e}",
                dir.display()
            ))
        })?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            HandlerError::internal(format!(
                "设置目录 {} 权限失败: {e}",
                dir.display()
            ))
        })?;
    }
    #[cfg(windows)]
    {
        let _ = dir; // Windows 无属主/POSIX 权限位概念
    }
    Ok(())
}

#[cfg(unix)]
fn permissions_label() -> &'static str {
    "0700"
}

#[cfg(windows)]
fn permissions_label() -> &'static str {
    "default"
}

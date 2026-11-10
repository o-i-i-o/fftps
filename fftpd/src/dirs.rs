//! 目录辅助命令面：用户主目录创建与权限设置
//!
//! 后端是配置/用户数据的唯一写入者，目录准备统一由守护进程完成：
//! Linux 设置属主为当前用户、权限 `0700`（nix）；Windows 仅创建目录。

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use fftp_common::sync::MutexExt;
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

    let users = state.users.lock_recover();
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
    let dir = validate_directory_path(path)?;
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
    let dir = validate_directory_path(path)?;
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

/// 校验并规范化目录路径
///
/// 目录创建/权限接口会 `create_dir_all` 并 `chown`/`chmod 0700`，若接受任意
/// 绝对路径，管理端可对系统目录动手。用户态服务限定：绝对路径、无 `..`、
/// 位于当前用户主目录下，且既有的目标必须是真实目录而非符号链接。
fn validate_directory_path(path: &str) -> Result<PathBuf, HandlerError> {
    if path.trim().is_empty() {
        return Err(HandlerError::validation("目录路径不能为空"));
    }

    let dir = PathBuf::from(path);
    if !dir.is_absolute() {
        return Err(HandlerError::validation(format!(
            "目录路径必须是绝对路径: {path}"
        )));
    }
    if dir
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(HandlerError::validation(format!(
            "目录路径不能包含 ..: {path}"
        )));
    }

    let home = fftp_common::paths::home_dir();
    // 单元测试使用临时目录（HOME 未指向测试目录），仅在测试构建放开
    #[cfg(test)]
    let allowed = dir.starts_with(&home) || dir.starts_with(std::env::temp_dir());
    #[cfg(not(test))]
    let allowed = dir.starts_with(&home);
    if !allowed {
        return Err(HandlerError::validation(format!(
            "目录必须位于用户主目录 {} 下: {path}",
            home.display()
        )));
    }

    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if meta.file_type().is_symlink() {
            return Err(HandlerError::validation(format!(
                "不允许操作符号链接目录: {path}"
            )));
        }
        if !meta.is_dir() {
            return Err(HandlerError::validation(format!("路径不是目录: {path}")));
        }
    }

    Ok(dir)
}

/// 创建目录（含父目录）
fn create_dir(dir: &Path) -> Result<(), HandlerError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| HandlerError::internal(format!("创建目录 {} 失败: {e}", dir.display())))
}

/// Linux：属主设为当前用户、权限 `0700`；Windows：空实现（合理简化）
fn set_owner_and_mode(dir: &Path) -> Result<(), HandlerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let uid = nix::unistd::Uid::current();
        let gid = nix::unistd::Gid::current();
        nix::unistd::chown(dir, Some(uid), Some(gid)).map_err(|e| {
            HandlerError::internal(format!("设置目录 {} 属主失败: {e}", dir.display()))
        })?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            HandlerError::internal(format!("设置目录 {} 权限失败: {e}", dir.display()))
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

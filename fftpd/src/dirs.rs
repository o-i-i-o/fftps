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
        if user.home_dir.trim().is_empty() {
            continue;
        }
        let home = validate_directory_path(&user.home_dir).map_err(|e| {
            HandlerError::validation(format!(
                "用户 {} 的主目录无效: {}",
                user.username, e.message
            ))
        })?;
        candidates.push(home);
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

/// 校验目录路径的结构与已有目标的有效性
///
/// 目录创建/权限接口会 `create_dir_all` 并 `chown`/`chmod 0700`。管理端可以
/// 填写任意目录（不限于桌面或主目录），但路径必须是绝对路径、不能含 `..`、
/// 不能是文件系统根；已存在的目标必须是真实目录且不能是符号链接（避免把
/// 创建/改权限操作带到链接目标）。目标不存在是允许的：创建接口会补建，
/// 权限接口则返回 NotFound。实际的读写/属主权限由随后的文件操作校验，
/// 失败时返回带系统错误信息的明确提示。
fn validate_directory_path(path: &str) -> Result<PathBuf, HandlerError> {
    let path = path.trim();
    if path.is_empty() {
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
    if dir.parent().is_none() {
        return Err(HandlerError::validation(format!(
            "不能把文件系统根目录当作业务目录: {path}"
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
    std::fs::create_dir_all(dir).map_err(|e| {
        let msg = format!("创建目录 {} 失败: {e}", dir.display());
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            HandlerError::validation(format!("没有权限创建目录：{msg}"))
        } else {
            HandlerError::internal(msg)
        }
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
            let msg = format!("设置目录 {} 属主失败: {e}", dir.display());
            if matches!(e, nix::errno::Errno::EPERM | nix::errno::Errno::EACCES) {
                HandlerError::validation(format!("没有权限修改目录属主：{msg}"))
            } else {
                HandlerError::internal(msg)
            }
        })?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            let msg = format!("设置目录 {} 权限失败: {e}", dir.display());
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                HandlerError::validation(format!("没有权限修改目录权限：{msg}"))
            } else {
                HandlerError::internal(msg)
            }
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

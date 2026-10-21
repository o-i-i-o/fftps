//! SFTP 链接操作：READLINK / SYMLINK
//!
//! 符号链接创建按平台分化：Unix 走 `std::os::unix::fs::symlink`，
//! Windows 按目标类型选 `symlink_file`/`symlink_dir` 并拒绝 junction/reparse 目标。
//! 链接路径与目标都必须落在 home 之内（jail）。
//!
//! 参数序说明：OpenSSH 客户端在 wire 上按 `SYMLINK(target, linkpath)` 发送
//! （与 draft 相反）。协议层按 draft 字段名把首串解析进 `linkpath` 参数，
//! 会话层透传时映射为 [`SftpState::symlink`] 的 `(target, link_path)` 业务参数序。

use std::path::{Path, PathBuf};

use crate::protocol::{File, Name, Status, StatusReply, StatusCode};
use crate::state::{SftpState, status_err, status_ok};

impl SftpState {
    /// `SSH_FXP_READLINK`：读取符号链接目标（应答 `SSH_FXP_NAME`，单条目）
    ///
    /// # Errors
    /// 权限不足、路径越狱或目标不是符号链接时返回错误应答
    pub async fn readlink(&mut self, id: u32, path: String) -> Result<Name, StatusReply> {
        if !self.check_permission(|p| p.can_read || p.can_list) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        // 不跟随符号链接：末段文件名保留，读取链接自身的目标
        let full_path = self.resolve_path_no_follow_or_err(&path)?;

        match tokio::fs::read_link(&full_path).await {
            Ok(target) => {
                let target_str = target.to_string_lossy().to_string();
                Ok(Name {
                    id,
                    files: vec![File::dummy(target_str)],
                })
            }
            Err(e) => {
                tracing::debug!("SFTP READLINK failed for {full_path:?}: {e}");
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    Err(status_err(StatusCode::PermissionDenied, "Permission denied"))
                } else {
                    Err(status_err(StatusCode::NoSuchFile, "No such file"))
                }
            }
        }
    }

    /// `SSH_FXP_SYMLINK`：创建符号链接（业务参数序：`target` 在前、`link_path` 在后）
    ///
    /// # Errors
    /// 权限不足、路径越狱或创建失败时返回错误应答
    pub async fn symlink(
        &mut self,
        id: u32,
        target: String,
        link_path: String,
    ) -> Result<Status, StatusReply> {
        if !self.check_permission(|p| p.can_write) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let full_link = self.resolve_path_or_err(&link_path)?;

        // home 规范路径作为 jail 基准（链接路径已经 resolve 落在其内）
        let home_canon = PathBuf::from(&self.home_dir)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(&self.home_dir));

        // 目标必须解析到 home 之内（相对目标按链接父目录拼接）
        let link_parent = full_link.parent().unwrap_or(Path::new(&self.home_dir));
        let resolved_target = if Path::new(&target).is_absolute() {
            self.resolve_path_or_err(&target)?
        } else {
            link_parent.join(&target)
        };

        // 词法校验：`..` 归一化后仍须落在 home 内（悬空链接目标也必须安全）
        if crate::path_resolve::build_safe_path(&home_canon, &resolved_target, "symlink target")
            .is_err()
        {
            tracing::warn!(
                "SFTP SYMLINK denied: target path outside home - {} -> {:?}",
                full_link.display(),
                resolved_target
            );
            return Err(status_err(
                StatusCode::PermissionDenied,
                "Permission denied: target path outside home",
            ));
        }

        // 目标已存在时再做 canonicalize 校验（防符号链接目标指向 home 之外）
        if let Ok(canon_target) = resolved_target.canonicalize()
            && !crate::path_resolve::path_starts_with_ignore_case(&canon_target, &home_canon)
        {
            tracing::warn!(
                "SFTP SYMLINK denied: canonicalized target outside home - {} -> {:?}",
                full_link.display(),
                canon_target
            );
            return Err(status_err(
                StatusCode::PermissionDenied,
                "Permission denied: target path outside home",
            ));
        }

        // Windows：拒绝指向 junction/reparse point 的目标（旧版防护）
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if resolved_target.exists()
                && let Ok(metadata) = std::fs::metadata(&resolved_target)
                && metadata.file_attributes() & 0x400 != 0
            {
                tracing::warn!(
                    "SFTP SYMLINK denied: target is a junction/reparse point - {:?}",
                    resolved_target
                );
                return Err(status_err(
                    StatusCode::PermissionDenied,
                    "Permission denied: junction points not allowed",
                ));
            }
        }

        match create_symlink(&target, &full_link, &resolved_target) {
            Ok(()) => {
                self.audit_file_op_pair(
                    "SYMLINK",
                    &full_link.to_string_lossy(),
                    &resolved_target.to_string_lossy(),
                    0,
                    "Symlink created successfully",
                );
                Ok(status_ok(id))
            }
            Err(e) => {
                tracing::warn!("SFTP SYMLINK failed for {full_link:?}: {e}");
                let msg = if e.raw_os_error() == Some(1314) {
                    // ERROR_PRIVILEGE_NOT_HELD：Windows 创建符号链接需要特权/开发者模式
                    "Symlink requires administrator privileges on Windows"
                } else {
                    "Failed to create symlink"
                };
                Err(status_err(StatusCode::Failure, msg))
            }
        }
    }
}

/// 跨平台创建符号链接
///
/// Windows 按已知目标类型选 file/dir 链接（目标不存在时按后缀猜测为文件链接）；
/// Unix 统一走 `std::os::unix::fs::symlink`。
fn create_symlink(
    target: &str,
    link_path: &Path,
    resolved_target: &Path,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let _ = resolved_target;
        std::os::unix::fs::symlink(target, link_path)
    }
    #[cfg(windows)]
    {
        let is_dir = if resolved_target.exists() {
            resolved_target.is_dir()
        } else {
            false
        };
        if is_dir {
            std::os::windows::fs::symlink_dir(target, link_path)
        } else {
            std::os::windows::fs::symlink_file(target, link_path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::setup_with_perms;

    /// SYMLINK → READLINK 回环（Windows 创建链接需特权，仅在 Unix 验证创建路径）
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_readlink_roundtrip() {
        let mut env = crate::test_util::setup();
        std::fs::write(env.dir.path().join("target.txt"), b"t").unwrap();

        // 业务参数序：target 在前、link_path 在后
        env.state
            .symlink(1, "target.txt".to_string(), "/link.txt".to_string())
            .await
            .unwrap();
        assert!(env.dir.path().join("link.txt").symlink_metadata().unwrap().is_symlink());

        let name = env.state.readlink(2, "/link.txt".to_string()).await.unwrap();
        assert_eq!(name.files[0].filename, "target.txt");

        // READLINK 不跟随链接：LSTAT 语义下链接自身可查
        let attrs = env.state.lstat(3, "/link.txt".to_string()).await.unwrap();
        assert!(attrs.attrs.is_symlink());
    }

    /// READLINK 目标不是符号链接（或不存在）回 NO_SUCH_FILE
    #[tokio::test]
    async fn readlink_non_symlink() {
        let mut env = crate::test_util::setup();
        std::fs::write(env.dir.path().join("plain.txt"), b"p").unwrap();

        let err = env.state.readlink(1, "/plain.txt".to_string()).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::NoSuchFile);

        let err = env.state.readlink(2, "/missing.txt".to_string()).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::NoSuchFile);
    }

    /// 无写权限时 SYMLINK 拒绝、无读权限时 READLINK 拒绝
    #[tokio::test]
    async fn link_ops_denied_without_permission() {
        let mut env = setup_with_perms(|p| p.can_write = false);
        let err = env
            .state
            .symlink(1, "t.txt".to_string(), "/l.txt".to_string())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::PermissionDenied);

        let mut env = setup_with_perms(|p| {
            p.can_read = false;
            p.can_list = false;
        });
        let err = env
            .state
            .readlink(2, "/whatever".to_string())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::PermissionDenied);
    }

    /// 链接目标越出 home 词法越狱拒绝（不实际创建）
    #[tokio::test]
    async fn symlink_target_outside_home_rejected() {
        let mut env = crate::test_util::setup();
        let err = env
            .state
            .symlink(
                1,
                "../../etc/passwd".to_string(),
                "/evil.txt".to_string(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::PermissionDenied);
        assert!(!env.dir.path().join("evil.txt").exists());
    }
}

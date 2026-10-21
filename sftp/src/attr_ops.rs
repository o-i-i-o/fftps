//! SFTP 属性操作：STAT / LSTAT / FSTAT / SETSTAT / FSETSTAT
//!
//! v3 属性集合：size / permissions / atime / mtime（`FileAttributes` 序列化
//! 由协议层按存在字段自动打 flags）。

use std::path::Path;

use crate::protocol::{Attrs, FileAttributes, Status, StatusReply, StatusCode};
use crate::state::{SftpState, status_err, status_ok};
use crate::types::SftpFileHandle;

impl SftpState {
    /// `SSH_FXP_STAT`：跟随符号链接的属性查询
    ///
    /// # Errors
    /// 权限不足、路径越狱或目标不存在时返回错误应答
    pub async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, StatusReply> {
        if !self.check_permission(|p| p.can_read || p.can_list) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let full_path = self.resolve_path_or_err(&path)?;

        match tokio::fs::metadata(&full_path).await {
            Ok(metadata) => Ok(Attrs {
                id,
                attrs: FileAttributes::from(&metadata),
            }),
            Err(e) => {
                tracing::debug!("SFTP STAT failed for {full_path:?}: {e}");
                Err(stat_io_error(&e))
            }
        }
    }

    /// `SSH_FXP_LSTAT`：不跟随符号链接的属性查询
    ///
    /// # Errors
    /// 权限不足、路径越狱或目标不存在时返回错误应答
    pub async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, StatusReply> {
        if !self.check_permission(|p| p.can_read || p.can_list) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        // 不跟随符号链接：末段文件名保留，符号链接自身可被 LSTAT
        let full_path = self.resolve_path_no_follow_or_err(&path)?;

        match tokio::fs::symlink_metadata(&full_path).await {
            Ok(metadata) => Ok(Attrs {
                id,
                attrs: FileAttributes::from(&metadata),
            }),
            Err(e) => {
                tracing::debug!("SFTP LSTAT failed for {full_path:?}: {e}");
                Err(stat_io_error(&e))
            }
        }
    }

    /// `SSH_FXP_FSTAT`：按句柄查询属性
    ///
    /// # Errors
    /// 句柄无效或属性查询失败时返回错误应答
    pub async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, StatusReply> {
        let Some(SftpFileHandle::File { file, .. }) = self
            .handles
            .get(&handle)
            .filter(|h| matches!(h, SftpFileHandle::File { .. }))
        else {
            tracing::debug!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "FSTAT_INVALID_HANDLE",
                handle = %handle,
                "SFTP FSTAT: handle not found or invalid type"
            );
            return Err(status_err(StatusCode::Failure, "Invalid handle"));
        };

        match file.metadata().await {
            Ok(metadata) => Ok(Attrs {
                id,
                attrs: FileAttributes::from(&metadata),
            }),
            Err(e) => {
                tracing::debug!("SFTP FSTAT failed: {e}");
                Err(stat_io_error(&e))
            }
        }
    }

    /// `SSH_FXP_SETSTAT`：按路径修改属性
    ///
    /// # Errors
    /// 权限不足、路径越狱、目标不存在或属性应用失败时返回错误应答
    pub async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, StatusReply> {
        if !self.check_permission(|p| p.can_write) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let full_path = self.resolve_path_or_err(&path)?;

        if !full_path.exists() {
            return Err(status_err(StatusCode::NoSuchFile, "No such file"));
        }

        apply_file_attributes(&full_path, &attrs)
            .await
            .map_err(|e| {
                tracing::warn!("SETSTAT failed for {full_path:?}: {e}");
                status_err(StatusCode::Failure, &format!("Failed to set attributes: {e}"))
            })?;
        tracing::debug!("SETSTAT applied to {full_path:?}");
        Ok(status_ok(id))
    }

    /// `SSH_FXP_FSETSTAT`：按句柄修改属性
    ///
    /// # Errors
    /// 权限不足、句柄无效或属性应用失败时返回错误应答
    pub async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, StatusReply> {
        if !self.check_permission(|p| p.can_write) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let path = match self.handles.get(&handle) {
            Some(SftpFileHandle::File { path, .. } | SftpFileHandle::Dir { path, .. }) => {
                path.clone()
            }
            None => {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "FSETSTAT_INVALID_HANDLE",
                    handle = %handle,
                    "SFTP FSETSTAT: handle not found"
                );
                return Err(status_err(StatusCode::Failure, "Invalid handle"));
            }
        };

        apply_file_attributes(&path, &attrs)
            .await
            .map_err(|e| {
                tracing::warn!("FSETSTAT failed for {path:?}: {e}");
                status_err(StatusCode::Failure, &format!("Failed to set attributes: {e}"))
            })?;
        tracing::debug!("FSETSTAT applied to {path:?}");
        Ok(status_ok(id))
    }
}

/// stat 类查询的 IO 错误 → 协议错误应答
fn stat_io_error(e: &std::io::Error) -> StatusReply {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        status_err(StatusCode::PermissionDenied, "Permission denied")
    } else {
        status_err(StatusCode::NoSuchFile, "No such file")
    }
}

/// 应用属性修改：permissions（仅 Unix 取低 9 位）、size（截断/扩容）、atime/mtime
///
/// # Errors
/// 文件操作失败时返回错误
pub async fn apply_file_attributes(path: &Path, attrs: &FileAttributes) -> anyhow::Result<()> {
    // permissions：v3 仅保留低 9 位访问权限位
    #[cfg(unix)]
    if let Some(permissions) = attrs.permissions {
        use std::os::unix::fs::PermissionsExt;
        let metadata = tokio::fs::metadata(path).await?;
        let mut perm = metadata.permissions();
        perm.set_mode(permissions & 0o777);
        tokio::fs::set_permissions(path, perm).await?;
    }
    #[cfg(windows)]
    if let Some(permissions) = attrs.permissions {
        tracing::debug!(
            "SETSTAT: permissions change to {permissions:o} for {path:?} (ignored on Windows)"
        );
    }

    let need_set_size = attrs.size.is_some();
    let need_set_times = attrs.atime.is_some() || attrs.mtime.is_some();
    if !need_set_size && !need_set_times {
        return Ok(());
    }

    let file = tokio::fs::OpenOptions::new().write(true).open(path).await?;

    if let Some(size) = attrs.size {
        file.set_len(size).await?;
        tracing::debug!("SETSTAT: set size to {size} for {path:?}");
    }

    if need_set_times {
        use std::time::{Duration, SystemTime};
        let std_file = file.into_std().await;
        let metadata = std_file.metadata()?;

        let atime = attrs
            .atime
            .map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(s)))
            .or_else(|| metadata.accessed().ok())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mtime = attrs
            .mtime
            .map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(s)))
            .or_else(|| metadata.modified().ok())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        let times = std::fs::FileTimes::new()
            .set_accessed(atime)
            .set_modified(mtime);
        std_file.set_times(times)?;
        tracing::debug!("SETSTAT: set atime={atime:?}, mtime={mtime:?} for {path:?}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::OpenFlags;
    use crate::test_util::{setup, setup_with_perms};

    /// STAT 返回文件大小；不存在的文件回 NO_SUCH_FILE
    #[tokio::test]
    async fn stat_size_and_missing() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("f.txt"), b"hello").unwrap();

        let attrs = env.state.stat(1, "/f.txt".to_string()).await.unwrap();
        assert_eq!(attrs.id, 1);
        assert_eq!(attrs.attrs.size, Some(5));

        let err = env.state.stat(2, "/missing.txt".to_string()).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::NoSuchFile);
    }

    /// LSTAT 与 FSTAT
    #[tokio::test]
    async fn lstat_and_fstat() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("f.txt"), b"abc").unwrap();

        let attrs = env.state.lstat(1, "/f.txt".to_string()).await.unwrap();
        assert_eq!(attrs.attrs.size, Some(3));

        let flags = OpenFlags::READ;
        let handle = env
            .state
            .open(2, "/f.txt".to_string(), flags, FileAttributes::default())
            .await
            .unwrap()
            .handle;
        let attrs = env.state.fstat(3, handle).await.unwrap();
        assert_eq!(attrs.attrs.size, Some(3));

        // 无效句柄
        let err = env.state.fstat(4, "ghost".to_string()).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }

    /// STAT 无权限拒绝
    #[tokio::test]
    async fn stat_denied_without_permission() {
        let mut env = setup_with_perms(|p| {
            p.can_read = false;
            p.can_list = false;
        });
        let err = env.state.stat(1, "/".to_string()).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::PermissionDenied);
    }

    /// SETSTAT：截断 + 修改时间；目标不存在回 NO_SUCH_FILE
    #[tokio::test]
    async fn setstat_truncate_and_times() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("f.txt"), b"hello world").unwrap();

        let attrs = FileAttributes {
            size: Some(4),
            atime: Some(1000),
            mtime: Some(2000),
            ..FileAttributes::default()
        };
        env.state
            .setstat(1, "/f.txt".to_string(), attrs)
            .await
            .unwrap();

        let metadata = std::fs::metadata(env.dir.path().join("f.txt")).unwrap();
        assert_eq!(metadata.len(), 4);

        // 不存在的文件
        let err = env
            .state
            .setstat(2, "/missing.txt".to_string(), FileAttributes::default())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::NoSuchFile);
    }

    /// FSETSTAT：按句柄截断；无效句柄回 FAILURE
    #[tokio::test]
    async fn fsetstat_by_handle() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("f.txt"), b"hello").unwrap();

        let flags = OpenFlags::READ | OpenFlags::WRITE;
        let handle = env
            .state
            .open(1, "/f.txt".to_string(), flags, FileAttributes::default())
            .await
            .unwrap()
            .handle;

        let attrs = FileAttributes {
            size: Some(2),
            ..FileAttributes::default()
        };
        env.state.fsetstat(2, handle.clone(), attrs).await.unwrap();
        assert_eq!(std::fs::metadata(env.dir.path().join("f.txt")).unwrap().len(), 2);

        let err = env
            .state
            .fsetstat(3, "ghost".to_string(), FileAttributes::default())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }

    /// apply_file_attributes：直接应用 size 属性
    #[tokio::test]
    async fn apply_file_attributes_sets_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.txt");
        std::fs::write(&path, b"0123456789").unwrap();

        let attrs = FileAttributes {
            size: Some(3),
            ..FileAttributes::default()
        };
        apply_file_attributes(&path, &attrs).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 3);
    }
}

//! SFTP 目录操作：OPENDIR / READDIR / REMOVE / MKDIR / RMDIR / RENAME / REALPATH
//!
//! 参数均为协议层解析后的强类型字段，返回协议应答类型；
//! 报文编解码由 [`crate::protocol`] 的报文循环完成。

use std::path::{Path, PathBuf};

use crate::path_resolve::{path_starts_with_ignore_case, to_ftp_path};
use crate::protocol::{File, FileAttributes, Handle, Name, Status, StatusReply, StatusCode};
use crate::state::{SftpState, status_err, status_ok};
use crate::types::{SftpFileHandle, MAX_HANDLES, MAX_READDIR_ENTRIES};

impl SftpState {
    /// `SSH_FXP_OPENDIR`：打开目录句柄
    ///
    /// # Errors
    /// 权限不足、句柄超限、路径越狱或目标不是目录时返回错误应答
    pub fn opendir(&mut self, id: u32, path: &str) -> Result<Handle, StatusReply> {
        if !self.check_permission(|p| p.can_list) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        if self.handles.len() >= MAX_HANDLES {
            tracing::warn!(
                "SFTP OPENDIR denied: too many open handles ({})",
                self.handles.len()
            );
            return Err(status_err(StatusCode::Failure, "Too many open handles"));
        }

        let full_path = self.resolve_path_or_err(path)?;

        if !full_path.exists() {
            return Err(status_err(StatusCode::NoSuchFile, "No such directory"));
        }

        if !full_path.is_dir() {
            return Err(status_err(StatusCode::Failure, "Not a directory"));
        }

        let handle = self.generate_handle();
        self.handles.insert(
            handle.clone(),
            SftpFileHandle::Dir {
                path: full_path,
                entries: Vec::new(),
                index: 0,
                last_access: std::time::Instant::now(),
            },
        );
        Ok(Handle { id, handle })
    }

    /// `SSH_FXP_READDIR`：分批枚举目录（每批 [`MAX_READDIR_ENTRIES`] 条）
    ///
    /// # Errors
    /// 句柄无效或目录读取失败时返回错误应答；枚举结束按协议返回 `EOF`
    pub async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, StatusReply> {
        // 首次调用读取整个目录并缓存条目，后续调用按批返回
        let batch = {
            let Some(dir_handle) = self
                .handles
                .get_mut(&handle)
                .filter(|h| matches!(h, SftpFileHandle::Dir { .. }))
            else {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "READDIR_INVALID_HANDLE",
                    handle = %handle,
                    "SFTP READDIR: handle not found or invalid type"
                );
                return Err(status_err(StatusCode::Failure, "Invalid handle"));
            };

            let SftpFileHandle::Dir {
                path,
                entries,
                index,
                last_access,
            } = dir_handle
            else {
                unreachable!("上一行 filter 已保证为目录句柄");
            };

            if entries.is_empty() && *index == 0 {
                let mut read_entries = Vec::new();
                match tokio::fs::read_dir(path).await {
                    Ok(mut dir) => {
                        while let Ok(Some(entry)) = dir.next_entry().await {
                            let name = entry.file_name().to_string_lossy().to_string();
                            let attrs = match entry.metadata().await {
                                // DirEntry::metadata 不跟随符号链接，链接自身可被列出
                                Ok(m) => FileAttributes::from(&m),
                                Err(_) => FileAttributes::empty(),
                            };
                            read_entries.push(crate::types::DirEntry { name, attrs });
                        }
                    }
                    Err(e) => {
                        return Err(status_err(
                            StatusCode::Failure,
                            &format!("Failed to read directory: {e}"),
                        ));
                    }
                }
                *entries = read_entries;
            }

            if *index >= entries.len() {
                return Err(status_err(StatusCode::Eof, "End of directory"));
            }

            let count = (entries.len() - *index).min(MAX_READDIR_ENTRIES);
            let batch: Vec<crate::types::DirEntry> = entries[*index..*index + count].to_vec();
            *index += count;
            *last_access = std::time::Instant::now();
            batch
        };

        let files = batch
            .into_iter()
            .map(|entry| File::new(entry.name, entry.attrs))
            .collect();
        Ok(Name { id, files })
    }

    /// `SSH_FXP_REMOVE`：删除文件（结算配额 + 审计）
    ///
    /// # Errors
    /// 权限不足、路径越狱或删除失败时返回错误应答
    pub async fn remove(&mut self, id: u32, filename: String) -> Result<Status, StatusReply> {
        if !self.check_permission(|p| p.can_delete) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let full_path = self.resolve_path_or_err(&filename)?;

        let file_size = tokio::fs::metadata(&full_path)
            .await
            .map_or(0, |m| m.len());

        if tokio::fs::remove_file(&full_path).await.is_ok() {
            if file_size > 0
                && let Some(username) = &self.username
            {
                self.quota_manager.subtract_usage(username, file_size);
            }
            self.audit_file_op("DELETE", &full_path.to_string_lossy(), 0);
            Ok(status_ok(id))
        } else {
            Err(status_err(StatusCode::Failure, "Failed to remove file"))
        }
    }

    /// `SSH_FXP_MKDIR`：创建目录
    ///
    /// # Errors
    /// 权限不足、路径越狱、目录已存在或创建失败时返回错误应答
    pub async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, StatusReply> {
        if !self.check_permission(|p| p.can_mkdir) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let full_path = self.resolve_path_or_err(&path)?;

        if full_path.exists() {
            return Err(status_err(StatusCode::Failure, "Directory already exists"));
        }

        match tokio::fs::create_dir(&full_path).await {
            Ok(()) => {
                self.audit_file_op("MKDIR", &full_path.to_string_lossy(), 0);
                Ok(status_ok(id))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(status_err(
                StatusCode::NoSuchFile,
                "Parent directory not found",
            )),
            Err(_) => Err(status_err(
                StatusCode::Failure,
                "Failed to create directory",
            )),
        }
    }

    /// `SSH_FXP_RMDIR`：删除空目录（回收目录占用配额 + 审计）
    ///
    /// # Errors
    /// 权限不足、路径越狱、目录非空或删除失败时返回错误应答
    pub async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, StatusReply> {
        if !self.check_permission(|p| p.can_rmdir) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let full_path = self.resolve_path_or_err(&path)?;

        let dir_size = calculate_dir_size(&full_path).await;

        match tokio::fs::remove_dir(&full_path).await {
            Ok(()) => {
                if dir_size > 0
                    && let Some(username) = &self.username
                {
                    self.quota_manager.subtract_usage(username, dir_size);
                }
                self.audit_file_op("RMDIR", &full_path.to_string_lossy(), 0);
                Ok(status_ok(id))
            }
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                Err(status_err(StatusCode::Failure, "Directory not empty"))
            }
            Err(_) => Err(status_err(
                StatusCode::Failure,
                "Failed to remove directory",
            )),
        }
    }

    /// `SSH_FXP_RENAME`：重命名/移动（目标存在则拒绝，双路径审计）
    ///
    /// # Errors
    /// 权限不足、路径越狱、源不存在或目标已存在时返回错误应答
    pub async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, StatusReply> {
        if !self.check_permission(|p| p.can_rename) {
            tracing::warn!(
                "SFTP RENAME denied: no permission for user {:?}",
                self.username
            );
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let old_full = self.resolve_path_or_err(&oldpath)?;
        let new_full = self.resolve_path_or_err(&newpath)?;

        tracing::debug!(
            "SFTP RENAME: raw_old='{oldpath}', resolved_old='{}', raw_new='{newpath}', \
             resolved_new='{}'",
            old_full.display(),
            new_full.display()
        );

        if !old_full.exists() {
            tracing::warn!(
                "SFTP RENAME failed: source does not exist - {}",
                old_full.display()
            );
            return Err(status_err(StatusCode::NoSuchFile, "No such file"));
        }

        if old_full == new_full {
            return Ok(status_ok(id));
        }

        let home = PathBuf::from(&self.home_dir);
        if !path_starts_with_ignore_case(&old_full, &home)
            || !path_starts_with_ignore_case(&new_full, &home)
        {
            tracing::warn!(
                "SFTP RENAME denied: path outside home - old={}, new={}",
                old_full.display(),
                new_full.display()
            );
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        self.check_symlink_in_home(&old_full).await?;

        if new_full.exists() {
            self.check_symlink_in_home(&new_full).await?;
            return Err(status_err(StatusCode::Failure, "File already exists"));
        }

        match tokio::fs::rename(&old_full, &new_full).await {
            Ok(()) => {
                let old_parent = old_full
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let new_parent = new_full
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let operation = if old_parent == new_parent {
                    "RENAME"
                } else {
                    "MOVE"
                };
                self.audit_file_op_pair(
                    operation,
                    &old_full.to_string_lossy(),
                    &new_full.to_string_lossy(),
                    0,
                    "",
                );
                Ok(status_ok(id))
            }
            Err(e) => {
                tracing::error!(
                    "SFTP Rename failed: {} -> {}: {} (os error {:?})",
                    old_full.display(),
                    new_full.display(),
                    e,
                    e.raw_os_error()
                );
                Err(status_err(StatusCode::Failure, "Failed to rename"))
            }
        }
    }

    /// `SSH_FXP_REALPATH`：路径规范化（映射回 `/` 起的虚路径）
    ///
    /// # Errors
    /// 路径越狱或映射失败时返回错误应答
    pub fn realpath(&mut self, id: u32, path: &str) -> Result<Name, StatusReply> {
        let full_path = if path.is_empty() || path == "." {
            PathBuf::from(&self.cwd)
        } else {
            self.resolve_path(path).map_err(|e| {
                tracing::warn!("REALPATH failed for '{path}': {e}");
                status_err(StatusCode::NoSuchFile, &e.to_string())
            })?
        };

        let resolved = if full_path.exists() {
            match full_path.canonicalize() {
                Ok(canon) => {
                    if !path_starts_with_ignore_case(&canon, Path::new(&self.home_dir)) {
                        tracing::warn!(
                            "REALPATH security: canonicalized path escapes home - input: {path}, \
                             canonicalized: {}",
                            canon.display()
                        );
                        return Err(status_err(
                            StatusCode::PermissionDenied,
                            "Permission denied",
                        ));
                    }
                    canon
                }
                Err(_) => full_path,
            }
        } else {
            full_path
        };

        let path_str = to_ftp_path(&resolved, Path::new(&self.home_dir))
            .map_err(|e| {
                tracing::error!("REALPATH failed: {e}");
                status_err(StatusCode::NoSuchFile, &e.to_string())
            })?;

        tracing::debug!(
            client_ip = %self.client_ip,
            username = ?self.username.as_deref(),
            action = "REALPATH",
            protocol = "SFTP",
            "Resolved '{path}' -> '{path_str}'"
        );

        Ok(Name {
            id,
            files: vec![File::dummy(path_str)],
        })
    }
}

/// 递归统计目录字节数（删除目录时回收配额用）
fn calculate_dir_size(
    path: &Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = u64> + Send + '_>> {
    Box::pin(async move {
        let mut total_size: u64 = 0;
        if let Ok(mut entries) = tokio::fs::read_dir(path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(metadata) = entry.metadata().await {
                    if metadata.is_file() {
                        total_size += metadata.len();
                    } else if metadata.is_dir() {
                        total_size += calculate_dir_size(&entry.path()).await;
                    }
                }
            }
        }
        total_size
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::setup_with_perms;

    /// MKDIR → OPENDIR → READDIR → REMOVE → RMDIR 全流程
    #[tokio::test]
    async fn dir_lifecycle() {
        let mut env = crate::test_util::setup();

        env.state
            .mkdir(1, "/sub".to_string(), FileAttributes::default())
            .await
            .unwrap();
        std::fs::write(env.dir.path().join("sub/f.txt"), b"data").unwrap();

        // 重复创建拒绝
        let err = env
            .state
            .mkdir(2, "/sub".to_string(), FileAttributes::default())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);

        let handle = env.state.opendir(3, "/sub").unwrap().handle;

        // 非目录路径拒绝
        let err = env.state.opendir(4, "/sub/f.txt").unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);

        let name = env.state.readdir(5, handle.clone()).await.unwrap();
        assert_eq!(name.files.len(), 1);
        assert_eq!(name.files[0].filename, "f.txt");

        // 缓存已耗尽 → EOF
        let err = env.state.readdir(6, handle.clone()).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::Eof);

        env.state.close(7, handle).await.unwrap();

        env.state.remove(8, "/sub/f.txt".to_string()).await.unwrap();
        env.state.rmdir(9, "/sub".to_string()).await.unwrap();
        assert!(!env.dir.path().join("sub").exists());

        // 空目录首次 READDIR 即 EOF
        env.state
            .mkdir(10, "/empty".to_string(), FileAttributes::default())
            .await
            .unwrap();
        let handle = env.state.opendir(11, "/empty").unwrap().handle;
        let err = env.state.readdir(12, handle).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::Eof);
    }

    /// 不存在的目录 `OPENDIR` 回 `NO_SUCH_FILE`
    #[tokio::test]
    async fn opendir_missing_dir() {
        let mut env = crate::test_util::setup();
        let err = env.state.opendir(1, "/missing").unwrap_err();
        assert_eq!(err.status_code, StatusCode::NoSuchFile);
    }

    /// REMOVE 无权限拒绝；删除不存在的文件回 FAILURE
    #[tokio::test]
    async fn remove_permission_and_missing() {
        let mut env = setup_with_perms(|p| p.can_delete = false);
        std::fs::write(env.dir.path().join("f.txt"), b"x").unwrap();

        let err = env.state.remove(1, "/f.txt".to_string()).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::PermissionDenied);

        let mut env = crate::test_util::setup();
        let err = env.state.remove(2, "/missing.txt".to_string()).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }

    /// RENAME：同目录改名与跨目录移动；目标已存在拒绝
    #[tokio::test]
    async fn rename_move_and_conflict() {
        let mut env = crate::test_util::setup();
        std::fs::write(env.dir.path().join("a.txt"), b"aaa").unwrap();
        env.state
            .mkdir(1, "/sub".to_string(), FileAttributes::default())
            .await
            .unwrap();

        env.state
            .rename(2, "/a.txt".to_string(), "/b.txt".to_string())
            .await
            .unwrap();
        assert!(env.dir.path().join("b.txt").exists());

        // 跨目录移动
        env.state
            .rename(3, "/b.txt".to_string(), "/sub/b.txt".to_string())
            .await
            .unwrap();
        assert!(env.dir.path().join("sub/b.txt").exists());

        // 目标已存在拒绝
        std::fs::write(env.dir.path().join("sub/other.txt"), b"o").unwrap();
        let err = env
            .state
            .rename(4, "/sub/b.txt".to_string(), "/sub/other.txt".to_string())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);

        // 源不存在回 NO_SUCH_FILE
        let err = env
            .state
            .rename(5, "/ghost.txt".to_string(), "/x.txt".to_string())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::NoSuchFile);
    }

    /// RENAME 无权限拒绝
    #[tokio::test]
    async fn rename_denied_without_permission() {
        let mut env = setup_with_perms(|p| p.can_rename = false);
        std::fs::write(env.dir.path().join("a.txt"), b"a").unwrap();
        let err = env
            .state
            .rename(1, "/a.txt".to_string(), "/b.txt".to_string())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::PermissionDenied);
    }

    /// REALPATH：虚路径映射回 `/` 起始；越狱拒绝
    #[tokio::test]
    async fn realpath_maps_to_virtual_root() {
        let mut env = crate::test_util::setup();

        let name = env.state.realpath(1, ".").unwrap();
        assert_eq!(name.files[0].filename, "/");

        let name = env.state.realpath(2, "/").unwrap();
        assert_eq!(name.files[0].filename, "/");

        // 存在的文件映射为虚路径
        std::fs::write(env.dir.path().join("f.txt"), b"x").unwrap();
        let name = env.state.realpath(3, "/f.txt").unwrap();
        assert_eq!(name.files[0].filename, "/f.txt");

        // 越狱拒绝
        let err = env.state.realpath(4, "/../escape").unwrap_err();
        assert_eq!(err.status_code, StatusCode::NoSuchFile);
    }
}

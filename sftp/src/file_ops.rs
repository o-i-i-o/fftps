//! SFTP 文件操作：OPEN / CLOSE / READ / WRITE
//!
//! 覆盖配额预留与结算、限速、写缓冲落盘与文件操作审计。

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::protocol::{Data, FileAttributes, Handle, OpenFlags, Status, StatusReply, StatusCode};
use crate::state::{SftpState, status_err, status_ok};
use crate::types::{
    SftpFileHandle, MAX_HANDLES, SFTP_READ_BUFFER_SIZE, SFTP_WRITE_FLUSH_THRESHOLD,
};

/// 写打开时的配额预留粒度（100 MiB）
const QUOTA_RESERVE_BYTES: u64 = 100 * 1024 * 1024;

impl SftpState {
    /// `SSH_FXP_OPEN`：打开文件并创建句柄
    ///
    /// # Errors
    /// 权限不足、句柄超限、路径越狱或打开失败时返回错误应答
    // 命令主流程（权限 → 路径解析 → fs 操作 → 审计）保持单函数内联，拆分会割裂协议语义
    #[allow(clippy::too_many_lines)]
    pub async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, StatusReply> {
        let need_read = pflags.contains(OpenFlags::READ);
        let need_write = pflags.contains(OpenFlags::WRITE);
        let need_append = pflags.contains(OpenFlags::APPEND);
        let need_creat = pflags.contains(OpenFlags::CREATE);
        let need_trunc = pflags.contains(OpenFlags::TRUNCATE);
        let need_excl = pflags.contains(OpenFlags::EXCLUDE);

        if !self.check_permission(|p| {
            (!need_read || p.can_read)
                && if need_append {
                    // 追加打开：can_append 或 can_write 任一即可
                    p.can_append || p.can_write
                } else {
                    !need_write || p.can_write
                }
        }) {
            tracing::warn!(
                "SFTP OPEN denied: no permission for user {:?} (read={need_read}, \
                 write={need_write}, append={need_append})",
                self.username
            );
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        if self.handles.len() >= MAX_HANDLES {
            tracing::warn!(
                "SFTP OPEN denied: too many open handles ({})",
                self.handles.len()
            );
            return Err(status_err(StatusCode::Failure, "Too many open handles"));
        }

        let full_path = self.resolve_path_or_err(&filename)?;
        let file_existed = full_path.exists();

        tracing::debug!(
            "SFTP OPEN: raw='{filename}', resolved='{}', existed={file_existed}, flags={pflags:?}",
            full_path.display()
        );

        let file_result = if need_write || need_append {
            if need_excl && need_creat && file_existed {
                return Err(status_err(StatusCode::Failure, "File already exists"));
            }

            if need_append {
                tokio::fs::OpenOptions::new()
                    .read(need_read)
                    .write(true)
                    .create(need_creat)
                    .append(true)
                    .open(&full_path)
                    .await
            } else if need_trunc {
                tokio::fs::OpenOptions::new()
                    .read(need_read)
                    .write(true)
                    .create(need_creat)
                    .truncate(true)
                    .open(&full_path)
                    .await
            } else if need_creat {
                tokio::fs::OpenOptions::new()
                    .read(need_read)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&full_path)
                    .await
            } else {
                tokio::fs::OpenOptions::new()
                    .read(need_read)
                    .write(true)
                    .open(&full_path)
                    .await
            }
        } else {
            tokio::fs::File::open(&full_path).await
        };

        match file_result {
            Ok(file) => {
                let handle = self.generate_handle();

                let original_size = if file_existed {
                    tokio::fs::metadata(&full_path)
                        .await
                        .map_or(0, |m| m.len())
                } else {
                    0
                };

                let quota_reserved = if need_write || need_append {
                    let quota_mb = self.cached_permissions.as_ref().and_then(|p| p.quota_mb);
                    if let Some(quota) = quota_mb {
                        let username = self.audit_user();
                        if self.quota_manager.try_reserve_quota(
                            username,
                            QUOTA_RESERVE_BYTES,
                            quota,
                        ) {
                            QUOTA_RESERVE_BYTES
                        } else {
                            tracing::warn!(
                                "SFTP OPEN denied: quota exceeded for user {:?}",
                                self.username
                            );
                            return Err(status_err(StatusCode::Failure, "Quota exceeded"));
                        }
                    } else {
                        0
                    }
                } else {
                    0
                };

                self.handles.insert(
                    handle.clone(),
                    SftpFileHandle::File {
                        path: full_path,
                        file,
                        locked: false,
                        existed: file_existed,
                        written_bytes: 0,
                        read_bytes: 0,
                        pending_flush_bytes: 0,
                        last_access: std::time::Instant::now(),
                        quota_reserved,
                        original_size,
                    },
                );
                tracing::debug!("SFTP OPEN: handle '{handle}' created for {filename}");
                Ok(Handle { id, handle })
            }
            Err(e) => {
                tracing::error!("SFTP OPEN failed for {}: {e}", full_path.display());
                Err(status_err(StatusCode::Failure, "Failed to open file"))
            }
        }
    }

    /// `SSH_FXP_CLOSE`：关闭句柄，结算配额并写审计日志
    ///
    /// # Errors
    /// 句柄不存在时返回错误应答
    #[allow(clippy::too_many_lines)]
    pub async fn close(&mut self, id: u32, handle: String) -> Result<Status, StatusReply> {
        let Some(handle_obj) = self.handles.remove(&handle) else {
            tracing::debug!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "CLOSE_INVALID",
                handle = %handle,
                "Close request for non-existent handle (already closed or invalid)"
            );
            // 未知句柄按协议回 FAILURE，与其它句柄类命令一致
            return Err(status_err(StatusCode::Failure, "Invalid handle"));
        };

        match handle_obj {
            SftpFileHandle::File {
                path,
                locked,
                existed,
                written_bytes,
                read_bytes,
                mut file,
                quota_reserved,
                original_size,
                ..
            } => {
                if let Err(e) = file.flush().await {
                    tracing::warn!("Failed to flush file on close {path:?}: {e}");
                }
                if written_bytes > 0
                    && let Err(e) = file.sync_data().await
                {
                    tracing::debug!("sync_data on close {path:?}: {e}");
                }

                drop(file);

                if locked {
                    self.locked_files.remove(&path);
                }

                if written_bytes > 0 {
                    let file_size = tokio::fs::metadata(&path)
                        .await
                        .map_or(written_bytes, |m| m.len());

                    let actual_new_bytes = if existed {
                        file_size.saturating_sub(original_size)
                    } else {
                        file_size
                    };

                    if quota_reserved > 0 {
                        let username = self.audit_user().to_string();
                        self.quota_manager
                            .commit_usage(&username, quota_reserved, actual_new_bytes);
                    } else if let Some(username) = &self.username
                        && actual_new_bytes > 0
                    {
                        self.quota_manager.add_usage(username, actual_new_bytes);
                    }

                    if existed {
                        self.audit_file_op("UPDATE", &path.to_string_lossy(), file_size);
                    } else {
                        self.audit_file_op("UPLOAD", &path.to_string_lossy(), written_bytes);
                    }
                    fftp_common::metrics::record_upload_bytes("SFTP", written_bytes);
                } else if quota_reserved > 0 {
                    let username = self.audit_user().to_string();
                    self.quota_manager
                        .rollback_reservation(&username, quota_reserved);
                }

                if read_bytes > 0 {
                    self.audit_file_op("DOWNLOAD", &path.to_string_lossy(), read_bytes);
                    fftp_common::metrics::record_download_bytes("SFTP", read_bytes);
                }

                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "CLOSE",
                    handle = %handle,
                    "File handle closed: {:?}",
                    path
                );
            }
            SftpFileHandle::Dir { path, .. } => {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "CLOSE",
                    handle = %handle,
                    "Directory handle closed: {:?}",
                    path
                );
            }
        }
        Ok(status_ok(id))
    }

    /// `SSH_FXP_READ`：读文件（单次长度钳制到 [`SFTP_READ_BUFFER_SIZE`]）
    ///
    /// # Errors
    /// 权限不足、句柄无效、读到末尾（EOF）或 IO 失败时返回错误应答
    // 命令主流程（权限 → 路径解析 → fs 操作 → 审计）保持单函数内联，拆分会割裂协议语义
    #[allow(clippy::too_many_lines)]
    pub async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, StatusReply> {
        if !self.check_permission(|p| p.can_read) {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "READ_DENIED",
                "SFTP READ denied: no read permission"
            );
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let Some(SftpFileHandle::File {
            path,
            file,
            read_bytes,
            last_access,
            ..
        }) = self
            .handles
            .get_mut(&handle)
            // 目录句柄与不存在的句柄统一按无效处理
            .filter(|h| matches!(h, SftpFileHandle::File { .. }))
        else {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "READ_INVALID_HANDLE",
                handle = %handle,
                total_handles = self.handles.len(),
                "SFTP READ: handle not found or invalid type"
            );
            return Err(status_err(StatusCode::Failure, "Invalid handle"));
        };

        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
            tracing::error!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "READ_ERROR",
                "SFTP READ seek error for {path:?}: {e}"
            );
            return Err(status_err(StatusCode::Failure, &format!("Seek error: {e}")));
        }

        let read_len = usize::try_from(len).unwrap_or(0).min(SFTP_READ_BUFFER_SIZE);
        let mut buffer = vec![0u8; read_len];

        match file.read(&mut buffer).await {
            Ok(0) => Err(status_err(StatusCode::Eof, "End of file")),
            Ok(n) => {
                if let Some(limiter) = &self.rate_limiter {
                    limiter.acquire(n).await;
                }

                buffer.truncate(n);
                *read_bytes += n as u64;
                *last_access = std::time::Instant::now();

                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username.as_deref(),
                    action = "READ",
                    handle = %handle,
                    "Read {n} bytes from {path:?} at offset {offset}"
                );

                Ok(Data { id, data: buffer })
            }
            Err(e) => {
                tracing::error!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "READ_ERROR",
                    "SFTP READ error for {path:?}: {e}"
                );
                Err(status_err(StatusCode::Failure, &format!("Read error: {e}")))
            }
        }
    }

    /// `SSH_FXP_WRITE`：写文件（累计 [`SFTP_WRITE_FLUSH_THRESHOLD`] 后落盘）
    ///
    /// # Errors
    /// 权限不足、句柄无效或 IO 失败时返回错误应答
    // 命令主流程（权限 → 路径解析 → fs 操作 → 审计）保持单函数内联，拆分会割裂协议语义
    #[allow(clippy::too_many_lines)]
    pub async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        write_data: Vec<u8>,
    ) -> Result<Status, StatusReply> {
        let data_len = write_data.len();

        // 写入放行条件与 OPEN 门禁一致：追加打开仅需 can_append
        if !self.check_permission(|p| p.can_write || p.can_append) {
            tracing::warn!(
                "SFTP WRITE denied: no write permission for user {:?}",
                self.username
            );
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        if let Some(limiter) = &self.rate_limiter {
            limiter.acquire(data_len).await;
        }

        let Some(SftpFileHandle::File {
            path,
            file,
            written_bytes,
            pending_flush_bytes,
            last_access,
            ..
        }) = self
            .handles
            .get_mut(&handle)
            // 目录句柄与不存在的句柄统一按无效处理
            .filter(|h| matches!(h, SftpFileHandle::File { .. }))
        else {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "WRITE_INVALID_HANDLE",
                handle = %handle,
                total_handles = self.handles.len(),
                "SFTP WRITE: handle not found or invalid type"
            );
            return Err(status_err(StatusCode::Failure, "Invalid handle"));
        };

        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
            tracing::error!("SFTP WRITE seek error for {path:?}: {e}");
            return Err(status_err(StatusCode::Failure, &format!("Seek error: {e}")));
        }

        if let Err(e) = file.write_all(&write_data).await {
            tracing::error!("SFTP WRITE error for {path:?}: {e}");
            return Err(status_err(StatusCode::Failure, &format!("Write error: {e}")));
        }

        let written = data_len as u64;
        *written_bytes += written;
        *pending_flush_bytes += written;
        *last_access = std::time::Instant::now();

        if *pending_flush_bytes >= SFTP_WRITE_FLUSH_THRESHOLD as u64 {
            if let Err(e) = file.flush().await {
                tracing::error!("SFTP WRITE flush error for {path:?}: {e}");
                return Err(status_err(StatusCode::Failure, &format!("Flush error: {e}")));
            }
            if let Err(e) = file.sync_all().await {
                tracing::warn!("SFTP WRITE sync_all error for {path:?}: {e}");
            }
            *pending_flush_bytes = 0;
        }

        tracing::debug!(
            "SFTP WRITE: {data_len} bytes to {path:?} at offset {offset} (pending_flush: {})",
            *pending_flush_bytes
        );

        Ok(status_ok(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::setup_with_perms;

    /// 写后读回环：open(WRITE|CREATE|TRUNC) → write → close → open(READ) → read → close
    #[tokio::test]
    async fn write_read_roundtrip() {
        let mut env = crate::test_util::setup();
        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE;
        let handle = env
            .state
            .open(1, "/a.txt".to_string(), flags, FileAttributes::default())
            .await
            .unwrap()
            .handle;

        let status = env
            .state
            .write(2, handle.clone(), 0, b"hello world".to_vec())
            .await
            .unwrap();
        assert_eq!(status.status_code, StatusCode::Ok);

        env.state.close(3, handle).await.unwrap();

        let handle = env
            .state
            .open(4, "/a.txt".to_string(), OpenFlags::READ, FileAttributes::default())
            .await
            .unwrap()
            .handle;
        let data = env.state.read(5, handle.clone(), 0, 32).await.unwrap();
        assert_eq!(data.data, b"hello world");

        // 偏移读取
        let data = env.state.read(6, handle.clone(), 6, 5).await.unwrap();
        assert_eq!(data.data, b"world");

        env.state.close(7, handle).await.unwrap();
    }

    /// 无写权限时 OPEN(WRITE) 拒绝
    #[tokio::test]
    async fn open_write_denied_without_permission() {
        let mut env = setup_with_perms(|p| p.can_write = false);
        let flags = OpenFlags::WRITE | OpenFlags::CREATE;
        let err = env
            .state
            .open(1, "/a.txt".to_string(), flags, FileAttributes::default())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::PermissionDenied);
    }

    /// 无读权限时 READ 拒绝
    #[tokio::test]
    async fn read_denied_without_permission() {
        let mut env = setup_with_perms(|p| p.can_read = false);
        let flags = OpenFlags::WRITE | OpenFlags::CREATE;
        let handle = env
            .state
            .open(1, "/a.txt".to_string(), flags, FileAttributes::default())
            .await
            .unwrap()
            .handle;
        let err = env
            .state
            .read(2, handle, 0, 8)
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::PermissionDenied);
    }

    /// 空文件读取返回 EOF
    #[tokio::test]
    async fn read_empty_file_eof() {
        let mut env = crate::test_util::setup();
        let path = env.dir.path().join("empty.txt");
        std::fs::File::create(&path).unwrap();

        let handle = env
            .state
            .open(1, "/empty.txt".to_string(), OpenFlags::READ, FileAttributes::default())
            .await
            .unwrap()
            .handle;
        let err = env.state.read(2, handle, 0, 16).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::Eof);
    }

    /// 无效句柄的读/写统一回 FAILURE
    #[tokio::test]
    async fn invalid_handle_rejected() {
        let mut env = crate::test_util::setup();

        let err = env.state.read(1, "ghost".to_string(), 0, 8).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);

        let err = env
            .state
            .write(2, "ghost".to_string(), 0, b"x".to_vec())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);

        // 目录句柄不能当文件句柄用
        let dir_handle = env.state.opendir(3, "/").unwrap().handle;
        let err = env
            .state
            .read(4, dir_handle, 0, 8)
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }

    /// CLOSE 未知句柄回 FAILURE
    #[tokio::test]
    async fn close_unknown_handle() {
        let mut env = crate::test_util::setup();
        let err = env
            .state
            .close(1, "ghost".to_string())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }

    /// EXCL 语义：已存在的文件拒绝以 CREATE|EXCLUDE 打开
    #[tokio::test]
    async fn open_excl_existing_file_fails() {
        let mut env = crate::test_util::setup();
        std::fs::write(env.dir.path().join("exists.txt"), b"x").unwrap();

        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE;
        let err = env
            .state
            .open(1, "/exists.txt".to_string(), flags, FileAttributes::default())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }
}

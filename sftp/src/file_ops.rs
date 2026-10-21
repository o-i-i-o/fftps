//! SFTP 文件操作命令：OPEN / CLOSE / READ / WRITE
//!
//! 覆盖配额预留与结算、限速、写缓冲落盘与文件操作审计。

use anyhow::Result;

use crate::protocol::{
    build_data_packet, build_handle_packet, build_status_packet, parse_string,
    parse_string_with_len, parse_u32, parse_u64,
};
use crate::state::SftpState;
// types 是本 crate 的协议常量/句柄类型聚合模块（等价内部预导入），逐项列举反而降低可读性
#[allow(clippy::wildcard_imports)]
use crate::types::*;

/// 写打开时的配额预留粒度（100 MiB）
const QUOTA_RESERVE_BYTES: u64 = 100 * 1024 * 1024;

impl SftpState {
    /// `SSH_FXP_OPEN`：打开文件并创建句柄
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    // 命令主流程（权限 → 路径解析 → fs 操作 → 审计）保持单函数内联，拆分会割裂协议语义
    #[allow(clippy::too_many_lines)]
    pub async fn handle_open(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (path, path_len) = parse_string_with_len(data, 5)?;
        let pflags = parse_u32(data, 5 + 4 + path_len)?;

        let need_read = pflags & SSH_FXF_READ != 0;
        let need_write = pflags & SSH_FXF_WRITE != 0;
        let need_append = pflags & SSH_FXF_APPEND != 0;
        let need_creat = pflags & SSH_FXF_CREAT != 0;
        let need_trunc = pflags & SSH_FXF_TRUNC != 0;
        let need_excl = pflags & SSH_FXF_EXCL != 0;

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
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        if self.handles.len() >= MAX_HANDLES {
            tracing::warn!(
                "SFTP OPEN denied: too many open handles ({})",
                self.handles.len()
            );
            return Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Too many open handles",
                "",
            ));
        }

        let full_path = match self.resolve_path_checked(id, &path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };
        let file_existed = full_path.exists();

        tracing::debug!(
            "SFTP OPEN: raw='{}', resolved='{}', existed={}, flags=0x{:08X}",
            path,
            full_path.display(),
            file_existed,
            pflags
        );

        let file_result = if need_write || need_append {
            if need_excl && need_creat && file_existed {
                return Ok(build_status_packet(
                    id,
                    SSH_FX_FAILURE,
                    "File already exists",
                    "",
                ));
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
                            return Ok(build_status_packet(
                                id,
                                SSH_FX_FAILURE,
                                "Quota exceeded",
                                "",
                            ));
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
                tracing::debug!("SFTP OPEN: handle '{handle}' created for {path}");
                Ok(build_handle_packet(id, &handle))
            }
            Err(e) => {
                tracing::error!("SFTP OPEN failed for {}: {e}", full_path.display());
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Failed to open file", ""))
            }
        }
    }

    /// `SSH_FXP_CLOSE`：关闭句柄，结算配额并写审计日志
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_close(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let handle = parse_string(data, 5)?;

        if let Some(handle_obj) = self.handles.remove(&handle) {
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
                    use tokio::io::AsyncWriteExt;
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
                            self.quota_manager.commit_usage(
                                &username,
                                quota_reserved,
                                actual_new_bytes,
                            );
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
        } else {
            tracing::debug!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "CLOSE_INVALID",
                handle = %handle,
                "Close request for non-existent handle (already closed or invalid)"
            );
            // 未知句柄按协议回 FAILURE，与其它句柄类命令一致
            return Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle", ""));
        }
        Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
    }

    /// `SSH_FXP_READ`：读文件（单次长度钳制到 [`SFTP_READ_BUFFER_SIZE`]）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    // 命令主流程（权限 → 路径解析 → fs 操作 → 审计）保持单函数内联，拆分会割裂协议语义
    #[allow(clippy::too_many_lines)]
    pub async fn handle_read(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (handle_str, handle_len) = parse_string_with_len(data, 5)?;
        let offset = parse_u64(data, 5 + 4 + handle_len)?;
        let len = parse_u32(data, 5 + 4 + handle_len + 8)? as usize;

        if !self.check_permission(|p| p.can_read) {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "READ_DENIED",
                "SFTP READ denied: no read permission"
            );
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        match self.handles.get_mut(&handle_str) {
            Some(SftpFileHandle::File {
                path,
                file,
                read_bytes,
                last_access,
                ..
            }) => {
                use tokio::io::{AsyncReadExt, AsyncSeekExt};

                if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
                    tracing::error!(
                        client_ip = %self.client_ip,
                        username = ?self.username,
                        action = "READ_ERROR",
                        "SFTP READ seek error for {path:?}: {e}"
                    );
                    return Ok(build_status_packet(
                        id,
                        SSH_FX_FAILURE,
                        &format!("Seek error: {e}"),
                        "",
                    ));
                }

                let read_len = len.min(SFTP_READ_BUFFER_SIZE);
                let mut buffer = vec![0u8; read_len];

                match file.read(&mut buffer).await {
                    Ok(0) => Ok(build_status_packet(id, SSH_FX_EOF, "End of file", "")),
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
                            handle = %handle_str,
                            "Read {} bytes from {:?} at offset {}",
                            n,
                            path,
                            offset
                        );

                        Ok(build_data_packet(id, &buffer))
                    }
                    Err(e) => {
                        tracing::error!(
                            client_ip = %self.client_ip,
                            username = ?self.username,
                            action = "READ_ERROR",
                            "SFTP READ error for {path:?}: {e}"
                        );
                        Ok(build_status_packet(
                            id,
                            SSH_FX_FAILURE,
                            &format!("Read error: {e}"),
                            "",
                        ))
                    }
                }
            }
            Some(SftpFileHandle::Dir { path, .. }) => {
                tracing::warn!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "READ_INVALID_TYPE",
                    handle = %handle_str,
                    "SFTP READ on directory handle (expected file): {path:?}"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle type", ""))
            }
            None => {
                tracing::warn!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "READ_INVALID_HANDLE",
                    handle = %handle_str,
                    total_handles = self.handles.len(),
                    "SFTP READ: handle not found (may be closed or invalid)"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle", ""))
            }
        }
    }

    /// `SSH_FXP_WRITE`：写文件（累计 [`SFTP_WRITE_FLUSH_THRESHOLD`] 后落盘）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    // 命令主流程（权限 → 路径解析 → fs 操作 → 审计）保持单函数内联，拆分会割裂协议语义
    #[allow(clippy::too_many_lines)]
    pub async fn handle_write(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (handle_str, handle_len) = parse_string_with_len(data, 5)?;
        let offset_pos = 5 + 4 + handle_len;
        let offset = parse_u64(data, offset_pos)?;
        let data_len = usize::try_from(parse_u32(data, offset_pos + 8)?)?;

        let Some(write_data) = data.get(offset_pos + 12..offset_pos + 12 + data_len) else {
            tracing::error!(
                "SFTP WRITE: invalid data length - offset_pos={offset_pos}, data_len={data_len}, \
                 packet_len={}",
                data.len()
            );
            return Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Invalid data length",
                "",
            ));
        };

        // 写入放行条件与 OPEN 门禁一致：追加打开仅需 can_append
        if !self.check_permission(|p| p.can_write || p.can_append) {
            tracing::warn!(
                "SFTP WRITE denied: no write permission for user {:?}",
                self.username
            );
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        if let Some(limiter) = &self.rate_limiter {
            limiter.acquire(data_len).await;
        }

        match self.handles.get_mut(&handle_str) {
            Some(SftpFileHandle::File {
                path,
                file,
                written_bytes,
                pending_flush_bytes,
                last_access,
                ..
            }) => {
                use tokio::io::{AsyncSeekExt, AsyncWriteExt};

                if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
                    tracing::error!("SFTP WRITE seek error for {path:?}: {e}");
                    return Ok(build_status_packet(
                        id,
                        SSH_FX_FAILURE,
                        &format!("Seek error: {e}"),
                        "",
                    ));
                }

                if let Err(e) = file.write_all(write_data).await {
                    tracing::error!("SFTP WRITE error for {path:?}: {e}");
                    return Ok(build_status_packet(
                        id,
                        SSH_FX_FAILURE,
                        &format!("Write error: {e}"),
                        "",
                    ));
                }

                *written_bytes += data_len as u64;
                *pending_flush_bytes += data_len as u64;
                *last_access = std::time::Instant::now();

                if *pending_flush_bytes >= SFTP_WRITE_FLUSH_THRESHOLD as u64 {
                    if let Err(e) = file.flush().await {
                        tracing::error!("SFTP WRITE flush error for {path:?}: {e}");
                        return Ok(build_status_packet(
                            id,
                            SSH_FX_FAILURE,
                            &format!("Flush error: {e}"),
                            "",
                        ));
                    }
                    if let Err(e) = file.sync_all().await {
                        tracing::warn!("SFTP WRITE sync_all error for {path:?}: {e}");
                    }
                    *pending_flush_bytes = 0;
                }

                tracing::debug!(
                    "SFTP WRITE: {} bytes to {:?} at offset {} (pending_flush: {})",
                    data_len,
                    path,
                    offset,
                    pending_flush_bytes
                );

                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
            }
            Some(SftpFileHandle::Dir { path, .. }) => {
                tracing::warn!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "WRITE_INVALID_TYPE",
                    handle = %handle_str,
                    "SFTP WRITE on directory handle (expected file): {path:?}"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle type", ""))
            }
            None => {
                tracing::warn!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "WRITE_INVALID_HANDLE",
                    handle = %handle_str,
                    total_handles = self.handles.len(),
                    "SFTP WRITE: handle not found (may be closed or invalid)"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle", ""))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{self, setup, setup_with_perms};

    fn open_req(id: u32, path: &str, pflags: u32) -> Vec<u8> {
        let mut v = vec![SSH_FXP_OPEN];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(path));
        v.extend_from_slice(&pflags.to_be_bytes());
        // ATTRS 空属性（flags=0）
        v.extend_from_slice(&0u32.to_be_bytes());
        v
    }

    fn handle_of(resp: &[u8]) -> String {
        parse_string(test_util::payload(resp), 5).unwrap()
    }

    fn close_req(id: u32, handle: &str) -> Vec<u8> {
        let mut v = vec![SSH_FXP_CLOSE];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(handle));
        v
    }

    fn read_req(id: u32, handle: &str, offset: u64, len: u32) -> Vec<u8> {
        let mut v = vec![SSH_FXP_READ];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(handle));
        v.extend_from_slice(&offset.to_be_bytes());
        v.extend_from_slice(&len.to_be_bytes());
        v
    }

    fn write_req(id: u32, handle: &str, offset: u64, data: &[u8]) -> Vec<u8> {
        let mut v = vec![SSH_FXP_WRITE];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(handle));
        v.extend_from_slice(&offset.to_be_bytes());
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    #[tokio::test]
    async fn test_open_write_read_close_roundtrip() {
        let mut env = setup();

        let flags = SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC;
        let resp = env
            .state
            .dispatch_packet(&open_req(1, "note.txt", flags))
            .await
            .unwrap();
        assert_eq!(test_util::payload(&resp)[0], SSH_FXP_HANDLE);
        let handle = handle_of(&resp);

        let resp = env
            .state
            .dispatch_packet(&write_req(2, &handle, 0, b"hello world"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);

        let resp = env
            .state
            .dispatch_packet(&close_req(3, &handle))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);

        // 重新打开读取
        let resp = env
            .state
            .dispatch_packet(&open_req(4, "note.txt", SSH_FXF_READ))
            .await
            .unwrap();
        let read_handle = handle_of(&resp);
        let resp = env
            .state
            .dispatch_packet(&read_req(5, &read_handle, 0, 5))
            .await
            .unwrap();
        assert_eq!(test_util::payload(&resp)[0], SSH_FXP_DATA);
        let data = parse_string_with_len(test_util::payload(&resp), 5).unwrap().0;
        assert_eq!(data, "hello");

        // 读到末尾 → EOF
        let resp = env
            .state
            .dispatch_packet(&read_req(6, &read_handle, 11, 10))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_EOF);

        env.state
            .dispatch_packet(&close_req(7, &read_handle))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_read_caps_length_at_max() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("small.txt"), b"ab").unwrap();

        let resp = env
            .state
            .dispatch_packet(&open_req(1, "small.txt", SSH_FXF_READ))
            .await
            .unwrap();
        let handle = handle_of(&resp);
        // 请求 u32::MAX 长度：内部钳制，不会超大分配
        let resp = env
            .state
            .dispatch_packet(&read_req(2, &handle, 0, u32::MAX))
            .await
            .unwrap();
        let data = parse_string_with_len(test_util::payload(&resp), 5).unwrap().0;
        assert_eq!(data, "ab");
    }

    #[tokio::test]
    async fn test_open_denied_without_write_permission() {
        let mut env = setup_with_perms(|p| p.can_write = false);
        let resp = env
            .state
            .dispatch_packet(&open_req(
                1,
                "x.txt",
                SSH_FXF_WRITE | SSH_FXF_CREAT,
            ))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_PERMISSION_DENIED);
    }

    #[tokio::test]
    async fn test_open_denied_without_read_permission() {
        let mut env = setup_with_perms(|p| p.can_read = false);
        std::fs::write(env.dir.path().join("x.txt"), b"data").unwrap();
        let resp = env
            .state
            .dispatch_packet(&open_req(1, "x.txt", SSH_FXF_READ))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_PERMISSION_DENIED);
    }

    #[tokio::test]
    async fn test_open_append_allowed_with_append_permission_only() {
        let mut env = setup_with_perms(|p| {
            p.can_write = false;
            p.can_append = true;
        });
        std::fs::write(env.dir.path().join("log.txt"), b"old").unwrap();

        let resp = env
            .state
            .dispatch_packet(&open_req(
                1,
                "log.txt",
                SSH_FXF_WRITE | SSH_FXF_APPEND,
            ))
            .await
            .unwrap();
        let handle = handle_of(&resp);
        env.state
            .dispatch_packet(&write_req(2, &handle, 3, b"new"))
            .await
            .unwrap();
        env.state
            .dispatch_packet(&close_req(3, &handle))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(env.dir.path().join("log.txt")).unwrap(),
            b"oldnew"
        );
    }

    #[tokio::test]
    async fn test_close_unknown_handle_fails() {
        let mut env = setup();
        let resp = env
            .state
            .dispatch_packet(&close_req(1, "nope"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_FAILURE);
    }

    #[tokio::test]
    async fn test_open_excl_existing_file_fails() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("e.txt"), b"x").unwrap();
        let resp = env
            .state
            .dispatch_packet(&open_req(
                1,
                "e.txt",
                SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL,
            ))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_FAILURE);
    }

    #[tokio::test]
    async fn test_write_invalid_data_length_returns_failure() {
        let mut env = setup();
        let resp = env
            .state
            .dispatch_packet(&open_req(
                1,
                "w.txt",
                SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
            ))
            .await
            .unwrap();
        let handle = handle_of(&resp);

        // 构造 data_len 大于实际数据的 WRITE：返回 FAILURE 而不是断开会话
        let mut req = vec![SSH_FXP_WRITE];
        req.extend_from_slice(&2u32.to_be_bytes());
        req.extend_from_slice(&test_util::str_field(&handle));
        req.extend_from_slice(&0u64.to_be_bytes());
        req.extend_from_slice(&64u32.to_be_bytes());
        req.extend_from_slice(b"short");
        let resp = env.state.dispatch_packet(&req).await.unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_FAILURE);
    }
}

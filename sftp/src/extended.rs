//! SFTP 扩展命令（`SSH_FXP_EXTENDED`）
//!
//! 支持 md5sum / sha256sum / copy-file / hardlink / statvfs / fsync / limits
//! `@openssh.com`，同时接受 md5sum、sha256sum、hardlink 的旧裸拼写。
//!
//! 应答 wire 格式差异（对照 OpenSSH）：
//! - md5/sha256：`EXTENDED_REPLY` data 为 `u32 长度 + hex 字符串`
//! - statvfs：data 为 11 个 u64（无长度前缀，与 [`Statvfs`] 序列化一致）
//! - limits：data 为 `string("limits@openssh.com") + 4×u64`

use bytes::Bytes;
// `Md5::new()` 构造函数来自 Digest trait
use md5::Digest as _;

use crate::protocol::{
    de, ser,
    extensions::{self, FsyncExtension, HardlinkExtension, Statvfs, StatvfsExtension},
    message::ExtendedReply,
    Config, Packet, StatusReply, StatusCode,
};
use crate::state::{SftpState, status_err, status_ok};
use crate::types::{SftpFileHandle, MAX_HANDLES, SFTP_READ_BUFFER_SIZE};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// 写请求帧（id + handle + offset + data）开销预留，limits 广播的写上限需留出该空间
const LIMITS_MAX_WRITE_LEN: u64 = 261_120;

/// 通用文件摘要器（md5/sha256 共用流式接口）
trait FileHasher: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize_hex(self: Box<Self>) -> String;
}

struct Md5Hasher(md5::Md5);
struct Sha256Hasher(sha2::Sha256);

impl FileHasher for Md5Hasher {
    fn update(&mut self, data: &[u8]) {
        use md5::Digest;
        self.0.update(data);
    }
    fn finalize_hex(self: Box<Self>) -> String {
        use md5::Digest;
        hex::encode(self.0.finalize())
    }
}

impl FileHasher for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.0.update(data);
    }
    fn finalize_hex(self: Box<Self>) -> String {
        use sha2::Digest;
        hex::encode(self.0.finalize())
    }
}

/// md5sum/sha256sum 请求负载：`string path, u64 start, u64 length`
#[derive(serde::Deserialize)]
struct DigestRequest {
    path: String,
    start: u64,
    length: u64,
}

/// 少数客户端省略 start/length 时的退化负载：仅 `string path`
#[derive(serde::Deserialize)]
struct DigestPathOnly {
    path: String,
}

/// copy-file 请求负载：`string src, string dst`
#[derive(serde::Deserialize)]
struct CopyFileRequest {
    src: String,
    dst: String,
}

/// 扩展负载解析失败
fn malformed_request() -> StatusReply {
    status_err(StatusCode::Failure, "Malformed extended request")
}

impl SftpState {
    /// `SSH_FXP_EXTENDED`：按扩展名分发
    ///
    /// # Errors
    /// 权限不足、负载畸形或 IO 失败时返回错误应答；未知扩展返回 `OP_UNSUPPORTED`
    pub async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<Packet, StatusReply> {
        match request.as_str() {
            "md5sum" | "md5sum@openssh.com" => {
                self.file_digest(id, &data, Box::new(Md5Hasher(md5::Md5::new())))
                    .await
            }
            "sha256sum" | "sha256sum@openssh.com" => {
                self.file_digest(id, &data, Box::new(Sha256Hasher(sha2::Sha256::new())))
                    .await
            }
            "copy-file" => self.copy_file(id, data).await,
            "hardlink" | extensions::HARDLINK => self.hardlink(id, data).await,
            extensions::STATVFS => self.statvfs(id, &data),
            extensions::FSYNC => self.fsync(id, &data).await,
            extensions::LIMITS => limits_reply(id),
            _ => {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "EXTENDED_UNKNOWN",
                    extension = %request,
                    "SFTP EXTENDED: unknown extension"
                );
                Err(status_err(
                    StatusCode::OpUnsupported,
                    &format!("Unsupported extension: {request}"),
                ))
            }
        }
    }

    /// md5sum/sha256sum：对文件区间做流式摘要，应答 `EXTENDED_REPLY`（hex 字符串）
    async fn file_digest(
        &mut self,
        id: u32,
        data: &[u8],
        mut hasher: Box<dyn FileHasher + Send>,
    ) -> Result<Packet, StatusReply> {
        let mut buf = Bytes::copy_from_slice(data);
        let (path, start, length) = if let Ok(r) = de::from_bytes::<DigestRequest>(&mut buf) {
            (r.path, r.start, r.length)
        } else {
            let mut fallback = Bytes::copy_from_slice(data);
            match de::from_bytes::<DigestPathOnly>(&mut fallback) {
                Ok(r) => (r.path, 0, 0),
                Err(_) => return Err(malformed_request()),
            }
        };

        if !self.check_permission(|p| p.can_read) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let full_path = self.resolve_path_or_err(&path)?;

        let mut file = match tokio::fs::File::open(&full_path).await {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("SFTP file hash failed: {e}");
                return Err(if e.kind() == std::io::ErrorKind::PermissionDenied {
                    status_err(StatusCode::PermissionDenied, "Permission denied")
                } else {
                    status_err(StatusCode::NoSuchFile, "No such file")
                });
            }
        };

        if start > 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
            return Err(status_err(StatusCode::Failure, "Seek failed"));
        }

        let mut remaining = if length == 0 { None } else { Some(length) };
        let mut buffer = vec![0u8; 8192];

        loop {
            let to_read = if let Some(rem) = remaining {
                if rem == 0 {
                    break;
                }
                buffer.len().min(rem as usize)
            } else {
                buffer.len()
            };

            match file.read(&mut buffer[..to_read]).await {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buffer[..n]);
                    if let Some(ref mut rem) = remaining {
                        *rem -= n as u64;
                    }
                }
                Err(e) => {
                    return Err(status_err(
                        StatusCode::Failure,
                        &format!("Read error: {e}"),
                    ));
                }
            }
        }

        let hash_hex = hasher.finalize_hex();

        // OpenSSH 期望 data 为 string(hex)：手工补 u32 长度前缀
        let mut payload = (hash_hex.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(hash_hex.as_bytes());
        Ok(Packet::ExtendedReply(ExtendedReply { id, data: payload }))
    }

    /// copy-file：服务端内复制文件（源/目标都必须在 home 内，目标不得已存在）
    ///
    /// # Errors
    /// 权限不足、路径越狱、源不存在、目标已存在、配额超限或复制失败时返回错误应答
    async fn copy_file(&mut self, id: u32, data: Vec<u8>) -> Result<Packet, StatusReply> {
        let mut buf = Bytes::from(data);
        let CopyFileRequest { src, dst } =
            de::from_bytes(&mut buf).map_err(|_| malformed_request())?;

        if !self.check_permission(|p| p.can_read && p.can_write) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let src_full = self.resolve_path_or_err(&src)?;
        let dst_full = self.resolve_path_or_err(&dst)?;

        if !src_full.exists() {
            return Err(status_err(
                StatusCode::NoSuchFile,
                "Source file not found",
            ));
        }

        if dst_full.exists() {
            return Err(status_err(
                StatusCode::Failure,
                "Destination already exists",
            ));
        }

        // 配额：按源大小预留，复制完成后结算
        let quota_mb = self.cached_permissions.as_ref().and_then(|p| p.quota_mb);
        let mut quota_reserved = 0u64;
        if let Some(quota) = quota_mb {
            let src_size = match tokio::fs::metadata(&src_full).await {
                Ok(m) => m.len(),
                Err(e) => {
                    tracing::warn!("SFTP COPY: cannot read source metadata: {e}");
                    return Err(status_err(
                        StatusCode::Failure,
                        "Cannot read source file metadata",
                    ));
                }
            };
            let username = self.audit_user();
            if self
                .quota_manager
                .try_reserve_quota(username, src_size, quota)
            {
                quota_reserved = src_size;
            } else {
                return Err(status_err(StatusCode::Failure, "Quota exceeded"));
            }
        }

        match tokio::fs::copy(&src_full, &dst_full).await {
            Ok(bytes_copied) => {
                if quota_reserved > 0 {
                    let username = self.audit_user().to_string();
                    self.quota_manager
                        .commit_usage(&username, quota_reserved, bytes_copied);
                } else if let Some(username) = &self.username {
                    self.quota_manager.add_usage(username, bytes_copied);
                }
                self.audit_file_op_pair(
                    "COPY",
                    &src_full.to_string_lossy(),
                    &dst_full.to_string_lossy(),
                    bytes_copied,
                    "File copied successfully",
                );
                tracing::debug!(
                    "SFTP COPY_FILE: copied {bytes_copied} bytes from {src_full:?} to {dst_full:?}"
                );
                fftp_common::metrics::record_upload_bytes("SFTP", bytes_copied);
                Ok(status_ok(id).into())
            }
            Err(e) => {
                if quota_reserved > 0 {
                    let username = self.audit_user().to_string();
                    self.quota_manager
                        .rollback_reservation(&username, quota_reserved);
                }
                tracing::error!(
                    "SFTP COPY_FILE failed: {} -> {}: {e}",
                    src_full.display(),
                    dst_full.display()
                );
                Err(status_err(StatusCode::Failure, "Failed to copy file"))
            }
        }
    }

    /// hardlink@openssh.com：创建硬链接（目标不得已存在）
    ///
    /// # Errors
    /// 权限不足、路径越狱、源不存在、目标已存在或创建失败时返回错误应答
    async fn hardlink(&mut self, id: u32, data: Vec<u8>) -> Result<Packet, StatusReply> {
        let mut buf = Bytes::from(data);
        let HardlinkExtension { oldpath, newpath } =
            de::from_bytes(&mut buf).map_err(|_| malformed_request())?;

        if !self.check_permission(|p| p.can_write) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let src_full = self.resolve_path_or_err(&oldpath)?;
        let dst_full = self.resolve_path_or_err(&newpath)?;

        if !src_full.exists() {
            return Err(status_err(
                StatusCode::NoSuchFile,
                "Source file not found",
            ));
        }

        if dst_full.exists() {
            return Err(status_err(
                StatusCode::Failure,
                "Destination already exists",
            ));
        }

        let src = src_full.clone();
        let dst = dst_full.clone();
        match tokio::task::spawn_blocking(move || std::fs::hard_link(&src, &dst)).await {
            Ok(Ok(())) => {
                self.audit_file_op_pair(
                    "HARDLINK",
                    &src_full.to_string_lossy(),
                    &dst_full.to_string_lossy(),
                    0,
                    "Hardlink created successfully",
                );
                tracing::debug!(
                    "SFTP HARDLINK: created hardlink from {src_full:?} to {dst_full:?}"
                );
                Ok(status_ok(id).into())
            }
            Ok(Err(e)) => {
                tracing::error!(
                    "SFTP HARDLINK failed: {} -> {}: {e}",
                    src_full.display(),
                    dst_full.display()
                );
                Err(status_err(
                    StatusCode::Failure,
                    "Failed to create hardlink",
                ))
            }
            Err(e) => {
                tracing::error!("SFTP HARDLINK task failed: {e}");
                Err(status_err(
                    StatusCode::Failure,
                    "Failed to create hardlink",
                ))
            }
        }
    }

    /// statvfs@openssh.com：文件系统空间信息（`EXTENDED_REPLY`，11 个 u64）
    ///
    /// # Errors
    /// 权限不足、路径越狱或空间查询失败时返回错误应答
    fn statvfs(&mut self, id: u32, data: &[u8]) -> Result<Packet, StatusReply> {
        let mut buf = Bytes::copy_from_slice(data);
        let StatvfsExtension { path } =
            de::from_bytes(&mut buf).map_err(|_| malformed_request())?;

        if !self.check_permission(|p| p.can_read || p.can_list) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let full_path = self.resolve_path_or_err(&path)?;

        // 目标可能尚不存在，逐级向上找最近的存在路径
        let mut target_path = full_path.clone();
        while !target_path.exists() {
            if !target_path.pop() {
                target_path = std::path::PathBuf::from(&self.home_dir);
                break;
            }
        }

        let free_space = fs2::free_space(&target_path);
        let available_space = fs2::available_space(&target_path);
        let (free_space, available_space) = match (free_space, available_space) {
            (Ok(f), Ok(a)) => (f, a),
            (e1, e2) => {
                tracing::error!("STATVFS space query error: {e1:?} / {e2:?}");
                return Err(status_err(
                    StatusCode::Failure,
                    "Failed to get filesystem info",
                ));
            }
        };
        let total_space = fs2::total_space(&target_path).unwrap_or(0);

        // statvfs@openssh.com 应答字段（块数按 4 KiB 块折算）
        let statvfs = Statvfs {
            block_size: 4096,
            fragment_size: 4096,
            blocks: total_space / 4096,
            blocks_free: free_space / 4096,
            blocks_avail: available_space / 4096,
            inodes: 1_000_000,
            inodes_free: 500_000,
            inodes_avail: 500_000,
            fs_id: 0,
            flags: 0,
            name_max: 255,
        };

        let payload = ser::to_bytes(&statvfs)
            .map_err(|_| status_err(StatusCode::Failure, "Failed to encode statvfs reply"))?
            .to_vec();
        Ok(Packet::ExtendedReply(ExtendedReply { id, data: payload }))
    }

    /// fsync@openssh.com：刷新文件句柄数据到磁盘
    ///
    /// # Errors
    /// 句柄无效或刷新失败时返回错误应答
    async fn fsync(&mut self, id: u32, data: &[u8]) -> Result<Packet, StatusReply> {
        let mut buf = Bytes::copy_from_slice(data);
        let FsyncExtension { handle } =
            de::from_bytes(&mut buf).map_err(|_| malformed_request())?;

        let Some(SftpFileHandle::File {
            file, last_access, ..
        }) = self
            .handles
            .get_mut(&handle)
            .filter(|h| matches!(h, SftpFileHandle::File { .. }))
        else {
            tracing::debug!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "FSYNC_INVALID_HANDLE",
                handle = %handle,
                "SFTP FSYNC: handle not found or invalid type"
            );
            return Err(status_err(StatusCode::Failure, "Invalid handle"));
        };

        *last_access = Instant::now();

        if let Err(e) = file.flush().await {
            tracing::warn!("SFTP FSYNC flush failed for handle {handle}: {e}");
            return Err(status_err(StatusCode::Failure, &format!("Flush error: {e}")));
        }
        if let Err(e) = file.sync_data().await {
            tracing::warn!("SFTP FSYNC sync_data failed for handle {handle}: {e}");
            return Err(status_err(
                StatusCode::Failure,
                &format!("Sync error: {e}"),
            ));
        }
        tracing::debug!("SFTP FSYNC: handle {handle} flushed to disk");
        Ok(status_ok(id).into())
    }
}

/// limits@openssh.com：广播服务端读/写/句柄上限
///
/// 应答 data 按 OpenSSH 格式：`string("limits@openssh.com") + 4×u64`
fn limits_reply(id: u32) -> Result<Packet, StatusReply> {
    let max_packet_len = u64::from(Config::default().max_client_packet_len);
    let mut payload = ser::to_bytes(extensions::LIMITS)
        .map_err(|_| status_err(StatusCode::Failure, "Failed to encode limits reply"))?
        .to_vec();
    payload.extend_from_slice(&max_packet_len.to_be_bytes());
    payload.extend_from_slice(&(SFTP_READ_BUFFER_SIZE as u64).to_be_bytes());
    payload.extend_from_slice(&LIMITS_MAX_WRITE_LEN.to_be_bytes());
    payload.extend_from_slice(&(MAX_HANDLES as u64).to_be_bytes());
    Ok(Packet::ExtendedReply(ExtendedReply { id, data: payload }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::OpenFlags;
    use crate::protocol::message::{FileAttributes, StatusCode};
    use crate::test_util::setup;

    /// 从 `EXTENDED_REPLY` 的 data 中取出 `u32 长度 + hex` 负载里的 hex 字符串
    fn hex_of(data: &[u8]) -> String {
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        String::from_utf8(data[4..4 + len].to_vec()).unwrap()
    }

    /// 打开文件句柄的辅助
    async fn open_file(state: &mut SftpState, path: &str) -> String {
        state
            .open(1, path.to_string(), OpenFlags::WRITE | OpenFlags::CREATE, FileAttributes::default())
            .await
            .unwrap()
            .handle
    }

    /// md5sum：返回 `u32 长度 + hex` 负载
    #[tokio::test]
    async fn md5sum_full_file() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("f.txt"), b"hello").unwrap();

        let mut data = crate::test_util::str_field("/f.txt");
        data.extend(crate::test_util::u64_field(0));
        data.extend(crate::test_util::u64_field(0));

        let reply = env
            .state
            .extended(1, "md5sum@openssh.com".to_string(), data)
            .await
            .unwrap();
        let Packet::ExtendedReply(r) = reply else {
            panic!("expected ExtendedReply");
        };
        assert_eq!(hex_of(&r.data), "5d41402abc4b2a76b9719d911017c592");
    }

    /// md5sum：省略 start/length 的退化负载（仅 path）
    #[tokio::test]
    async fn md5sum_path_only_payload() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("f.txt"), b"hello").unwrap();

        let reply = env
            .state
            .extended(1, "md5sum".to_string(), crate::test_util::str_field("/f.txt"))
            .await
            .unwrap();
        let Packet::ExtendedReply(r) = reply else {
            panic!("expected ExtendedReply");
        };
        assert_eq!(hex_of(&r.data), "5d41402abc4b2a76b9719d911017c592");
    }

    /// sha256sum：全文件与区间摘要
    #[tokio::test]
    async fn sha256sum_full_and_range() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("f.txt"), b"hello").unwrap();

        let mut data = crate::test_util::str_field("/f.txt");
        data.extend(crate::test_util::u64_field(0));
        data.extend(crate::test_util::u64_field(0));
        let reply = env
            .state
            .extended(1, "sha256sum@openssh.com".to_string(), data)
            .await
            .unwrap();
        let Packet::ExtendedReply(r) = reply else {
            panic!("expected ExtendedReply");
        };
        assert_eq!(
            hex_of(&r.data),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );

        // 区间 [0, 2)："he"（与全文件摘要不同）
        let mut data = crate::test_util::str_field("/f.txt");
        data.extend(crate::test_util::u64_field(0));
        data.extend(crate::test_util::u64_field(2));
        let reply = env
            .state
            .extended(2, "sha256sum@openssh.com".to_string(), data)
            .await
            .unwrap();
        let Packet::ExtendedReply(r) = reply else {
            panic!("expected ExtendedReply");
        };
        let hex = hex_of(&r.data);
        assert_eq!(hex.len(), 64);
        assert_ne!(hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    /// 摘要请求负载畸形回 FAILURE
    #[tokio::test]
    async fn digest_malformed_payload() {
        let mut env = setup();
        let err = env
            .state
            .extended(1, "md5sum".to_string(), vec![0xFF, 0xFF])
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }

    /// copy-file：复制成功；目标已存在拒绝
    #[tokio::test]
    async fn copy_file_roundtrip() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("src.txt"), b"payload").unwrap();

        let mut data = crate::test_util::str_field("/src.txt");
        data.extend(crate::test_util::str_field("/dst.txt"));
        let reply = env
            .state
            .extended(1, "copy-file".to_string(), data)
            .await
            .unwrap();
        let Packet::Status(s) = reply else {
            panic!("expected Status");
        };
        assert_eq!(s.status_code, StatusCode::Ok);
        assert_eq!(std::fs::read(env.dir.path().join("dst.txt")).unwrap(), b"payload");

        // 目标已存在
        let mut data = crate::test_util::str_field("/src.txt");
        data.extend(crate::test_util::str_field("/dst.txt"));
        let err = env
            .state
            .extended(2, "copy-file".to_string(), data)
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }

    /// hardlink：创建成功后两路径内容一致；目标已存在拒绝
    #[tokio::test]
    async fn hardlink_roundtrip() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("src.txt"), b"payload").unwrap();

        let mut data = crate::test_util::str_field("/src.txt");
        data.extend(crate::test_util::str_field("/dst.txt"));
        let reply = env
            .state
            .extended(1, "hardlink@openssh.com".to_string(), data)
            .await
            .unwrap();
        let Packet::Status(s) = reply else {
            panic!("expected Status");
        };
        assert_eq!(s.status_code, StatusCode::Ok);
        assert_eq!(std::fs::read(env.dir.path().join("dst.txt")).unwrap(), b"payload");

        // 目标已存在
        let mut data = crate::test_util::str_field("/src.txt");
        data.extend(crate::test_util::str_field("/dst.txt"));
        let err = env
            .state
            .extended(2, "hardlink@openssh.com".to_string(), data)
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }

    /// statvfs：应答 data 为 11 个 u64（88 字节）
    #[tokio::test]
    async fn statvfs_reply_is_88_bytes() {
        let mut env = setup();
        let reply = env
            .state
            .extended(
                1,
                extensions::STATVFS.to_string(),
                crate::test_util::str_field("/"),
            )
            .await
            .unwrap();
        let Packet::ExtendedReply(r) = reply else {
            panic!("expected ExtendedReply");
        };
        assert_eq!(r.data.len(), 88);
    }

    /// fsync：有效句柄回 STATUS OK；无效句柄回 FAILURE
    #[tokio::test]
    async fn fsync_ok_and_invalid_handle() {
        let mut env = setup();
        let handle = open_file(&mut env.state, "/f.txt").await;

        let reply = env
            .state
            .extended(
                1,
                extensions::FSYNC.to_string(),
                crate::test_util::str_field(&handle),
            )
            .await
            .unwrap();
        let Packet::Status(s) = reply else {
            panic!("expected Status");
        };
        assert_eq!(s.status_code, StatusCode::Ok);

        let err = env
            .state
            .extended(
                2,
                extensions::FSYNC.to_string(),
                crate::test_util::str_field("ghost"),
            )
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }

    /// limits：data = string("limits@openssh.com") + 4×u64
    #[tokio::test]
    async fn limits_reply_format() {
        let mut env = setup();
        let reply = env
            .state
            .extended(1, extensions::LIMITS.to_string(), Vec::new())
            .await
            .unwrap();
        let Packet::ExtendedReply(r) = reply else {
            panic!("expected ExtendedReply");
        };

        let name_len = u32::from_be_bytes([r.data[0], r.data[1], r.data[2], r.data[3]]) as usize;
        assert_eq!(&r.data[4..4 + name_len], extensions::LIMITS.as_bytes());

        let nums = &r.data[4 + name_len..];
        assert_eq!(nums.len(), 32);
        let read_u64 = |off: usize| {
            u64::from_be_bytes(nums[off..off + 8].try_into().unwrap())
        };
        assert_eq!(read_u64(0), 262_144); // max_packet
        assert_eq!(read_u64(8), crate::types::SFTP_READ_BUFFER_SIZE as u64); // max_read
        assert_eq!(read_u64(16), 261_120); // max_write
        assert_eq!(read_u64(24), crate::types::MAX_HANDLES as u64); // max_open_handles
    }

    /// 未知扩展回 `OP_UNSUPPORTED`
    #[tokio::test]
    async fn unknown_extension_unsupported() {
        let mut env = setup();
        let err = env
            .state
            .extended(1, "no-such-ext@openssh.com".to_string(), Vec::new())
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::OpUnsupported);
    }
}

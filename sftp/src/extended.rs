//! SFTP 扩展命令（`SSH_FXP_EXTENDED`）
//!
//! 支持 md5sum / sha256sum / copy-file / hardlink / statvfs@openssh.com，
//! 同时接受旧拼写（`md5sum`）与 OpenSSH 拼写（`md5sum@openssh.com`）。

use anyhow::Result;

use crate::protocol::{
    build_packet, build_status_packet, parse_string, parse_string_with_len, parse_u32, parse_u64,
};
use crate::state::SftpState;
// types 是本 crate 的协议常量/句柄类型聚合模块（等价内部预导入），逐项列举反而降低可读性
#[allow(clippy::wildcard_imports)]
use crate::types::*;

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

/// 解析 md5sum/sha256sum 扩展请求体：`string path, u64 start, u64 length`
///
/// start/length 缺省为 0（表示整文件）。路径必须是严格 UTF-8
/// （wire 上的路径不接受有损解码）。纯函数，便于测试 wire 格式。
#[must_use]
pub fn parse_digest_request(data: &[u8]) -> Option<(String, u64, u64)> {
    let path_len = parse_u32(data, 0).ok()? as usize;
    if data.len() < 4 + path_len {
        return None;
    }
    let path = std::str::from_utf8(&data[4..4 + path_len]).ok()?.to_string();
    let start_pos = 4 + path_len;
    let (start, length) = if data.len() >= start_pos + 16 {
        (
            parse_u64(data, start_pos).ok()?,
            parse_u64(data, start_pos + 8).ok()?,
        )
    } else {
        (0, 0)
    };
    Some((path, start, length))
}

impl SftpState {
    /// `SSH_FXP_EXTENDED`：按扩展名分发
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_extended(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (ext_name, ext_len) = parse_string_with_len(data, 5)?;

        match ext_name.as_str() {
            "md5sum" | "md5sum@openssh.com" => {
                use md5::Digest;
                self.handle_file_hash(id, data, ext_len, Box::new(Md5Hasher(md5::Md5::new())))
                    .await
            }
            "sha256sum" | "sha256sum@openssh.com" => {
                use sha2::Digest;
                self.handle_file_hash(
                    id,
                    data,
                    ext_len,
                    Box::new(Sha256Hasher(sha2::Sha256::new())),
                )
                .await
            }
            "copy-file" => self.handle_copy_file(id, data, ext_len).await,
            "hardlink" | "hardlink@openssh.com" => self.handle_hardlink(id, data, ext_len).await,
            "statvfs@openssh.com" => self.handle_statvfs(id, data, ext_len),
            _ => {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "EXTENDED_UNKNOWN",
                    extension = %ext_name,
                    "SFTP EXTENDED: unknown extension"
                );
                Ok(build_status_packet(
                    id,
                    SSH_FX_OP_UNSUPPORTED,
                    &format!("Unsupported extension: {ext_name}"),
                    "",
                ))
            }
        }
    }

    /// md5sum/sha256sum：对文件区间做流式摘要，应答 `SSH_FXP_EXTENDED_REPLY`（hex 字符串）
    async fn handle_file_hash(
        &mut self,
        id: u32,
        data: &[u8],
        ext_len: usize,
        mut hasher: Box<dyn FileHasher + Send>,
    ) -> Result<Vec<u8>> {
        let path_pos = 5 + 4 + ext_len;
        let (path, path_len) = parse_string_with_len(data, path_pos)?;
        let start_pos = path_pos + 4 + path_len;
        let start = parse_u64(data, start_pos)?;
        let len_pos = start_pos + 8;
        let length = parse_u64(data, len_pos)?;

        if !self.check_permission(|p| p.can_read) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let full_path = match self.resolve_path_checked(id, &path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        match tokio::fs::File::open(&full_path).await {
            Ok(mut file) => {
                use tokio::io::AsyncReadExt;
                use tokio::io::AsyncSeekExt;

                if start > 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
                    return Ok(build_status_packet(id, SSH_FX_FAILURE, "Seek failed", ""));
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
                            return Ok(build_status_packet(
                                id,
                                SSH_FX_FAILURE,
                                &format!("Read error: {e}"),
                                "",
                            ));
                        }
                    }
                }

                let hash_hex = hasher.finalize_hex();

                let mut payload = vec![SSH_FXP_EXTENDED_REPLY];
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&(hash_hex.len() as u32).to_be_bytes());
                payload.extend_from_slice(hash_hex.as_bytes());
                Ok(build_packet(&payload))
            }
            Err(e) => {
                tracing::debug!("SFTP file hash failed: {e}");
                let (code, msg) = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    (SSH_FX_PERMISSION_DENIED, "Permission denied")
                } else {
                    (SSH_FX_NO_SUCH_FILE, "No such file")
                };
                Ok(build_status_packet(id, code, msg, ""))
            }
        }
    }

    /// copy-file：服务端内复制文件（源/目标都必须在 home 内，目标不得已存在）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_copy_file(
        &mut self,
        id: u32,
        data: &[u8],
        ext_len: usize,
    ) -> Result<Vec<u8>> {
        let src_pos = 5 + 4 + ext_len;
        let (src_path, src_len) = parse_string_with_len(data, src_pos)?;
        let dst_pos = src_pos + 4 + src_len;
        let dst_path = parse_string(data, dst_pos)?;

        if !self.check_permission(|p| p.can_read && p.can_write) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let src_full = match self.resolve_path_checked(id, &src_path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };
        let dst_full = match self.resolve_path_checked(id, &dst_path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        if !src_full.exists() {
            return Ok(build_status_packet(
                id,
                SSH_FX_NO_SUCH_FILE,
                "Source file not found",
                "",
            ));
        }

        if dst_full.exists() {
            return Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Destination already exists",
                "",
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
                    return Ok(build_status_packet(
                        id,
                        SSH_FX_FAILURE,
                        "Cannot read source file metadata",
                        "",
                    ));
                }
            };
            let username = self.audit_user();
            if self.quota_manager.try_reserve_quota(username, src_size, quota) {
                quota_reserved = src_size;
            } else {
                return Ok(build_status_packet(id, SSH_FX_FAILURE, "Quota exceeded", ""));
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
                    "SFTP COPY_FILE: copied {bytes_copied} bytes from {:?} to {:?}",
                    src_full,
                    dst_full
                );
                fftp_common::metrics::record_upload_bytes("SFTP", bytes_copied);
                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
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
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Failed to copy file", ""))
            }
        }
    }

    /// hardlink@openssh.com：创建硬链接（目标不得已存在）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_hardlink(
        &mut self,
        id: u32,
        data: &[u8],
        ext_len: usize,
    ) -> Result<Vec<u8>> {
        let src_pos = 5 + 4 + ext_len;
        let (src_path, src_len) = parse_string_with_len(data, src_pos)?;
        let dst_pos = src_pos + 4 + src_len;
        let dst_path = parse_string(data, dst_pos)?;

        if !self.check_permission(|p| p.can_write) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let src_full = match self.resolve_path_checked(id, &src_path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };
        let dst_full = match self.resolve_path_checked(id, &dst_path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        if !src_full.exists() {
            return Ok(build_status_packet(
                id,
                SSH_FX_NO_SUCH_FILE,
                "Source file not found",
                "",
            ));
        }

        if dst_full.exists() {
            return Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Destination already exists",
                "",
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
                    "SFTP HARDLINK: created hardlink from {:?} to {:?}",
                    src_full,
                    dst_full
                );
                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
            }
            Ok(Err(e)) => {
                tracing::error!(
                    "SFTP HARDLINK failed: {} -> {}: {e}",
                    src_full.display(),
                    dst_full.display()
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Failed to create hardlink", ""))
            }
            Err(e) => {
                tracing::error!("SFTP HARDLINK task failed: {e}");
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Failed to create hardlink", ""))
            }
        }
    }

    /// statvfs@openssh.com：文件系统空间信息（`SSH_FXP_EXTENDED_REPLY`，11 个 u64）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub fn handle_statvfs(
        &mut self,
        id: u32,
        data: &[u8],
        ext_len: usize,
    ) -> Result<Vec<u8>> {
        let path_pos = 5 + 4 + ext_len;
        let path = parse_string(data, path_pos)?;

        if !self.check_permission(|p| p.can_read || p.can_list) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let full_path = match self.resolve_path_checked(id, &path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

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
                return Ok(build_status_packet(
                    id,
                    SSH_FX_FAILURE,
                    "Failed to get filesystem info",
                    "",
                ));
            }
        };
        let total_space = fs2::total_space(&target_path).unwrap_or(0);

        // statvfs@openssh.com 应答字段（块数按 4 KiB 块折算）
        let bsize: u64 = 4096;
        let frsize: u64 = 4096;
        let blocks: u64 = total_space / frsize;
        let bfree: u64 = free_space / frsize;
        let bavail: u64 = available_space / frsize;
        let files: u64 = 1_000_000;
        let ffree: u64 = 500_000;
        let favail: u64 = 500_000;
        let fsid: u64 = 0;
        let flag: u64 = 0;
        let namemax: u64 = 255;

        let mut payload = vec![SSH_FXP_EXTENDED_REPLY];
        payload.extend_from_slice(&id.to_be_bytes());

        payload.extend_from_slice(&bsize.to_be_bytes());
        payload.extend_from_slice(&frsize.to_be_bytes());
        payload.extend_from_slice(&blocks.to_be_bytes());
        payload.extend_from_slice(&bfree.to_be_bytes());
        payload.extend_from_slice(&bavail.to_be_bytes());
        payload.extend_from_slice(&files.to_be_bytes());
        payload.extend_from_slice(&ffree.to_be_bytes());
        payload.extend_from_slice(&favail.to_be_bytes());
        payload.extend_from_slice(&fsid.to_be_bytes());
        payload.extend_from_slice(&flag.to_be_bytes());
        payload.extend_from_slice(&namemax.to_be_bytes());

        Ok(build_packet(&payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{self, setup};

    fn ext_req(id: u32, ext_name: &str, body: &[u8]) -> Vec<u8> {
        let mut v = vec![SSH_FXP_EXTENDED];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(ext_name));
        v.extend_from_slice(body);
        v
    }

    fn digest_body(path: &str, start: u64, length: u64) -> Vec<u8> {
        let mut v = test_util::str_field(path);
        v.extend_from_slice(&start.to_be_bytes());
        v.extend_from_slice(&length.to_be_bytes());
        v
    }

    // ---- parse_digest_request wire 格式（源自 Linux 侧 ops/tests.rs）----

    #[test]
    fn test_parse_digest_request_wire_format() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
        buf.extend_from_slice(&1u64.to_be_bytes());
        buf.extend_from_slice(&2u64.to_be_bytes());
        assert_eq!(parse_digest_request(&buf), Some(("abc".to_string(), 1, 2)));
    }

    #[test]
    fn test_parse_digest_request_defaults_offset_length() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
        assert_eq!(parse_digest_request(&buf), Some(("abc".to_string(), 0, 0)));
    }

    #[test]
    fn test_parse_digest_request_rejects_truncated_and_bad_utf8() {
        assert_eq!(parse_digest_request(&[]), None);
        assert_eq!(parse_digest_request(&[0xFF, 0xFF, 0xFF, 0xFF]), None);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(0xFF);
        assert_eq!(parse_digest_request(&buf), None);
    }

    // ---- md5sum / sha256sum ----

    #[tokio::test]
    async fn test_md5sum_extension_reply_wire_format() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("abc.txt"), b"abc").unwrap();

        let body = digest_body("/abc.txt", 0, 0);
        let resp = env
            .state
            .dispatch_packet(&ext_req(1, "md5sum@openssh.com", &body))
            .await
            .unwrap();
        let payload = test_util::payload(&resp);
        assert_eq!(payload[0], SSH_FXP_EXTENDED_REPLY);
        let digest = parse_string(payload, 5).unwrap();
        // md5("abc")
        assert_eq!(digest, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[tokio::test]
    async fn test_sha256sum_with_range() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("r.txt"), b"abcdef").unwrap();

        // 仅摘要前 3 字节 "abc"
        let body = digest_body("/r.txt", 0, 3);
        let resp = env
            .state
            .dispatch_packet(&ext_req(1, "sha256sum", &body))
            .await
            .unwrap();
        let payload = test_util::payload(&resp);
        assert_eq!(payload[0], SSH_FXP_EXTENDED_REPLY);
        let digest = parse_string(payload, 5).unwrap();
        // sha256("abc")
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn test_hash_nonexistent_file_returns_no_such_file() {
        let mut env = setup();
        let body = digest_body("/missing.bin", 0, 0);
        let resp = env
            .state
            .dispatch_packet(&ext_req(1, "md5sum@openssh.com", &body))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_NO_SUCH_FILE);
    }

    // ---- copy-file / hardlink ----

    #[tokio::test]
    async fn test_copy_file_roundtrip() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("src.txt"), b"payload").unwrap();

        let mut body = test_util::str_field("/src.txt");
        body.extend_from_slice(&test_util::str_field("/dst.txt"));
        let resp = env
            .state
            .dispatch_packet(&ext_req(1, "copy-file", &body))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);
        assert_eq!(
            std::fs::read(env.dir.path().join("dst.txt")).unwrap(),
            b"payload"
        );

        // 目标已存在 → 拒绝
        let resp = env
            .state
            .dispatch_packet(&ext_req(2, "copy-file", &body))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_FAILURE);
    }

    #[tokio::test]
    async fn test_hardlink_roundtrip() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("h1.txt"), b"linked").unwrap();

        let mut body = test_util::str_field("/h1.txt");
        body.extend_from_slice(&test_util::str_field("/h2.txt"));
        let resp = env
            .state
            .dispatch_packet(&ext_req(1, "hardlink@openssh.com", &body))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);
        assert_eq!(
            std::fs::read(env.dir.path().join("h2.txt")).unwrap(),
            b"linked"
        );
    }

    // ---- statvfs@openssh.com / 未知扩展 ----

    #[tokio::test]
    async fn test_statvfs_reply_layout() {
        let mut env = setup();
        let body = test_util::str_field("/");
        let resp = env
            .state
            .dispatch_packet(&ext_req(1, "statvfs@openssh.com", &body))
            .await
            .unwrap();
        let payload = test_util::payload(&resp);
        assert_eq!(payload[0], SSH_FXP_EXTENDED_REPLY);
        // 11 个 u64 字段
        assert_eq!(payload.len(), 5 + 11 * 8);
        assert_eq!(parse_u64(payload, 5).unwrap(), 4096); // bsize
    }

    #[tokio::test]
    async fn test_unknown_extension_op_unsupported() {
        let mut env = setup();
        let resp = env
            .state
            .dispatch_packet(&ext_req(1, "nope@nowhere", &[]))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OP_UNSUPPORTED);
    }
}

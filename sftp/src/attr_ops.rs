//! SFTP 属性操作命令：STAT / LSTAT / FSTAT / SETSTAT / FSETSTAT

use std::path::Path;

use anyhow::Result;

use crate::protocol::{
    build_attrs_from_metadata, build_packet, build_status_packet, parse_string,
    parse_string_with_len, parse_u32,
};
use crate::state::SftpState;
// types 是本 crate 的协议常量/句柄类型聚合模块（等价内部预导入），逐项列举反而降低可读性
#[allow(clippy::wildcard_imports)]
use crate::types::*;

impl SftpState {
    /// `SSH_FXP_STAT`：跟随符号链接的属性查询
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_stat(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let path = parse_string(data, 5)?;

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

        match tokio::fs::metadata(&full_path).await {
            Ok(metadata) => {
                let is_dir = metadata.is_dir();
                let attrs = build_attrs_from_metadata(&metadata, is_dir);
                let mut payload = vec![SSH_FXP_ATTRS];
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&attrs);
                Ok(build_packet(&payload))
            }
            Err(e) => {
                tracing::debug!("SFTP STAT failed for {full_path:?}: {e}");
                let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    "Permission denied"
                } else {
                    "No such file"
                };
                Ok(build_status_packet(id, SSH_FX_NO_SUCH_FILE, msg, ""))
            }
        }
    }

    /// `SSH_FXP_LSTAT`：不跟随符号链接的属性查询
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_lstat(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let path = parse_string(data, 5)?;

        if !self.check_permission(|p| p.can_read || p.can_list) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        // 不跟随符号链接：末段文件名保留，符号链接自身可被 LSTAT
        let full_path = match self.resolve_path_no_follow_checked(id, &path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        match tokio::fs::symlink_metadata(&full_path).await {
            Ok(metadata) => {
                let is_dir = metadata.is_dir();
                let is_symlink = metadata.file_type().is_symlink();
                let attrs = build_attrs_from_metadata(&metadata, is_dir || is_symlink);
                let mut payload = vec![SSH_FXP_ATTRS];
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&attrs);
                Ok(build_packet(&payload))
            }
            Err(e) => {
                tracing::debug!("SFTP LSTAT failed for {full_path:?}: {e}");
                let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    "Permission denied"
                } else {
                    "No such file"
                };
                Ok(build_status_packet(id, SSH_FX_NO_SUCH_FILE, msg, ""))
            }
        }
    }

    /// `SSH_FXP_FSTAT`：按句柄查询属性
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_fstat(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let handle_str = parse_string(data, 5)?;

        match self.handles.get(&handle_str) {
            Some(SftpFileHandle::File { file, .. }) => match file.metadata().await {
                Ok(metadata) => {
                    let mut payload = vec![SSH_FXP_ATTRS];
                    payload.extend_from_slice(&id.to_be_bytes());
                    payload.extend_from_slice(&build_attrs_from_metadata(
                        &metadata,
                        metadata.is_dir(),
                    ));
                    Ok(build_packet(&payload))
                }
                Err(e) => {
                    tracing::debug!("SFTP FSTAT failed: {e}");
                    let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        "Permission denied"
                    } else {
                        "No such file"
                    };
                    Ok(build_status_packet(id, SSH_FX_NO_SUCH_FILE, msg, ""))
                }
            },
            Some(SftpFileHandle::Dir { .. }) => {
                tracing::warn!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "FSTAT_INVALID_TYPE",
                    handle = %handle_str,
                    "SFTP FSTAT on directory handle (expected file)"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle type", ""))
            }
            None => {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "FSTAT_INVALID_HANDLE",
                    handle = %handle_str,
                    "SFTP FSTAT: handle not found"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle", ""))
            }
        }
    }

    /// `SSH_FXP_SETSTAT`：按路径修改属性
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_setstat(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (path, path_len) = parse_string_with_len(data, 5)?;

        if !self.check_permission(|p| p.can_write) {
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

        if !full_path.exists() {
            return Ok(build_status_packet(id, SSH_FX_NO_SUCH_FILE, "No such file", ""));
        }

        let attr_offset = 5 + 4 + path_len;
        if attr_offset >= data.len() {
            return Ok(build_status_packet(id, SSH_FX_OK, "OK", ""));
        }

        match apply_file_attributes(&full_path, &data[attr_offset..]).await {
            Ok(()) => {
                tracing::debug!("SETSTAT applied to {full_path:?}");
                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
            }
            Err(e) => {
                tracing::warn!("SETSTAT failed for {full_path:?}: {e}");
                Ok(build_status_packet(
                    id,
                    SSH_FX_FAILURE,
                    &format!("Failed to set attributes: {e}"),
                    "",
                ))
            }
        }
    }

    /// `SSH_FXP_FSETSTAT`：按句柄修改属性
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_fsetstat(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (handle_str, handle_len) = parse_string_with_len(data, 5)?;

        if !self.check_permission(|p| p.can_write) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let path = match self.handles.get(&handle_str) {
            Some(SftpFileHandle::File { path, .. } | SftpFileHandle::Dir { path, .. }) => {
                path.clone()
            }
            None => {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "FSETSTAT_INVALID_HANDLE",
                    handle = %handle_str,
                    "SFTP FSETSTAT: handle not found"
                );
                return Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle", ""));
            }
        };

        let attr_offset = 5 + 4 + handle_len;
        if attr_offset >= data.len() {
            return Ok(build_status_packet(id, SSH_FX_OK, "OK", ""));
        }

        match apply_file_attributes(&path, &data[attr_offset..]).await {
            Ok(()) => {
                tracing::debug!("FSETSTAT applied to {path:?}");
                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
            }
            Err(e) => {
                tracing::warn!("FSETSTAT failed for {path:?}: {e}");
                Ok(build_status_packet(
                    id,
                    SSH_FX_FAILURE,
                    &format!("Failed to set attributes: {e}"),
                    "",
                ))
            }
        }
    }
}

/// 应用 ATTRS 修改文件：size（截断/扩容）、permissions（仅 Unix 生效）、atime/mtime
///
/// # Errors
/// 文件操作失败时返回错误
pub async fn apply_file_attributes(path: &Path, data: &[u8]) -> Result<()> {
    if data.len() < 4 {
        return Ok(());
    }

    let flags = parse_u32(data, 0)?;
    let mut offset = 4;

    let need_set_size = flags & SSH_FILEXFER_ATTR_SIZE != 0;
    let need_set_times = flags
        & (SSH_FILEXFER_ATTR_ACMODTIME
            | SSH_FILEXFER_ATTR_ACCESSTIME
            | SSH_FILEXFER_ATTR_CREATETIME)
        != 0;

    let mut target_size: Option<u64> = None;
    let mut atime_sec: Option<u64> = None;
    let mut mtime_sec: Option<u64> = None;

    if need_set_size && offset + 8 <= data.len() {
        target_size = Some(crate::protocol::parse_u64(data, offset)?);
        offset += 8;
    }

    if flags & SSH_FILEXFER_ATTR_UIDGID != 0 && offset + 8 <= data.len() {
        offset += 8; // uid + gid
    }

    if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 && offset + 4 <= data.len() {
        let permissions = parse_u32(data, offset)?;
        offset += 4;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = permissions & 0o777;
            let metadata = tokio::fs::metadata(path).await?;
            let mut perm = metadata.permissions();
            perm.set_mode(mode);
            tokio::fs::set_permissions(path, perm).await?;
        }
        #[cfg(windows)]
        {
            tracing::debug!(
                "SETSTAT: permissions change to {permissions:o} for {path:?} (ignored on Windows)"
            );
        }
    }

    // v3 ACMODTIME：u32 atime + u32 mtime（绝大多数客户端走这里）
    if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 && offset + 8 <= data.len() {
        atime_sec = Some(u64::from(parse_u32(data, offset)?));
        mtime_sec = Some(u64::from(parse_u32(data, offset + 4)?));
        offset += 8;
    }

    // v4+ ACCESSTIME：u64 atime + u64 mtime（秒，纳秒部分忽略）
    if flags & SSH_FILEXFER_ATTR_ACCESSTIME != 0 && offset + 16 <= data.len() {
        atime_sec = Some(crate::protocol::parse_u64(data, offset)?);
        mtime_sec = Some(crate::protocol::parse_u64(data, offset + 8)?);
        offset += 16;
    }

    // v4+ CREATETIME：u64 创建时间，Unix 无创建时间概念，仅记录日志
    if flags & SSH_FILEXFER_ATTR_CREATETIME != 0 && offset + 8 <= data.len() {
        let creatime = crate::protocol::parse_u64(data, offset)?;
        tracing::debug!("SETSTAT: create time {creatime} for {path:?} (ignored)");
    }

    if !need_set_size && !need_set_times {
        return Ok(());
    }

    let file = tokio::fs::OpenOptions::new().write(true).open(path).await?;

    if let Some(size) = target_size {
        file.set_len(size).await?;
        tracing::debug!("SETSTAT: set size to {size} for {path:?}");
    }

    if atime_sec.is_some() || mtime_sec.is_some() {
        use std::time::{Duration, SystemTime};
        let std_file = file.into_std().await;
        let metadata = std_file.metadata()?;

        let atime = atime_sec
            .map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(s))
            .or_else(|| metadata.accessed().ok())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mtime = mtime_sec
            .map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(s))
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
    use crate::test_util::{self, setup};

    fn path_req(cmd: u8, id: u32, path: &str) -> Vec<u8> {
        let mut v = vec![cmd];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(path));
        v
    }

    #[tokio::test]
    async fn test_stat_returns_attrs() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("s.txt"), b"hello").unwrap();

        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_STAT, 1, "/s.txt"))
            .await
            .unwrap();
        let payload = test_util::payload(&resp);
        assert_eq!(payload[0], SSH_FXP_ATTRS);
        let flags = parse_u32(payload, 5).unwrap();
        assert!(flags & SSH_FILEXFER_ATTR_SIZE != 0);
        assert_eq!(
            crate::protocol::parse_u64(payload, 9).unwrap(),
            5,
            "ATTRS.size 应为文件真实大小"
        );
    }

    #[tokio::test]
    async fn test_stat_nonexistent_returns_no_such_file() {
        let mut env = setup();
        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_STAT, 1, "/missing.txt"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_NO_SUCH_FILE);
    }

    #[tokio::test]
    async fn test_apply_attributes_truncates_size() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("t.txt");
        std::fs::write(&file, b"0123456789").unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&SSH_FILEXFER_ATTR_SIZE.to_be_bytes());
        data.extend_from_slice(&4u64.to_be_bytes());
        apply_file_attributes(&file, &data).await.unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"0123");
    }

    #[tokio::test]
    async fn test_apply_attributes_v3_acmodtime() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("t.txt");
        std::fs::write(&file, b"x").unwrap();

        // v3：flags=0x08 + u32 atime + u32 mtime
        let mut data = Vec::new();
        data.extend_from_slice(&SSH_FILEXFER_ATTR_ACMODTIME.to_be_bytes());
        data.extend_from_slice(&1_000_000u32.to_be_bytes());
        data.extend_from_slice(&1_234_567u32.to_be_bytes());
        apply_file_attributes(&file, &data).await.unwrap();

        let mtime = std::fs::metadata(&file)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(mtime, 1_234_567);
    }

    #[tokio::test]
    async fn test_apply_attributes_v4_accesstime_u64() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("t.txt");
        std::fs::write(&file, b"x").unwrap();

        // v4+：flags=0x10 + u64 atime + u64 mtime
        let mut data = Vec::new();
        data.extend_from_slice(&SSH_FILEXFER_ATTR_ACCESSTIME.to_be_bytes());
        data.extend_from_slice(&1_000_000u64.to_be_bytes());
        data.extend_from_slice(&2_000_000u64.to_be_bytes());
        apply_file_attributes(&file, &data).await.unwrap();

        let mtime = std::fs::metadata(&file)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(mtime, 2_000_000);
    }
}

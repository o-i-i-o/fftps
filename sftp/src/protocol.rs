//! SFTP 报文编解码与属性（ATTRS）构建
//!
//! 全部为纯函数，便于单元测试覆盖协议编解码边界。

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};

// types 是本 crate 的协议常量/句柄类型聚合模块（等价内部预导入），逐项列举反而降低可读性
#[allow(clippy::wildcard_imports)]
use crate::types::*;

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

/// 按大端序解析 `u32`
///
/// # Errors
/// 剩余数据不足 4 字节时返回错误
pub fn parse_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("Insufficient data for u32 at offset {offset}"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// 按大端序解析 `u64`
///
/// # Errors
/// 剩余数据不足 8 字节时返回错误
pub fn parse_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| anyhow!("Insufficient data for u64 at offset {offset}"))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
}

/// 解析长度前缀字符串（内容按 UTF-8 lossy 转换）
///
/// # Errors
/// 长度前缀越界或内容超出剩余数据时返回错误
pub fn parse_string(data: &[u8], offset: usize) -> Result<String> {
    Ok(parse_string_with_len(data, offset)?.0)
}

/// 解析长度前缀字符串并返回 `(内容, 内容字节数)`
///
/// # Errors
/// 长度前缀越界或内容超出剩余数据时返回错误
pub fn parse_string_with_len(data: &[u8], offset: usize) -> Result<(String, usize)> {
    let len = usize::try_from(parse_u32(data, offset)?)?;
    let content = data
        .get(offset + 4..offset + 4 + len)
        .ok_or_else(|| anyhow!("String length {len} exceeds available data at offset {offset}"))?;
    Ok((String::from_utf8_lossy(content).to_string(), len))
}

// ---------------------------------------------------------------------------
// 构建
// ---------------------------------------------------------------------------

/// 加上 u32 长度前缀打包为 SFTP 报文
#[must_use]
pub fn build_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// `SSH_FXP_VERSION` 应答，携带支持的扩展通告
#[must_use]
pub fn build_version_packet(version: u32, extensions: &[(String, String)]) -> Vec<u8> {
    let mut payload = vec![SSH_FXP_VERSION];
    payload.extend_from_slice(&version.to_be_bytes());
    for (name, value) in extensions {
        payload.extend_from_slice(&(name.len() as u32).to_be_bytes());
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
        payload.extend_from_slice(value.as_bytes());
    }
    build_packet(&payload)
}

/// `SSH_FXP_STATUS` 应答
#[must_use]
pub fn build_status_packet(id: u32, status: u32, msg: &str, lang: &str) -> Vec<u8> {
    let mut payload = vec![SSH_FXP_STATUS];
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&status.to_be_bytes());
    payload.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    payload.extend_from_slice(msg.as_bytes());
    payload.extend_from_slice(&(lang.len() as u32).to_be_bytes());
    payload.extend_from_slice(lang.as_bytes());
    build_packet(&payload)
}

/// `SSH_FXP_HANDLE` 应答
#[must_use]
pub fn build_handle_packet(id: u32, handle: &str) -> Vec<u8> {
    let mut payload = vec![SSH_FXP_HANDLE];
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&(handle.len() as u32).to_be_bytes());
    payload.extend_from_slice(handle.as_bytes());
    build_packet(&payload)
}

/// `SSH_FXP_DATA` 应答
#[must_use]
pub fn build_data_packet(id: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = vec![SSH_FXP_DATA];
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&(data.len() as u32).to_be_bytes());
    payload.extend_from_slice(data);
    build_packet(&payload)
}

// ---------------------------------------------------------------------------
// 属性（ATTRS）
// ---------------------------------------------------------------------------

/// 权限位映射：Unix 取真实 mode，其他平台按类型给默认值
///
/// SFTP 属性中的 permissions 字段按 POSIX 语义编码（目录 0o4xxxx / 文件 0o1xxxx）。
#[must_use]
pub fn attrs_permission(metadata: Option<&std::fs::Metadata>, is_dir: bool) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Some(m) = metadata {
            let file_type = if m.is_dir() { 0o040_000 } else { 0o100_000 };
            return file_type | (m.mode() & 0o7777);
        }
    }
    let _ = metadata;
    if is_dir {
        0o040_755
    } else {
        0o100_644
    }
}

fn unix_time(t: std::io::Result<SystemTime>) -> u32 {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| u32::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// 简化属性（SIZE|UIDGID|PERMISSIONS|ACMODTIME），用于 READDIR/REALPATH 等批量场景
#[must_use]
pub fn build_attrs(is_dir: bool, size: u64) -> Vec<u8> {
    let mut attrs = Vec::new();
    let flags = SSH_FILEXFER_ATTR_SIZE
        | SSH_FILEXFER_ATTR_UIDGID
        | SSH_FILEXFER_ATTR_PERMISSIONS
        | SSH_FILEXFER_ATTR_ACMODTIME;
    attrs.extend_from_slice(&flags.to_be_bytes());
    attrs.extend_from_slice(&size.to_be_bytes());
    attrs.extend_from_slice(&1000u32.to_be_bytes()); // uid
    attrs.extend_from_slice(&1000u32.to_be_bytes()); // gid
    attrs.extend_from_slice(&attrs_permission(None, is_dir).to_be_bytes());
    let now = unix_time(Ok(SystemTime::now()));
    attrs.extend_from_slice(&now.to_be_bytes()); // atime
    attrs.extend_from_slice(&now.to_be_bytes()); // mtime
    attrs
}

/// 完整属性（含真实时间戳与权限位），用于 STAT/LSTAT/FSTAT
///
/// Windows 下额外携带 `createtime` 扩展属性（旧版行为）。
#[must_use]
pub fn build_attrs_from_metadata(metadata: &std::fs::Metadata, is_dir: bool) -> Vec<u8> {
    let mut attrs = Vec::new();
    // flags 仅在 Windows 分支追加 createtime 扩展时改写
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut flags = SSH_FILEXFER_ATTR_SIZE
        | SSH_FILEXFER_ATTR_UIDGID
        | SSH_FILEXFER_ATTR_PERMISSIONS
        | SSH_FILEXFER_ATTR_ACMODTIME;

    attrs.extend_from_slice(&flags.to_be_bytes());
    attrs.extend_from_slice(&metadata.len().to_be_bytes());
    attrs.extend_from_slice(&1000u32.to_be_bytes()); // uid
    attrs.extend_from_slice(&1000u32.to_be_bytes()); // gid
    attrs.extend_from_slice(&attrs_permission(Some(metadata), is_dir).to_be_bytes());
    attrs.extend_from_slice(&unix_time(metadata.accessed()).to_be_bytes());
    attrs.extend_from_slice(&unix_time(metadata.modified()).to_be_bytes());

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Windows FILETIME（1601 纪元，100ns 单位）→ Unix 秒
        if let Some(ctime) = metadata
            .creation_time()
            .checked_sub(116_444_736_000_000_000)
            .map(|ns100| ns100 / 10_000_000)
            .and_then(|secs| u32::try_from(secs).ok())
        {
            flags |= SSH_FILEXFER_ATTR_EXTENDED;
            attrs[0..4].copy_from_slice(&flags.to_be_bytes());
            attrs.extend_from_slice(&1u32.to_be_bytes());
            let ext_name = "createtime";
            attrs.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
            attrs.extend_from_slice(ext_name.as_bytes());
            attrs.extend_from_slice(&8u32.to_be_bytes());
            attrs.extend_from_slice(&ctime.to_be_bytes());
        }
    }

    attrs
}

/// 判断路径是否在 `home` 之内（Windows 忽略大小写）
#[must_use]
pub fn path_starts_with_home(path: &Path, home: &Path) -> bool {
    crate::path_resolve::path_starts_with_ignore_case(path, home)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 解析 ----

    #[test]
    fn test_parse_u32_u64_big_endian() {
        assert_eq!(parse_u32(&[0x00, 0x00, 0x01, 0x02], 0).unwrap(), 0x0102);
        assert_eq!(
            parse_u64(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05], 0).unwrap(),
            5
        );
    }

    #[test]
    fn test_parse_insufficient_data_errors() {
        assert!(parse_u32(&[0, 0, 0], 0).is_err());
        assert!(parse_u64(&[0; 7], 0).is_err());
        assert!(parse_u32(&[0, 0, 0, 0, 0], 2).is_err());
        assert!(parse_string(&[0, 0, 0, 5, b'a'], 0).is_err());
    }

    #[test]
    fn test_parse_string_with_len() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
        let (s, len) = parse_string_with_len(&buf, 0).unwrap();
        assert_eq!(s, "abc");
        assert_eq!(len, 3);

        // 长度前缀越界
        assert!(parse_string_with_len(&[0xFF; 4], 0).is_err());
    }

    // ---- 构建 ----

    #[test]
    fn test_build_packet_adds_length_prefix() {
        let packet = build_packet(&[1, 2, 3]);
        assert_eq!(packet, vec![0, 0, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn test_build_handle_packet_layout() {
        let packet = build_handle_packet(7, "h1");
        let payload = &packet[4..];
        assert_eq!(payload[0], SSH_FXP_HANDLE);
        assert_eq!(parse_u32(payload, 1).unwrap(), 7);
        assert_eq!(parse_string(payload, 5).unwrap(), "h1");
    }

    #[test]
    fn test_build_data_packet_roundtrip() {
        let packet = build_data_packet(9, b"hello");
        let payload = &packet[4..];
        assert_eq!(payload[0], SSH_FXP_DATA);
        assert_eq!(parse_u32(payload, 1).unwrap(), 9);
        assert_eq!(parse_u32(payload, 5).unwrap(), 5);
        assert_eq!(&payload[9..], b"hello");
    }

    #[test]
    fn test_build_version_packet_extension_layout() {
        let exts = vec![("ext1".to_string(), "val".to_string())];
        let packet = build_version_packet(6, &exts);
        let payload = &packet[4..];
        assert_eq!(payload[0], SSH_FXP_VERSION);
        assert_eq!(parse_u32(payload, 1).unwrap(), 6);
        let (name, name_len) = parse_string_with_len(payload, 5).unwrap();
        assert_eq!(name, "ext1");
        assert_eq!(parse_string(payload, 5 + 4 + name_len).unwrap(), "val");
    }

    // ---- 权限映射 ----

    #[test]
    fn test_attrs_permission_defaults_without_metadata() {
        assert_eq!(attrs_permission(None, true), 0o040_755);
        assert_eq!(attrs_permission(None, false), 0o100_644);
    }

    #[cfg(unix)]
    #[test]
    fn test_attrs_permission_real_mode_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();

        let file_path = dir.path().join("f.txt");
        std::fs::write(&file_path, b"x").unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let meta = std::fs::metadata(&file_path).unwrap();
        assert_eq!(attrs_permission(Some(&meta), false), 0o100_640);

        let sub_path = dir.path().join("sub");
        std::fs::create_dir(&sub_path).unwrap();
        std::fs::set_permissions(&sub_path, std::fs::Permissions::from_mode(0o750)).unwrap();
        let meta = std::fs::metadata(&sub_path).unwrap();
        assert_eq!(attrs_permission(Some(&meta), true), 0o040_750);
    }

    #[test]
    fn test_build_attrs_flags_and_fields() {
        let attrs = build_attrs(true, 123);
        let flags = parse_u32(&attrs, 0).unwrap();
        assert_eq!(
            flags,
            SSH_FILEXFER_ATTR_SIZE
                | SSH_FILEXFER_ATTR_UIDGID
                | SSH_FILEXFER_ATTR_PERMISSIONS
                | SSH_FILEXFER_ATTR_ACMODTIME
        );
        assert_eq!(parse_u64(&attrs, 4).unwrap(), 123);
        // permissions 落在 size(8) + uid(4) + gid(4) 之后
        assert_eq!(parse_u32(&attrs, 20).unwrap(), 0o040_755);
    }

    #[test]
    fn test_build_attrs_from_metadata_flags() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("f.txt");
        std::fs::write(&file_path, b"hello").unwrap();
        let meta = std::fs::metadata(&file_path).unwrap();
        let attrs = build_attrs_from_metadata(&meta, false);
        let flags = parse_u32(&attrs, 0).unwrap();
        assert_eq!(
            flags & (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS),
            SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS
        );
        assert_eq!(parse_u64(&attrs, 4).unwrap(), 5);
    }

    #[test]
    fn test_path_starts_with_home() {
        let home = Path::new("/srv/home");
        assert!(path_starts_with_home(Path::new("/srv/home/x"), home));
        assert!(!path_starts_with_home(Path::new("/srv/other"), home));
    }
}

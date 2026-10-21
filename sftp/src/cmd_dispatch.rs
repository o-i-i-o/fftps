//! SFTP 命令分发
//!
//! 把收到的 SFTP 报文路由到各 ops 处理函数；INIT/VERSION 在此处理，
//! 版本协商后向客户端通告支持的扩展。

use anyhow::Result;

use crate::protocol;
use crate::state::SftpState;
// types 是本 crate 的协议常量/句柄类型聚合模块（等价内部预导入），逐项列举反而降低可读性
#[allow(clippy::wildcard_imports)]
use crate::types::*;

/// 服务器支持的 SFTP 版本上限
pub const MAX_SFTP_VERSION: u32 = 6;

/// INIT 应答中通告的扩展（客户端据此启用 md5sum/sha256sum/copy-file 等能力）
#[must_use]
pub fn supported_extensions() -> Vec<(String, String)> {
    [
        "md5sum@openssh.com",
        "sha256sum@openssh.com",
        "copy-file",
        "hardlink@openssh.com",
        "statvfs@openssh.com",
    ]
    .iter()
    .map(|name| ((*name).to_string(), String::new()))
    .collect()
}

impl SftpState {
    /// 分发单个 SFTP 报文（不含长度前缀），返回应答报文（不含长度前缀）
    ///
    /// # Errors
/// 报文字段解析失败时返回错误（调用方记录日志后断开会话）
    pub async fn dispatch_packet(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "EMPTY_PACKET",
                "SFTP: received empty packet"
            );
            return Ok(vec![]);
        }

        if self.last_handle_cleanup.elapsed() > std::time::Duration::from_secs(300) {
            self.cleanup_expired_handles().await;
            self.last_handle_cleanup = std::time::Instant::now();
        }

        let cmd = data[0];

        match cmd {
            SSH_FXP_INIT => self.handle_init(data),
            SSH_FXP_VERSION => self.handle_version(data),
            SSH_FXP_OPEN => self.handle_open(data).await,
            SSH_FXP_CLOSE => self.handle_close(data).await,
            SSH_FXP_READ => self.handle_read(data).await,
            SSH_FXP_WRITE => self.handle_write(data).await,
            SSH_FXP_LSTAT => self.handle_lstat(data).await,
            SSH_FXP_FSTAT => self.handle_fstat(data).await,
            SSH_FXP_SETSTAT => self.handle_setstat(data).await,
            SSH_FXP_FSETSTAT => self.handle_fsetstat(data).await,
            SSH_FXP_OPENDIR => self.handle_opendir(data),
            SSH_FXP_READDIR => self.handle_readdir(data).await,
            SSH_FXP_REMOVE => self.handle_remove(data).await,
            SSH_FXP_MKDIR => self.handle_mkdir(data).await,
            SSH_FXP_RMDIR => self.handle_rmdir(data).await,
            SSH_FXP_REALPATH => self.handle_realpath(data),
            SSH_FXP_STAT => self.handle_stat(data).await,
            SSH_FXP_RENAME => self.handle_rename(data).await,
            SSH_FXP_READLINK => self.handle_readlink(data).await,
            SSH_FXP_SYMLINK => self.handle_symlink(data),
            SSH_FXP_BLOCK => self.handle_lock(data),
            SSH_FXP_UNBLOCK => self.handle_unlock(data),
            SSH_FXP_EXTENDED => self.handle_extended(data).await,
            _ => {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "UNKNOWN_CMD",
                    cmd,
                    "SFTP: unknown command"
                );
                if data.len() >= 5 {
                    let id = protocol::parse_u32(data, 1)?;
                    Ok(protocol::build_status_packet(
                        id,
                        SSH_FX_OP_UNSUPPORTED,
                        "Unsupported command",
                        "",
                    ))
                } else {
                    Ok(vec![])
                }
            }
        }
    }

    /// `SSH_FXP_INIT`：版本协商（下限 3、上限 [`MAX_SFTP_VERSION`]）并通告扩展
    ///
    /// # Errors
    /// 版本字段缺失时返回错误
    pub fn handle_init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 5 {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "INIT_INVALID",
                "SFTP INIT: packet too short"
            );
            return Ok(protocol::build_version_packet(
                3,
                &supported_extensions(),
            ));
        }

        let client_version = protocol::parse_u32(data, 1)?;

        tracing::info!(
            client_ip = %self.client_ip,
            username = ?self.username,
            action = "INIT",
            client_version,
            "SFTP INIT received"
        );

        if client_version < 3 {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "INIT_VERSION_TOO_LOW",
                client_version,
                "SFTP INIT: client version too low, minimum is 3"
            );
            return Ok(protocol::build_status_packet(
                0,
                SSH_FX_OP_UNSUPPORTED,
                "Protocol version too old, minimum is 3",
                "",
            ));
        }

        let server_version = client_version.min(MAX_SFTP_VERSION);
        self.sftp_version = server_version;

        tracing::info!(
            client_ip = %self.client_ip,
            username = ?self.username,
            action = "INIT_COMPLETE",
            client_version,
            server_version,
            "SFTP version negotiated"
        );

        Ok(protocol::build_version_packet(
            server_version,
            &supported_extensions(),
        ))
    }

    /// `SSH_FXP_VERSION`：客户端主动发来的版本信息（记录后忽略）
    ///
    /// # Errors
    /// 版本字段缺失时返回错误
    pub fn handle_version(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 5 {
            return Ok(vec![]);
        }

        let version = protocol::parse_u32(data, 1)?;
        self.sftp_version = version;

        tracing::info!(
            client_ip = %self.client_ip,
            username = ?self.username,
            action = "VERSION",
            version,
            "SFTP VERSION received"
        );

        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{build_version_packet, parse_string_with_len, parse_u32};

    #[test]
    fn test_supported_extensions_advertised() {
        let exts = supported_extensions();
        let names: Vec<&str> = exts.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"md5sum@openssh.com"));
        assert!(names.contains(&"sha256sum@openssh.com"));
        assert!(names.contains(&"copy-file"));
    }

    #[test]
    fn test_version_packet_carries_extensions() {
        let packet = build_version_packet(3, &supported_extensions());
        // 跳过长度前缀与类型/版本，检查第一个扩展名
        let payload = &packet[4..];
        assert_eq!(payload[0], SSH_FXP_VERSION);
        let (name, _) = parse_string_with_len(payload, 5).unwrap();
        assert_eq!(name, "md5sum@openssh.com");
    }

    #[test]
    fn test_status_packet_layout() {
        let packet = protocol::build_status_packet(1, SSH_FX_OK, "OK", "");
        let payload = &packet[4..];
        assert_eq!(payload[0], SSH_FXP_STATUS);
        assert_eq!(parse_u32(payload, 1).unwrap(), 1);
        assert_eq!(parse_u32(payload, 5).unwrap(), SSH_FX_OK);
    }
}

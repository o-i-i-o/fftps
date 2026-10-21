//! libunftp 事件监听器（迁移自 wftpd-windows `ftp_server/listeners.rs`）
//!
//! - [`FtpDataListener`]：数据事件 → 文件操作审计（[`Logging::write_file_op`]）
//!   + 传输字节指标；
//! - [`FtpPresenceListener`]：登录/登出事件 → 会话 trace 映射、连接数注销、审计。

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use libunftp::notification::{DataEvent, DataListener, EventMeta, PresenceEvent, PresenceListener};

use fftp_common::logging::Logging;
use fftp_common::rate_limit::ConnectionLimiter;

use crate::auth::SessionTracker;

/// 数据事件监听器：文件操作审计 + 传输指标
pub struct FtpDataListener {
    sessions: Arc<SessionTracker>,
    logging: Arc<Logging>,
}

impl fmt::Debug for FtpDataListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 共享层组件（Logging）无 Debug，仅给出类型标识
        f.debug_struct("FtpDataListener").finish_non_exhaustive()
    }
}

impl FtpDataListener {
    /// 创建数据事件监听器
    #[must_use]
    pub fn new(sessions: Arc<SessionTracker>, logging: Arc<Logging>) -> Self {
        FtpDataListener { sessions, logging }
    }

    /// 写一条文件操作审计
    fn audit(&self, meta: &EventMeta, operation: &str, file_path: String, file_size: u64) {
        let client_ip = self
            .sessions
            .get_ip_by_trace(&meta.trace_id)
            .unwrap_or_default();
        self.logging.write_file_op(&fftp_common::FileOpLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            username: meta.username.clone(),
            client_ip,
            operation: operation.to_string(),
            file_path,
            file_size,
            protocol: "FTP".to_string(),
            success: true,
            message: String::new(),
        });
    }
}

#[async_trait]
impl DataListener for FtpDataListener {
    async fn receive_data_event(&self, event: DataEvent, meta: EventMeta) {
        match event {
            DataEvent::Put { path, bytes } => {
                fftp_common::metrics::record_upload_bytes("FTP", bytes);
                self.audit(&meta, "UPLOAD", path, bytes);
            }
            DataEvent::Got { path, bytes } => {
                fftp_common::metrics::record_download_bytes("FTP", bytes);
                self.audit(&meta, "DOWNLOAD", path, bytes);
            }
            DataEvent::Deleted { path } => self.audit(&meta, "DELETE", path, 0),
            DataEvent::MadeDir { path } => self.audit(&meta, "MKDIR", path, 0),
            DataEvent::RemovedDir { path } => self.audit(&meta, "RMDIR", path, 0),
            DataEvent::Renamed { from, to } => {
                self.audit(&meta, "RENAME", format!("{from} -> {to}"), 0);
            }
        }
    }
}

/// 会话事件监听器：会话 trace 映射、连接数注销、会话审计
pub struct FtpPresenceListener {
    sessions: Arc<SessionTracker>,
    connections: Arc<ConnectionLimiter>,
    logging: Arc<Logging>,
}

impl fmt::Debug for FtpPresenceListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 共享层组件（Logging）无 Debug，仅给出类型标识
        f.debug_struct("FtpPresenceListener").finish_non_exhaustive()
    }
}

impl FtpPresenceListener {
    /// 创建会话事件监听器
    #[must_use]
    pub fn new(
        sessions: Arc<SessionTracker>,
        connections: Arc<ConnectionLimiter>,
        logging: Arc<Logging>,
    ) -> Self {
        FtpPresenceListener {
            sessions,
            connections,
            logging,
        }
    }
}

#[async_trait]
impl PresenceListener for FtpPresenceListener {
    async fn receive_presence_event(&self, event: PresenceEvent, meta: EventMeta) {
        match event {
            PresenceEvent::LoggedIn => {
                if let Some(client_ip) = self.sessions.get_ip_for_user(&meta.username) {
                    self.sessions.register_trace(
                        meta.trace_id.to_string(),
                        &meta.username,
                        client_ip,
                    );
                }
                self.logging.write_audit(
                    &meta.username,
                    "SESSION_START",
                    "ftp",
                    &format!("会话 {} 建立", meta.trace_id),
                );
                tracing::info!(
                    username = %meta.username,
                    trace_id = %meta.trace_id,
                    "FTP 会话建立"
                );
            }
            PresenceEvent::LoggedOut => {
                // 匿名/未知会话按 trace 注销，其余按用户名注销
                let client_ip = if self.sessions.get_ip_for_user(&meta.username).is_some() {
                    self.sessions.unregister(&meta.username)
                } else {
                    self.sessions.unregister_by_trace(&meta.trace_id)
                };

                if let Some(ip) = client_ip {
                    self.connections.unregister(&ip);
                    tracing::debug!(ip = %ip, "FTP 连接数登记已注销");
                }
                self.logging.write_audit(
                    &meta.username,
                    "SESSION_END",
                    "ftp",
                    &format!("会话 {} 结束", meta.trace_id),
                );
                tracing::info!(
                    username = %meta.username,
                    trace_id = %meta.trace_id,
                    "FTP 会话结束"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fftp_common::LoggingConfig;

    fn make_tracker() -> Arc<SessionTracker> {
        let tracker = Arc::new(SessionTracker::new());
        tracker.register("alice", "10.0.0.1".to_string());
        tracker.register_trace("t1".to_string(), "alice", "10.0.0.1".to_string());
        tracker
    }

    #[tokio::test]
    async fn test_data_listener_audits_upload() {
        let logging = Arc::new(Logging::new(&LoggingConfig::default()));
        let listener = FtpDataListener::new(make_tracker(), Arc::clone(&logging));

        listener
            .receive_data_event(
                DataEvent::Put {
                    path: "/a.txt".to_string(),
                    bytes: 5,
                },
                EventMeta {
                    username: "alice".to_string(),
                    trace_id: "t1".to_string(),
                    sequence_number: 1,
                },
            )
            .await;

        let entries = logging.file_op_buffer().recent(10);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation, "UPLOAD");
        assert_eq!(entries[0].file_path, "/a.txt");
        assert_eq!(entries[0].file_size, 5);
        assert_eq!(entries[0].client_ip, "10.0.0.1");
        assert_eq!(entries[0].protocol, "FTP");
        assert!(entries[0].success);
    }

    #[tokio::test]
    async fn test_presence_listener_registers_and_unregisters() {
        let logging = Arc::new(Logging::new(&LoggingConfig::default()));
        let sessions = Arc::new(SessionTracker::new());
        let connections = Arc::new(ConnectionLimiter::default());
        let listener = FtpPresenceListener::new(
            Arc::clone(&sessions),
            Arc::clone(&connections),
            Arc::clone(&logging),
        );

        sessions.register("alice", "10.0.0.1".to_string());
        assert!(connections.try_register("10.0.0.1"));

        listener
            .receive_presence_event(
                PresenceEvent::LoggedIn,
                EventMeta {
                    username: "alice".to_string(),
                    trace_id: "t1".to_string(),
                    sequence_number: 1,
                },
            )
            .await;
        assert_eq!(sessions.get_ip_by_trace("t1").as_deref(), Some("10.0.0.1"));

        listener
            .receive_presence_event(
                PresenceEvent::LoggedOut,
                EventMeta {
                    username: "alice".to_string(),
                    trace_id: "t1".to_string(),
                    sequence_number: 2,
                },
            )
            .await;
        assert_eq!(sessions.get_ip_for_user("alice"), None);
        assert_eq!(connections.get_ip_count("10.0.0.1"), 0);
    }
}

//! 应用状态：配置 + 守护进程连接 + 会话存储

use std::sync::Arc;

use fftp_ipc::protocol::Command;

use crate::auth::SessionStore;
use crate::config::HttpConfig;
use crate::daemon::Daemon;

/// 进程级共享状态（`Arc<AppState>` 作为 axum state）
pub struct AppState {
    pub config: Arc<HttpConfig>,
    pub daemon: Daemon,
    pub sessions: SessionStore,
}

impl AppState {
    #[must_use]
    pub fn new(config: HttpConfig, daemon: Daemon) -> Arc<Self> {
        let sessions = SessionStore::new(config.auth.session_ttl_secs);
        Arc::new(Self {
            config: Arc::new(config),
            daemon,
            sessions,
        })
    }

    /// 写审计日志（经 fftpd 落盘；失败仅告警，不影响主流程）
    pub async fn audit(&self, user: &str, action: &str, target: &str, details: &str) {
        let cmd = Command::WriteAuditLog {
            user: user.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            details: details.to_string(),
        };
        if let Err(e) = self.daemon.request(cmd).await {
            tracing::warn!("审计写入失败（action={action} user={user}）: {e}");
        }
    }
}

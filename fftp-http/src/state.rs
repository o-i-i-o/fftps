//! 应用状态：配置 + 守护进程连接 + 会话存储

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use fftp_ipc::protocol::Command;

use crate::auth::SessionStore;
use crate::config::{AdminUser, HttpConfig};
use crate::daemon::Daemon;

/// 进程级共享状态（`Arc<AppState>` 作为 axum state）
pub struct AppState {
    pub config: Arc<HttpConfig>,
    /// fftp-http 自身管理员账户（运行期可变；登录校验以此为准）
    admins: RwLock<Arc<Vec<AdminUser>>>,
    /// fftp-http 自身配置文件路径（管理员变更时回写）
    pub http_config_path: PathBuf,
    pub daemon: Daemon,
    pub sessions: SessionStore,
}

impl AppState {
    #[must_use]
    pub fn new(config: HttpConfig, daemon: Daemon, http_config_path: PathBuf) -> Arc<Self> {
        let sessions = SessionStore::new(config.auth.session_ttl_secs);
        Arc::new(Self {
            admins: RwLock::new(Arc::new(config.admin_users.clone())),
            config: Arc::new(config),
            http_config_path,
            daemon,
            sessions,
        })
    }

    /// 管理员账户快照（无锁等待时间极短，返回共享 Arc）
    #[must_use]
    pub fn admins(&self) -> Arc<Vec<AdminUser>> {
        self.admins
            .read()
            .expect("管理员列表锁中毒")
            .clone()
    }

    /// 替换运行期管理员列表
    pub fn set_admins(&self, users: Vec<AdminUser>) {
        *self
            .admins
            .write()
            .expect("管理员列表锁中毒") = Arc::new(users);
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

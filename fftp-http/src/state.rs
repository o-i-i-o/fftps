//! 应用状态：配置 + 守护进程连接 + 会话存储

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use fftp_ipc::protocol::Command;
use tokio::sync::watch;

use crate::auth::{LoginLimiter, SessionStore};
use crate::config::{AdminUser, HttpConfig};
use crate::daemon::Daemon;
use crate::idle::{IdleState, ShutdownReason};

/// 进程级共享状态（`Arc<AppState>` 作为 axum state）
pub struct AppState {
    pub config: Arc<HttpConfig>,
    /// fftp-http 自身管理员账户（运行期可变；登录校验以此为准）
    admins: RwLock<Arc<Vec<AdminUser>>>,
    /// fftp-http 自身配置文件路径（管理员/空闲设置变更时回写）
    pub http_config_path: PathBuf,
    pub daemon: Daemon,
    pub sessions: SessionStore,
    /// 登录失败限流（按 IP + 用户名）
    pub login_limiter: LoginLimiter,
    /// 空闲自动关闭
    pub idle: Arc<IdleState>,
    shutdown_tx: watch::Sender<Option<ShutdownReason>>,
}

impl AppState {
    #[must_use]
    pub fn new(
        config: HttpConfig,
        daemon: Daemon,
        http_config_path: PathBuf,
    ) -> (Arc<Self>, watch::Receiver<Option<ShutdownReason>>) {
        let sessions = SessionStore::new(config.auth.session_ttl_secs);
        let (shutdown_tx, shutdown_rx) = watch::channel(None);
        let idle = IdleState::new(config.idle.clone(), shutdown_tx.clone());
        let state = Arc::new(Self {
            admins: RwLock::new(Arc::new(config.admin_users.clone())),
            config: Arc::new(config),
            http_config_path,
            daemon,
            sessions,
            login_limiter: LoginLimiter::default(),
            idle,
            shutdown_tx,
        });
        (state, shutdown_rx)
    }

    /// 是否尚未配置管理员（本机 setup 引导模式）
    #[must_use]
    pub fn setup_required(&self) -> bool {
        self.admins().is_empty()
    }

    /// 请求关闭 fftp-http 自身（不关闭 fftpd）
    pub fn request_shutdown(&self, reason: ShutdownReason) {
        let _ = self.shutdown_tx.send(Some(reason));
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

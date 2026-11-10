//! 守护进程共享状态与协议服务生命周期
//!
//! [`AppState`] 汇聚共享层句柄（配置/用户/日志）与运行状态记账；
//! FTP/SFTP 服务实例与运行句柄存活在专用生命周期线程里，经 mpsc 请求驱动：
//! `SftpService::start` 内部的主机密钥生成 future 非 `Send`（russh 持有
//! `ThreadRng` 跨 await），无法在 IPC 分发的 `Send` future 中直接 await，
//! 故生命周期操作统一在该线程的专用运行时内执行，外部只做请求/应答。
//!
//! 配置句柄由 FTP/SFTP 共同持有同一份 `RwLock<Config>`；配额、Fail2Ban、
//! 连接数治理也各只创建一个实例并注入两个协议，使统计口径/封禁状态一致。

use fftp_common::sync::RwLockExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};

use tokio::sync::{mpsc, oneshot, watch};

use fftp_common::config::Config;
use fftp_common::fail2ban::Fail2BanManager;
use fftp_common::logging::Logging;
use fftp_common::quota::QuotaManager;
use fftp_common::rate_limit::ConnectionLimiter;
use fftp_common::users::UserManager;
use fftp_ftp::{FtpService, RunningFtpService};
use fftp_ipc::protocol::ServiceTarget;
use fftp_sftp::{RunningService, SftpService};

/// 服务生命周期请求（生命周期线程内执行，统一返回应答）
enum LifecycleRequest {
    /// 启动（已在运行时幂等成功）
    Start {
        which: ServiceTarget,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// 停止（未运行时幂等成功）
    Stop {
        which: ServiceTarget,
        reply: oneshot::Sender<()>,
    },
    /// 重启：先停后启（未运行时等价于直接启动）
    Restart {
        which: ServiceTarget,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// 配置热重载：只重启在跑的服务，使监听参数变更生效
    Reload {
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// 查询真实运行状态（服务自身标志）并回写状态字段
    Status {
        reply: oneshot::Sender<(bool, bool)>,
    },
}

/// 生命周期请求的应答超时：服务重启卡住时避免后续管理请求无限挂起
const LIFECYCLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// 守护进程共享状态
pub struct AppState {
    /// 统一配置（FTP/SFTP 共享同一句柄）
    pub config: Arc<StdRwLock<Config>>,
    /// 用户库（认证时热加载；`SaveUsers` 后整体替换）
    pub users: Arc<StdMutex<UserManager>>,
    /// 日志设施（环形缓冲 + 文件管理 + 审计写入）
    pub logging: Arc<Logging>,
    /// users.json 路径（`GetUsers`/`SaveUsers` 的落盘位置）
    pub users_path: PathBuf,
    /// FTP 运行状态（生命周期线程记账）
    pub ftp_running: Arc<AtomicBool>,
    /// SFTP 运行状态（同上）
    pub sftp_running: Arc<AtomicBool>,
    lifecycle: mpsc::Sender<LifecycleRequest>,
    shutdown_tx: watch::Sender<bool>,
}

impl AppState {
    /// 组装共享状态：拉起服务生命周期线程（不启动监听）
    #[must_use]
    pub fn new(
        config: Config,
        users: UserManager,
        logging: Arc<Logging>,
        shutdown_tx: watch::Sender<bool>,
    ) -> Arc<Self> {
        let config = Arc::new(StdRwLock::new(config));
        let users = Arc::new(StdMutex::new(users));
        let ftp_running = Arc::new(AtomicBool::new(false));
        let sftp_running = Arc::new(AtomicBool::new(false));

        let lifecycle = spawn_lifecycle_thread(
            Arc::clone(&config),
            Arc::clone(&users),
            Arc::clone(&logging),
            Arc::clone(&ftp_running),
            Arc::clone(&sftp_running),
        );

        Arc::new(Self {
            config,
            users,
            logging,
            users_path: fftp_common::paths::users_path(),
            ftp_running,
            sftp_running,
            lifecycle,
            shutdown_tx,
        })
    }

    /// 请求进程退出（保留 main 的 watch 机制）
    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// 当前配置快照
    #[must_use]
    pub fn current_config(&self) -> Config {
        self.config.read_recover().clone()
    }

    /// 写入新配置（FTP/SFTP 共享同一句柄，一次写入即两侧可见）
    pub fn store_config(&self, config: Config) {
        *self.config.write_recover() = config;
    }

    /// 运行状态（以服务自身标志为准，并回写 `ftp_running`/`sftp_running`）
    ///
    /// 生命周期线程不可用时回退到状态字段
    pub async fn service_status(&self) -> (bool, bool) {
        let (reply, rx) = oneshot::channel();
        if self
            .lifecycle
            .send(LifecycleRequest::Status { reply })
            .await
            .is_ok()
            && let Ok(status) = rx.await
        {
            return status;
        }
        (
            self.ftp_running.load(Ordering::SeqCst),
            self.sftp_running.load(Ordering::SeqCst),
        )
    }

    /// 启动指定服务（已在运行时幂等成功）
    ///
    /// # Errors
    /// 服务组装/监听失败或生命周期线程不可用时返回错误文本；
    /// `which = all` 时逐个尝试，已成功启动的保持运行，错误合并返回
    pub async fn start_service(&self, which: ServiceTarget) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        tokio::time::timeout(LIFECYCLE_TIMEOUT, async {
            self.lifecycle
                .send(LifecycleRequest::Start { which, reply })
                .await
                .map_err(|_| "服务生命周期线程已退出".to_string())?;
            rx.await.map_err(|_| "服务生命周期线程未应答".to_string())?
        })
        .await
        .map_err(|_| "服务生命周期线程响应超时".to_string())?
    }

    /// 停止指定服务（未运行时幂等成功）
    ///
    /// # Errors
    /// 生命周期线程不可用时返回错误文本
    pub async fn stop_service(&self, which: ServiceTarget) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        tokio::time::timeout(LIFECYCLE_TIMEOUT, async {
            self.lifecycle
                .send(LifecycleRequest::Stop { which, reply })
                .await
                .map_err(|_| "服务生命周期线程已退出".to_string())?;
            rx.await.map_err(|_| "服务生命周期线程未应答".to_string())
        })
        .await
        .map_err(|_| "服务生命周期线程响应超时".to_string())?
    }

    /// 重启指定服务：先停后启（未运行时等价于直接启动）
    ///
    /// # Errors
    /// 启动失败或生命周期线程不可用时返回错误文本
    pub async fn restart_service(&self, which: ServiceTarget) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        tokio::time::timeout(LIFECYCLE_TIMEOUT, async {
            self.lifecycle
                .send(LifecycleRequest::Restart { which, reply })
                .await
                .map_err(|_| "服务生命周期线程已退出".to_string())?;
            rx.await.map_err(|_| "服务生命周期线程未应答".to_string())?
        })
        .await
        .map_err(|_| "服务生命周期线程响应超时".to_string())?
    }

    /// 配置热重载：重启在跑的协议服务（`SaveConfig` 落盘后调用）
    ///
    /// # Errors
    /// 生命周期线程不可用，或任一服务按新配置重启失败时返回错误文本
    pub async fn reload_services(&self) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        tokio::time::timeout(LIFECYCLE_TIMEOUT, async {
            self.lifecycle
                .send(LifecycleRequest::Reload { reply })
                .await
                .map_err(|_| "服务生命周期线程已退出".to_string())?;
            rx.await.map_err(|_| "服务生命周期线程未应答".to_string())?
        })
        .await
        .map_err(|_| "服务生命周期线程响应超时".to_string())?
    }

    /// 启动流程：按配置启动启用的协议服务（单个服务失败不致命，仅记 error）
    pub async fn start_enabled_services(&self) {
        let config = self.current_config();
        let which = match (config.ftp.enabled, config.sftp.enabled) {
            (true, true) => Some(ServiceTarget::All),
            (true, false) => Some(ServiceTarget::Ftp),
            (false, true) => Some(ServiceTarget::Sftp),
            (false, false) => None,
        };
        if let Some(which) = which
            && let Err(e) = self.start_service(which).await
        {
            tracing::error!("协议服务启动失败: {e}");
        }
    }

    /// 进程退出前停止全部协议服务
    pub async fn stop_all(&self) {
        if let Err(e) = self.stop_service(ServiceTarget::All).await {
            tracing::warn!("停止协议服务失败: {e}");
        }
    }
}

/// `which = all` 展开为 ftp + sftp 两个目标
fn expand_target(which: ServiceTarget) -> Vec<ServiceTarget> {
    match which {
        ServiceTarget::All => vec![ServiceTarget::Ftp, ServiceTarget::Sftp],
        target => vec![target],
    }
}

/// 生命周期线程内的服务运行时：服务实例 + 运行句柄 + 状态记账
struct ServiceRuntime {
    ftp: FtpService,
    sftp: SftpService,
    ftp_handle: Option<RunningFtpService>,
    sftp_handle: Option<RunningService>,
    ftp_running: Arc<AtomicBool>,
    sftp_running: Arc<AtomicBool>,
}

impl ServiceRuntime {
    fn new(
        config: Arc<StdRwLock<Config>>,
        users: Arc<StdMutex<UserManager>>,
        logging: Arc<Logging>,
        ftp_running: Arc<AtomicBool>,
        sftp_running: Arc<AtomicBool>,
    ) -> Self {
        // 共享治理组件：同一实例注入两种协议，避免各自维护一份连接/封禁/配额状态
        let data_dir = fftp_common::paths::state_dir();
        let security = config.read_recover().security.clone();
        let quota = Arc::new(QuotaManager::new(&data_dir));
        let fail2ban = Arc::new(Fail2BanManager::new(&data_dir, &security));
        let connections = Arc::new(ConnectionLimiter::new(&security));

        let ftp = FtpService::new(
            Arc::clone(&config),
            Arc::clone(&users),
            Arc::clone(&logging),
        )
        .with_quota(Arc::clone(&quota))
        .with_fail2ban(Arc::clone(&fail2ban))
        .with_connection_limiter(Arc::clone(&connections));
        let sftp = SftpService::new(config, users)
            .with_logging(logging)
            .with_quota(quota)
            .with_fail2ban(fail2ban)
            .with_connection_limiter(connections);
        Self {
            ftp,
            sftp,
            ftp_handle: None,
            sftp_handle: None,
            ftp_running,
            sftp_running,
        }
    }

    /// 启动指定服务：逐个尝试，错误合并返回（单个失败不影响另一个）
    async fn start(&mut self, which: ServiceTarget) -> Result<(), String> {
        let mut errors = Vec::new();
        for target in expand_target(which) {
            let result = match target {
                ServiceTarget::Ftp => self.start_ftp().await,
                ServiceTarget::Sftp => self.start_sftp().await,
                ServiceTarget::All => continue,
            };
            if let Err(e) = result {
                tracing::error!("{e}");
                errors.push(e);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// 停止指定服务（未运行时幂等）
    async fn stop(&mut self, which: ServiceTarget) {
        for target in expand_target(which) {
            match target {
                ServiceTarget::Ftp => self.stop_ftp().await,
                ServiceTarget::Sftp => self.stop_sftp().await,
                ServiceTarget::All => {}
            }
        }
    }

    /// 重启指定服务：先停后启
    async fn restart(&mut self, which: ServiceTarget) -> Result<(), String> {
        self.stop(which).await;
        self.start(which).await
    }

    /// 配置热重载：只重启在跑的服务
    async fn reload(&mut self) -> Result<(), String> {
        let (ftp_on, sftp_on) = self.status();
        let mut errors = Vec::new();
        if ftp_on {
            self.stop_ftp().await;
            if let Err(e) = self.start_ftp().await {
                tracing::error!("FTP 服务按新配置重启失败: {e}");
                errors.push(format!("FTP: {e}"));
            }
        }
        if sftp_on {
            self.stop_sftp().await;
            if let Err(e) = self.start_sftp().await {
                tracing::error!("SFTP 服务按新配置重启失败: {e}");
                errors.push(format!("SFTP: {e}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// 真实运行状态（以服务自身标志为准），并回写状态字段
    fn status(&self) -> (bool, bool) {
        let ftp = self.ftp.is_running();
        let sftp = self
            .sftp_handle
            .as_ref()
            .is_some_and(RunningService::is_running);
        self.ftp_running.store(ftp, Ordering::SeqCst);
        self.sftp_running.store(sftp, Ordering::SeqCst);
        (ftp, sftp)
    }

    async fn start_ftp(&mut self) -> Result<(), String> {
        if self
            .ftp_handle
            .as_ref()
            .is_some_and(RunningFtpService::is_running)
        {
            self.ftp_running.store(true, Ordering::SeqCst);
            return Ok(()); // 已在运行：幂等成功
        }
        self.ftp_handle = None; // 清理监听任务已退出的失效句柄

        match self.ftp.start().await {
            Ok(running) => {
                self.ftp_handle = Some(running);
                self.ftp_running.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(e) => {
                self.ftp_running.store(false, Ordering::SeqCst);
                Err(format!("FTP 服务启动失败: {e:#}"))
            }
        }
    }

    async fn start_sftp(&mut self) -> Result<(), String> {
        if self
            .sftp_handle
            .as_ref()
            .is_some_and(RunningService::is_running)
        {
            self.sftp_running.store(true, Ordering::SeqCst);
            return Ok(());
        }
        self.sftp_handle = None;

        match self.sftp.start().await {
            Ok(running) => {
                self.sftp_handle = Some(running);
                self.sftp_running.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(e) => {
                self.sftp_running.store(false, Ordering::SeqCst);
                Err(format!("SFTP 服务启动失败: {e:#}"))
            }
        }
    }

    async fn stop_ftp(&mut self) {
        if let Some(running) = self.ftp_handle.take() {
            running.stop().await;
        }
        self.ftp_running.store(false, Ordering::SeqCst);
    }

    async fn stop_sftp(&mut self) {
        if let Some(running) = self.sftp_handle.take() {
            running.stop().await;
        }
        self.sftp_running.store(false, Ordering::SeqCst);
    }
}

/// 拉起服务生命周期线程：专用 current-thread 运行时驱动非 `Send` 的服务 future
fn spawn_lifecycle_thread(
    config: Arc<StdRwLock<Config>>,
    users: Arc<StdMutex<UserManager>>,
    logging: Arc<Logging>,
    ftp_running: Arc<AtomicBool>,
    sftp_running: Arc<AtomicBool>,
) -> mpsc::Sender<LifecycleRequest> {
    let (tx, mut rx) = mpsc::channel(32);
    std::thread::Builder::new()
        .name("fftpd-services".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("构建服务生命周期运行时失败");
            runtime.block_on(async move {
                let mut services =
                    ServiceRuntime::new(config, users, logging, ftp_running, sftp_running);
                while let Some(req) = rx.recv().await {
                    match req {
                        LifecycleRequest::Start { which, reply } => {
                            let _ = reply.send(services.start(which).await);
                        }
                        LifecycleRequest::Stop { which, reply } => {
                            services.stop(which).await;
                            let _ = reply.send(());
                        }
                        LifecycleRequest::Restart { which, reply } => {
                            let _ = reply.send(services.restart(which).await);
                        }
                        LifecycleRequest::Reload { reply } => {
                            let _ = reply.send(services.reload().await);
                        }
                        LifecycleRequest::Status { reply } => {
                            let _ = reply.send(services.status());
                        }
                    }
                }
                tracing::debug!("服务生命周期线程退出");
            });
        })
        .expect("启动服务生命周期线程失败");
    tx
}

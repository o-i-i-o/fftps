//! SFTP 服务组装与生命周期管理
//!
//! [`SftpService`] 是可长期持有的服务描述（配置/用户库引用 + 可注入的
//! 防护/配额/限速/日志组件），[`RunningService::start`] 启动监听并返回
//! [`RunningService`] 运行句柄（地址查询、优雅停止）。配置变更时可
//! `stop()` 后重新 `start()`。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use russh::MethodKind;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::sync::oneshot;

use fftp_common::config::Config;
use fftp_common::fail2ban::Fail2BanManager;
use fftp_common::logging::Logging;
use fftp_common::quota::QuotaManager;
use fftp_common::rate_limit::ConnectionLimiter;
use fftp_common::users::UserManager;

use crate::handler::{SftpHandler, SessionTracker};
use crate::host_key;

/// SFTP 服务描述（尚未启动）
///
/// 组装方式：[`SftpService::new`] 给出默认组件（配额/`Fail2Ban`/连接数治理
/// 按配置与 `state_dir` 自动创建），可用 `with_*` 注入 fftpd 统一持有的
/// 共享实例（例如与 FTP 共用同一 `Fail2Ban`）。
pub struct SftpService {
    config: Arc<StdMutex<Config>>,
    user_manager: Arc<StdMutex<UserManager>>,
    logging: Option<Arc<Logging>>,
    quota_manager: Arc<QuotaManager>,
    fail2ban: Option<Arc<Fail2BanManager>>,
    connection_limiter: Option<Arc<ConnectionLimiter>>,
    sessions: Arc<SessionTracker>,
}

impl SftpService {
    /// 创建 SFTP 服务描述
    ///
    /// 默认组件：配额管理器（`state_dir` 持久化）、`Fail2Ban`（按
    /// `security.fail2ban_*` 配置）、连接数治理（按 `security.max_connections*`）。
    /// 组件可被 `with_*` 方法替换。
    ///
    /// # Panics
    /// 内部配置互斥锁中毒时 panic（`fftp-common` 语义）
    #[must_use]
    pub fn new(config: Arc<StdMutex<Config>>, user_manager: Arc<StdMutex<UserManager>>) -> Self {
        let (quota_manager, fail2ban, connection_limiter) = {
            let cfg = config.lock().unwrap();
            let data_dir = fftp_common::paths::state_dir();
            let fail2ban = if cfg.security.fail2ban_enabled {
                Some(Arc::new(Fail2BanManager::new(
                    &data_dir,
                    &cfg.security,
                )))
            } else {
                None
            };
            (
                Arc::new(QuotaManager::new(&data_dir)),
                fail2ban,
                Some(Arc::new(ConnectionLimiter::new(&cfg.security))),
            )
        };

        SftpService {
            config,
            user_manager,
            logging: None,
            quota_manager,
            fail2ban,
            connection_limiter,
            sessions: Arc::new(SessionTracker::new()),
        }
    }

    /// 注入文件操作审计日志设施
    #[must_use]
    pub fn with_logging(mut self, logging: Arc<Logging>) -> Self {
        self.logging = Some(logging);
        self
    }

    /// 注入 `Fail2Ban` 管理器（与 fftpd 其他协议共享时使用）
    #[must_use]
    pub fn with_fail2ban(mut self, fail2ban: Arc<Fail2BanManager>) -> Self {
        self.fail2ban = Some(fail2ban);
        self
    }

    /// 注入配额管理器（与 FTP 共享同一份用量统计时使用）
    #[must_use]
    pub fn with_quota(mut self, quota_manager: Arc<QuotaManager>) -> Self {
        self.quota_manager = quota_manager;
        self
    }

    /// 注入连接数治理器（与 FTP 共享全局连接上限时使用）
    #[must_use]
    pub fn with_connection_limiter(mut self, limiter: Arc<ConnectionLimiter>) -> Self {
        self.connection_limiter = Some(limiter);
        self
    }

    /// 启动 SFTP 监听，返回运行句柄
    ///
    /// 流程：校验配置 → 主机密钥轮换检查 → 加载/生成 Ed25519 主机密钥 →
    /// 双栈监听（`SO_REUSEADDR`，IPv6 可同时接受 v4）→ spawn accept 循环。
    /// accept 循环内依次做 `Fail2Ban` 封禁检查、IP 黑白名单、连接数治理，
    /// 然后为每个连接 spawn 一个 `russh::server::run_stream` 会话任务。
    ///
    /// # Errors
    /// 配置校验失败、主机密钥处理失败、地址非法或监听失败时返回错误
    ///
    /// # Panics
    /// 内部配置互斥锁中毒时 panic（`fftp-common` 语义）
    // 启动流程（配置读取 → 密钥 → 监听 → accept 循环）单函数内联，拆分会割裂生命周期管理
    #[allow(clippy::too_many_lines)]
    pub async fn start(&self) -> Result<RunningService> {
        let (
            bind_ip,
            sftp_port,
            host_key_path,
            key_rotation_days,
            max_auth_attempts,
            auth_timeout,
            max_sessions_per_user,
            allow_symlinks,
        ) = {
            let cfg = self.config.lock().unwrap();
            cfg.validate()?;
            (
                cfg.sftp.bind_ip.clone(),
                cfg.sftp.port,
                cfg.sftp.resolved_host_key_path(),
                cfg.sftp.host_key_rotation_days,
                cfg.sftp.max_auth_attempts,
                cfg.sftp.auth_timeout,
                cfg.sftp.max_sessions_per_user,
                cfg.security.allow_symlinks,
            )
        };

        tracing::info!("SFTP server starting on {bind_ip}:{sftp_port}");

        // 主机密钥：按周期轮换 + 不存在时自动生成 Ed25519
        let mut last_rotation: Option<DateTime<Utc>> = None;
        host_key::check_and_rotate_key(&host_key_path, key_rotation_days, &mut last_rotation)
            .await?;
        let host_key = host_key::load_or_generate_host_key(&host_key_path).await?;

        let mut methods = russh::MethodSet::empty();
        methods.push(MethodKind::Password);
        methods.push(MethodKind::PublicKey);

        let ssh_config = russh::server::Config {
            keys: vec![host_key],
            methods,
            max_auth_attempts: usize::try_from(max_auth_attempts)?,
            auth_rejection_time: std::time::Duration::from_secs(1),
            auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
            inactivity_timeout: Some(std::time::Duration::from_secs(auth_timeout)),
            keepalive_interval: Some(std::time::Duration::from_secs(30)),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        };
        let ssh_config = Arc::new(ssh_config);

        let listener = bind_listener(&bind_ip, sftp_port)?;
        let local_addr = listener.local_addr()?;
        tracing::info!("SFTP server started on {local_addr}");

        // Fail2Ban 后台清理任务
        if let Some(fb) = &self.fail2ban {
            Arc::clone(fb).start_cleanup_task();
        }

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let (stopped_tx, stopped_rx) = oneshot::channel::<()>();
        let running = Arc::new(AtomicBool::new(true));

        let user_manager = Arc::clone(&self.user_manager);
        let quota_manager = Arc::clone(&self.quota_manager);
        let fail2ban = self.fail2ban.clone();
        let connection_limiter = self.connection_limiter.clone();
        let logging = self.logging.clone();
        let sessions = Arc::clone(&self.sessions);
        let config = Arc::clone(&self.config);
        let running_flag = Arc::clone(&running);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        tracing::info!("SFTP server shutdown signal received");
                        break;
                    }
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((socket, peer_addr)) => {
                                let client_ip = peer_addr.ip().to_string();

                                // Fail2Ban 封禁检查
                                if let Some(fb) = &fail2ban
                                    && fb.is_banned(&client_ip).await
                                {
                                    tracing::warn!(
                                        "SFTP connection rejected from {client_ip}: \
                                         IP is banned by Fail2Ban"
                                    );
                                    fftp_common::metrics::record_connection_rejected();
                                    continue;
                                }

                                // IP 黑白名单
                                let ip_allowed = {
                                    let cfg = config.lock().unwrap();
                                    cfg.is_ip_allowed(&client_ip)
                                };
                                if !ip_allowed {
                                    tracing::warn!(
                                        "SFTP connection rejected from {client_ip}: \
                                         IP not allowed by blacklist/whitelist"
                                    );
                                    fftp_common::metrics::record_connection_rejected();
                                    continue;
                                }

                                // 连接数治理（全局 + 每 IP）
                                if let Some(limiter) = &connection_limiter
                                    && !limiter.try_register(&client_ip)
                                {
                                    tracing::warn!(
                                        "SFTP connection rejected from {client_ip}: \
                                         connection limit exceeded"
                                    );
                                    fftp_common::metrics::record_connection_rejected();
                                    continue;
                                }

                                tracing::info!(
                                    client_ip = %client_ip,
                                    action = "CONNECT",
                                    protocol = "SFTP",
                                    "Client connected from {client_ip}"
                                );

                                let ssh_config = Arc::clone(&ssh_config);
                                let user_manager = Arc::clone(&user_manager);
                                let quota_manager = Arc::clone(&quota_manager);
                                let fail2ban = fail2ban.clone();
                                let connection_limiter = connection_limiter.clone();
                                let logging = logging.clone();
                                let sessions = Arc::clone(&sessions);

                                tokio::spawn(async move {
                                    // 连接结束时归还连接数配额
                                    let limiter_guard = connection_limiter.clone();
                                    let cleanup_ip = client_ip.clone();
                                    let _guard = scopeguard::guard((), move |()| {
                                        if let Some(limiter) = &limiter_guard {
                                            limiter.unregister(&cleanup_ip);
                                        }
                                    });

                                    let handler = SftpHandler::new(
                                        user_manager,
                                        quota_manager,
                                        fail2ban,
                                        sessions,
                                        logging,
                                        client_ip,
                                        max_auth_attempts,
                                        auth_timeout,
                                        max_sessions_per_user,
                                        allow_symlinks,
                                    );

                                    if let Err(e) =
                                        russh::server::run_stream(ssh_config, socket, handler).await
                                    {
                                        tracing::error!(
                                            "SSH connection error from {peer_addr}: {e}"
                                        );
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("Failed to accept connection: {e}");
                            }
                        }
                    }
                }
            }

            running_flag.store(false, Ordering::SeqCst);
            let _ = stopped_tx.send(());
        });

        Ok(RunningService {
            addr: local_addr,
            running,
            shutdown_tx: Some(shutdown_tx),
            stopped_rx: Some(stopped_rx),
        })
    }
}

/// 双栈 TCP 监听：IPv6 监听同时接受 IPv4（`IPV6_V6ONLY=false`）
fn bind_listener(bind_ip: &str, port: u16) -> Result<tokio::net::TcpListener> {
    let domain = if bind_ip == "::" || (bind_ip.starts_with('[') && bind_ip.ends_with(']')) {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    if domain == Domain::IPV6 {
        socket.set_only_v6(false)?;
    }

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let addr: SocketAddr = format!("{bind_ip}:{port}")
        .parse()
        .map_err(|e| anyhow!("Invalid bind address '{bind_ip}:{port}': {e}"))?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(128)?;
    tokio::net::TcpListener::from_std(socket.into())
        .map_err(|e| anyhow!("Failed to create tokio listener: {e}"))
}

/// 运行中的 SFTP 服务句柄
///
/// 由 [`SftpService::start`] 返回；配置变更场景：`stop()` 后用同一
/// [`SftpService`]（或新配置）再次 `start()`。
pub struct RunningService {
    addr: SocketAddr,
    running: Arc<AtomicBool>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    stopped_rx: Option<oneshot::Receiver<()>>,
}

impl RunningService {
    /// 实际监听地址（含端口，便于 `port = 0` 时回读）
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// 服务是否仍在运行
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 优雅停止：通知 accept 循环退出并等待其收尾
    ///
    /// 已建立的连接会继续服务直至客户端断开（新连接不再被接受）。
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take()
            && tx.send(()).is_err()
        {
            tracing::warn!("SFTP shutdown signal receiver already dropped");
        }
        if let Some(rx) = self.stopped_rx.take() {
            let _ = rx.await;
        }
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("SFTP server stopped");
    }
}

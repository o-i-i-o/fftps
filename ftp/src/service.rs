//! FTP(FTPS) 服务组装与生命周期管理
//!
//! 迁移整合自 wftpd-windows `ftp_server/unftp.rs`（libunftp builder 组装）与
//! wftpd-linux `ftp/src/server.rs`（生命周期形态），对接统一共享层
//! （[`fftp_common`] 的配置/用户/配额/限速/防护/指标/审计）。
//!
//! 对外暴露两个类型：
//! - [`FtpService`]：持有共享层资源，[`FtpService::start`] 组装 libunftp 服务端
//!   并返回运行句柄；
//! - [`RunningFtpService`]：运行句柄，[`RunningFtpService::stop`] 优雅停止
//!   （drop 句柄同样触发停止）。
//!
//! 存储栈（docs/design.md §4 Windows 组装路线）：
//!
//! ```text
//! RestrictingVfs<JailFilesystem<RooterVfs<Filesystem, FtpUser, Meta>>, FtpUser, Meta>
//! ```
//!
//! 热重载兼容：配置/用户更新后调用 `stop()` 再 `start()`，即以新配置快照重建服务；
//! 同一 [`FtpService`] 实例只允许一个运行中的服务（重复 `start` 会被拒绝）。

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use libunftp::ServerBuilder;
use libunftp::options::{
    ActivePassiveMode, FailedLoginsBlock, FailedLoginsPolicy, PassiveHost, Shutdown,
};
use tokio::sync::oneshot;
use unftp_sbe_fs::{Filesystem, Meta};
use unftp_sbe_restrict::RestrictingVfs;
use unftp_sbe_rooter::RooterVfs;

use fftp_common::fail2ban::Fail2BanManager;
use fftp_common::logging::Logging;
use fftp_common::rate_limit::ConnectionLimiter;
use fftp_common::{Config, ConnectionMode, FtpsConfig, QuotaManager, UserManager};

use crate::auth::{FtpAuthenticator, FtpUser, FtpUserDetailProvider, RootMode, SessionTracker};
use crate::cert_gen::ensure_cert_exists;
use crate::listeners::{FtpDataListener, FtpPresenceListener};
use crate::passive_mode::format_listen_addresses;
use crate::storage::JailFilesystem;

/// 组装完成的存储栈类型（libunftp `StorageBackend` 实现）
pub type FtpStorage =
    RestrictingVfs<JailFilesystem<RooterVfs<Filesystem, FtpUser, Meta>>, FtpUser, Meta>;

/// 优雅停止时给在线会话的宽限时间（秒）
const SHUTDOWN_GRACE_SECS: u64 = 5;

/// `stop()` 等待监听任务退出的上限（秒）
const STOP_WAIT_SECS: u64 = 10;

/// 解析存储根模式：配置了 `ftp_root` 为共享根，未配置则按用户 home 隔离
///
/// 共享根必须已存在（启动即校验，快速失败）。
///
/// # Errors
/// `ftp_root` 不存在/不可访问，或 homes 模式无法解析卷根时返回错误
pub fn resolve_root_mode(ftp_root: Option<&str>) -> Result<RootMode> {
    match ftp_root {
        Some(root) => {
            let base = std::fs::canonicalize(root)
                .with_context(|| format!("FTP 根目录不存在或不可访问: {root}"))?;
            Ok(RootMode::Shared { base })
        }
        None => Ok(RootMode::Homes {
            base: homes_base()?,
        }),
    }
}

/// 解析 homes 模式的存储根（卷根）：Unix 为 `/`，Windows 为盘符根
///
/// 各用户 home 相对卷根做会话根，跨卷 home 会在会话建立时报错
/// （见 [`RootMode::session_root`]）。
///
/// # Errors
/// 无法从当前用户主目录解析出卷根（Windows）时返回错误
pub fn homes_base() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        Ok(PathBuf::from("/"))
    }
    #[cfg(windows)]
    {
        // 取 home 的 Prefix + RootDir（如 `C:\Users\x` → `C:\`）作为共存卷根
        use std::path::Component;
        let home = fftp_common::paths::home_dir();
        let base: PathBuf = home
            .components()
            .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
            .collect();
        if base.as_os_str().is_empty() {
            bail!("无法从主目录 {} 解析卷根", home.display());
        }
        Ok(base)
    }
}

/// 解析 FTPS 证书对 `(cert_path, key_path)`；`None` 表示未启用 FTPS
///
/// - 未启用：`None`；
/// - 证书/私钥均留空：自动生成到 `state_dir/certs/ftps-cert.pem` +
///   `ftps-key.pem`（rcgen 自签，缺失时补齐）；
/// - 证书/私钥均设置：沿用用户配置的路径（不自动生成，文件缺失在组装时快速失败）；
/// - 只设置一半：报错。
///
/// # Errors
/// 证书/私钥只配置一半，或自动生成失败时返回错误
pub fn resolve_ftps_paths(ftps: &FtpsConfig) -> Result<Option<(PathBuf, PathBuf)>> {
    if !ftps.enabled {
        return Ok(None);
    }
    match (ftps.cert_path_opt(), ftps.key_path_opt()) {
        (Some(cert), Some(key)) => Ok(Some((PathBuf::from(cert), PathBuf::from(key)))),
        (None, None) => {
            let cert_dir = fftp_common::paths::state_dir().join("certs");
            let cert = cert_dir.join("ftps-cert.pem");
            let key = cert_dir.join("ftps-key.pem");
            ensure_cert_exists(
                cert.to_str().context("证书路径包含非 UTF-8 字符")?,
                key.to_str().context("私钥路径包含非 UTF-8 字符")?,
            )?;
            Ok(Some((cert, key)))
        }
        _ => bail!("FTPS 已启用，但 cert_path 与 key_path 必须同时设置或同时留空"),
    }
}

/// 被动模式通告地址：IP 字面量 → [`PassiveHost::Ip`]，非空主机名 → `Dns`，
/// 空/未指定地址 → `FromConnection`（跟随实际连接地址）
#[must_use]
pub fn resolve_passive_host(masquerade_address: Option<&str>) -> PassiveHost {
    match masquerade_address {
        Some(addr) => match addr.parse::<Ipv4Addr>() {
            Ok(ip) if !ip.is_unspecified() => PassiveHost::Ip(ip),
            Ok(_) => PassiveHost::FromConnection,
            Err(_) => PassiveHost::Dns(addr.to_string()),
        },
        None => PassiveHost::FromConnection,
    }
}

/// 配置连接模式 → libunftp 主动/被动模式
#[must_use]
pub fn map_connection_mode(mode: ConnectionMode) -> ActivePassiveMode {
    match mode {
        ConnectionMode::PassiveOnly => ActivePassiveMode::PassiveOnly,
        ConnectionMode::ActiveOnly => ActivePassiveMode::ActiveOnly,
        ConnectionMode::ActiveAndPassive => ActivePassiveMode::ActiveAndPassive,
    }
}

/// FTP(FTPS) 服务：持有共享层资源，负责组装与生命周期管理
///
/// 由 fftpd 在启动时构造一个实例；配置/用户热重载时 `stop()` 后重新 `start()`
/// 即可（配置在 `start()` 时快照，用户库在每次认证时热加载）。
pub struct FtpService {
    config: Arc<StdRwLock<Config>>,
    users: Arc<StdMutex<UserManager>>,
    logging: Arc<Logging>,
    quota: Arc<QuotaManager>,
    fail2ban: Arc<Fail2BanManager>,
    connections: Arc<ConnectionLimiter>,
    sessions: Arc<SessionTracker>,
    /// 是否有服务在运行（与 [`RunningFtpService`] 共享）
    running: Arc<AtomicBool>,
    /// fail2ban 清理任务是否已启动（每实例一次，避免热重载堆积任务）
    cleanup_started: AtomicBool,
}

impl FtpService {
    /// 创建 FTP 服务（不启动监听）
    ///
    /// - `config`：统一配置（热重载后重新 `start()` 生效）；
    /// - `users`：用户库（认证时按 `users.json` 热加载）；
    /// - `logging`：审计/文件操作日志写入口。
    ///
    /// 配额、fail2ban 的持久化数据存于 [`fftp_common::paths::state_dir`]。
    ///
    /// # Panics
    /// 共享配置锁被毒化时 panic（内部约定不跨锁持有 panic）
    #[must_use]
    pub fn new(
        config: Arc<StdRwLock<Config>>,
        users: Arc<StdMutex<UserManager>>,
        logging: Arc<Logging>,
    ) -> Self {
        let data_dir = fftp_common::paths::state_dir();
        let security = config.read().unwrap().security.clone();
        FtpService {
            quota: Arc::new(QuotaManager::new(&data_dir)),
            fail2ban: Arc::new(Fail2BanManager::new(&data_dir, &security)),
            connections: Arc::new(ConnectionLimiter::new(&security)),
            sessions: Arc::new(SessionTracker::new()),
            config,
            users,
            logging,
            running: Arc::new(AtomicBool::new(false)),
            cleanup_started: AtomicBool::new(false),
        }
    }

    /// 当前是否有服务在运行
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 启动 FTP(FTPS) 服务：组装 libunftp 并在后台任务中开始监听
    ///
    /// 返回 [`RunningFtpService`] 运行句柄；句柄 `stop()` 优雅停止，
    /// 直接 drop 同样触发停止。重复启动（前一实例未停止）会被拒绝。
    ///
    /// greeting 文本经 `Box::leak` 提升为 `&'static str`（libunftp 接口要求），
    /// 每次 `start()` 泄漏一次欢迎语内存（量级为字节，可接受）。
    ///
    /// # Errors
    /// 配置非法（根目录不存在、FTPS 证书配置不一致/生成失败）、libunftp
    /// 组装失败时返回错误；监听绑定失败在后台任务中记录日志并使
    /// [`FtpService::is_running`] 归于 `false`。
    pub async fn start(&self) -> Result<RunningFtpService> {
        if self.is_running() {
            bail!("FTP 服务已在运行，请先 stop() 再重新 start()");
        }

        // 配置快照：后续组装不跨 await 持锁，热重载在下次 start() 生效
        let cfg = self.config.read().unwrap().clone();

        let root_mode = resolve_root_mode(cfg.ftp.ftp_root_opt())?;
        let ftps_paths = resolve_ftps_paths(&cfg.ftp.ftps)?;

        if !self.cleanup_started.swap(true, Ordering::SeqCst) {
            Arc::clone(&self.fail2ban).start_cleanup_task();
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (closed_tx, closed_rx) = oneshot::channel();

        let bind_addr = format!("{}:{}", cfg.ftp.bind_ip, cfg.ftp.port);
        tracing::info!(
            "FTP 服务启动：监听 {}（连接模式 {}）",
            format_listen_addresses(&cfg.ftp.bind_ip, cfg.ftp.port),
            cfg.ftp.connection_mode.as_str()
        );

        if cfg.ftp.pooled_listener_mode {
            // 上游缺陷（libunftp 0.23.1）：池化模式把被动监听器交给分离的 accept 任务，
            // stop() 只取消监听循环，不关闭这些任务持有的端口，运行期 restart 会绑定失败
            tracing::warn!(
                "已启用池化被动监听模式（pooled_listener_mode）：libunftp 停止后不会释放被动端口，\
                 运行期 restart 将失败，需重启 fftpd 进程恢复；建议保持默认关闭"
            );
        }

        let server = self.assemble_server(&cfg, root_mode, ftps_paths, shutdown_rx)?;
        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            if let Err(e) = server.listen(bind_addr).await {
                tracing::error!("FTP 监听任务异常退出: {e}");
            }
            running.store(false, Ordering::SeqCst);
            let _ = closed_tx.send(());
        });

        Ok(RunningFtpService {
            shutdown_tx: Some(shutdown_tx),
            closed_rx,
            running: Arc::clone(&self.running),
        })
    }

    /// 组装 libunftp `Server`（存储栈 + 认证链 + 监听器 + FTPS）
    fn assemble_server(
        &self,
        cfg: &Config,
        root_mode: RootMode,
        ftps_paths: Option<(PathBuf, PathBuf)>,
        shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<libunftp::Server<FtpStorage, FtpUser>> {
        let base_root = root_mode.base().to_path_buf();
        let quota = Arc::clone(&self.quota);
        let config = Arc::clone(&self.config);
        let storage_factory: Box<dyn Fn() -> FtpStorage + Send + Sync> = Box::new(move || {
            // 存储根已在 start() 校验存在；运行期被删除属于无法安全回退的场景，
            // 直接 panic 终止该会话（不能回退到其它目录，等同越狱）
            let fs = Filesystem::new(&base_root)
                .expect("存储根已在启动时校验，打开失败说明运行期目录被移除");
            let rooter = RooterVfs::<Filesystem, FtpUser, Meta>::new(fs);
            let jailed = JailFilesystem::new(
                rooter,
                base_root.clone(),
                Arc::clone(&quota),
                Arc::clone(&config),
            );
            RestrictingVfs::<_, FtpUser, Meta>::new(jailed)
        });

        let authenticator = Arc::new(FtpAuthenticator::new(
            Arc::clone(&self.users),
            Arc::clone(&self.config),
            Arc::clone(&self.fail2ban),
            Arc::clone(&self.connections),
            Arc::clone(&self.sessions),
            Arc::clone(&self.logging),
        ));

        let user_detail_provider = Arc::new(FtpUserDetailProvider::new(
            Arc::clone(&self.users),
            Arc::clone(&self.config),
            root_mode,
        ));

        // libunftp 的 greeting 要求 &'static str；每次 start() 泄漏一次欢迎语
        let greeting: &'static str = Box::leak(cfg.ftp.welcome_message.clone().into_boxed_str());

        // 停止信号：stop() 发送后进入优雅停止（宽限 SHUTDOWN_GRACE_SECS）
        let shutdown_indicator = async move {
            let _ = shutdown_rx.await;
            tracing::info!("FTP 服务收到停止信号，开始优雅停止");
            Shutdown::new().grace_period(Duration::from_secs(SHUTDOWN_GRACE_SECS))
        };

        let mut builder = ServerBuilder::with_user_detail_provider(
            storage_factory,
            user_detail_provider,
        )
        .authenticator(authenticator)
        .greeting(greeting)
        .passive_ports(cfg.ftp.passive_ports.0..=cfg.ftp.passive_ports.1)
        .idle_session_timeout(cfg.ftp.idle_timeout)
        .notify_data(FtpDataListener::new(
            Arc::clone(&self.sessions),
            Arc::clone(&self.logging),
        ))
        .notify_presence(FtpPresenceListener::new(
            Arc::clone(&self.sessions),
            Arc::clone(&self.connections),
            Arc::clone(&self.logging),
        ))
        // libunftp 内建的连续登录失败惩罚与共享层 fail2ban 叠加生效
        .failed_logins_policy(FailedLoginsPolicy::new(
            cfg.security.max_login_attempts,
            Duration::from_secs(cfg.security.fail2ban_ban_time),
            FailedLoginsBlock::UserAndIP,
        ))
        .shutdown_indicator(shutdown_indicator);

        if cfg.ftp.pooled_listener_mode {
            builder = builder.pooled_listener_mode();
        }

        builder = builder.active_passive_mode(map_connection_mode(cfg.ftp.connection_mode));
        builder = builder.passive_host(resolve_passive_host(cfg.ftp.masquerade_address_opt()));

        if let Some((cert, key)) = ftps_paths {
            builder = builder
                .ftps(cert, key)
                .ftps_required(cfg.ftp.ftps.require_ssl, cfg.ftp.ftps.require_ssl);
            tracing::info!("FTPS 已启用（require_ssl: {}）", cfg.ftp.ftps.require_ssl);
        }

        builder.build().context("组装 libunftp 服务端失败")
    }
}

/// FTP 服务运行句柄：监听生命周期与优雅停止
///
/// 由 [`FtpService::start`] 返回；`stop()` 后可用同一 [`FtpService`]
/// 重新 `start()`（配置/用户热重载流程）。
pub struct RunningFtpService {
    shutdown_tx: Option<oneshot::Sender<()>>,
    closed_rx: oneshot::Receiver<()>,
    running: Arc<AtomicBool>,
}

impl RunningFtpService {
    /// 服务是否仍在运行（监听任务未退出）
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 优雅停止：通知监听任务退出并等待其结束（上限 [`STOP_WAIT_SECS`] 秒）
    ///
    /// 宽限期见 [`SHUTDOWN_GRACE_SECS`]。句柄被直接 drop 时同样触发停止
    /// （停止信号发送方被关闭，监听任务按优雅停止处理）。
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        match tokio::time::timeout(Duration::from_secs(STOP_WAIT_SECS), &mut self.closed_rx).await {
            Ok(Ok(())) => tracing::info!("FTP 服务已优雅停止"),
            Ok(Err(_)) => tracing::warn!("FTP 监听任务已提前退出"),
            Err(_) => tracing::warn!("等待 FTP 监听任务退出超时（{STOP_WAIT_SECS}s）"),
        }
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::path::{Component, Path};

    use tokio::net::{TcpListener, TcpStream};

    use fftp_common::{LoggingConfig, Permissions};
    use unftp_core::auth::{Authenticator, ChannelEncryptionState, Credentials, UserDetailProvider};

    use crate::test_support::ENV_LOCK;

    /// 在临时状态目录下构造测试用服务（持有 ENV_LOCK 后调用）
    fn make_service(cfg: Config) -> FtpService {
        FtpService::new(
            Arc::new(StdRwLock::new(cfg)),
            Arc::new(StdMutex::new(UserManager::new())),
            Arc::new(Logging::new(&LoggingConfig::default())),
        )
    }

    fn test_config() -> Config {
        let mut cfg = Config::default();
        cfg.ftp.bind_ip = "127.0.0.1".to_string();
        cfg.ftp.port = 0;
        // libunftp 0.23.1 池化模式停止时不释放被动端口，测试显式走 legacy 模式
        cfg.ftp.pooled_listener_mode = false;
        cfg
    }

    #[test]
    fn new_service_is_not_running() {
        let _guard = ENV_LOCK.lock().unwrap();
        let state = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("FFTPD_STATE_DIR", state.path()) };
        assert!(!make_service(test_config()).is_running());
    }

    #[tokio::test]
    async fn start_stop_lifecycle() {
        let _guard = ENV_LOCK.lock().unwrap();
        let state = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("FFTPD_STATE_DIR", state.path()) };

        let service = make_service(test_config());
        let running = service.start().await.unwrap();
        assert!(service.is_running());
        assert!(running.is_running());

        running.stop().await;
        assert!(!service.is_running());
        // 热重载形态：停止后可再次启动
        let running = service.start().await.unwrap();
        running.stop().await;
        assert!(!service.is_running());
    }

    #[tokio::test]
    async fn stop_is_safe_when_listener_exits_early() {
        let _guard = ENV_LOCK.lock().unwrap();
        let state = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("FFTPD_STATE_DIR", state.path()) };

        // 绑定不可用地址（TEST-NET-3，本机无此地址）→ 监听任务启动即失败退出
        let mut cfg = test_config();
        cfg.ftp.bind_ip = "203.0.113.250".to_string();
        let service = make_service(cfg);

        let running = service.start().await.unwrap();
        // 监听任务已退出时 stop() 为安全空操作
        running.stop().await;
        assert!(!service.is_running());
    }

    #[test]
    fn resolve_root_mode_shared_and_homes() {
        let dir = tempfile::tempdir().unwrap();
        let mode = resolve_root_mode(Some(dir.path().to_str().unwrap())).unwrap();
        match mode {
            RootMode::Shared { base } => {
                assert_eq!(base, dir.path().canonicalize().unwrap());
            }
            RootMode::Homes { .. } => panic!("应解析为共享根模式"),
        }

        let mode = resolve_root_mode(None).unwrap();
        match mode {
            RootMode::Homes { base } => {
                // 卷根：仅由 Prefix + RootDir 构成
                assert!(base
                    .components()
                    .all(|c| matches!(c, Component::Prefix(_) | Component::RootDir)));
                #[cfg(unix)]
                assert_eq!(base, PathBuf::from("/"));
            }
            RootMode::Shared { .. } => panic!("应解析为 homes 模式"),
        }

        assert!(resolve_root_mode(Some("/no-such-ftp-root-12345")).is_err());
    }

    #[test]
    fn resolve_ftps_paths_variants() {
        // 未启用 → None
        assert!(resolve_ftps_paths(&FtpsConfig::default()).unwrap().is_none());

        // 双设置 → 沿用
        let ftps = FtpsConfig {
            enabled: true,
            require_ssl: false,
            cert_path: "/etc/fftps/cert.pem".to_string(),
            key_path: "/etc/fftps/key.pem".to_string(),
        };
        let (cert, key) = resolve_ftps_paths(&ftps).unwrap().unwrap();
        assert_eq!(cert, PathBuf::from("/etc/fftps/cert.pem"));
        assert_eq!(key, PathBuf::from("/etc/fftps/key.pem"));

        // 只设置一半 → 报错
        let half = FtpsConfig {
            enabled: true,
            require_ssl: false,
            cert_path: "/etc/fftps/cert.pem".to_string(),
            key_path: String::new(),
        };
        assert!(resolve_ftps_paths(&half).is_err());

        // 双空 → 自动生成到 state_dir/certs（需临时状态目录隔离）
        let _guard = ENV_LOCK.lock().unwrap();
        let state = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("FFTPD_STATE_DIR", state.path()) };
        let auto = FtpsConfig {
            enabled: true,
            ..FtpsConfig::default()
        };
        let (cert, key) = resolve_ftps_paths(&auto).unwrap().unwrap();
        assert_eq!(cert, state.path().join("certs").join("ftps-cert.pem"));
        assert_eq!(key, state.path().join("certs").join("ftps-key.pem"));
        assert!(cert.is_file() && key.is_file());
    }

    #[test]
    fn resolve_passive_host_variants() {
        assert_eq!(
            resolve_passive_host(None),
            PassiveHost::FromConnection
        );
        assert_eq!(
            resolve_passive_host(Some("0.0.0.0")),
            PassiveHost::FromConnection
        );
        assert_eq!(
            resolve_passive_host(Some("192.0.2.10")),
            PassiveHost::Ip(Ipv4Addr::new(192, 0, 2, 10))
        );
        assert_eq!(
            resolve_passive_host(Some("ftp.example.com")),
            PassiveHost::Dns("ftp.example.com".to_string())
        );
    }

    #[test]
    fn map_connection_mode_variants() {
        assert_eq!(
            map_connection_mode(ConnectionMode::PassiveOnly),
            ActivePassiveMode::PassiveOnly
        );
        assert_eq!(
            map_connection_mode(ConnectionMode::ActiveOnly),
            ActivePassiveMode::ActiveOnly
        );
        assert_eq!(
            map_connection_mode(ConnectionMode::ActiveAndPassive),
            ActivePassiveMode::ActiveAndPassive
        );
    }

    /// 认证链测试：合法用户成功/口令错误/未知用户/匿名开关
    #[tokio::test]
    async fn authenticate_chain() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("FFTPD_CONFIG_DIR", dir.path());
            std::env::set_var("FFTPD_STATE_DIR", dir.path());
        };

        let home = dir.path().join("home").join("alice");
        std::fs::create_dir_all(&home).unwrap();

        let mut users = UserManager::new();
        users
            .add_user(
                "alice".to_string(),
                "secret-pw",
                home.to_string_lossy().into_owned(),
                Permissions::full(),
                false,
            )
            .unwrap();
        users.save(&fftp_common::paths::users_path()).unwrap();

        let mut cfg = Config::default();
        cfg.security.allowed_ips = vec!["0.0.0.0/0".to_string()];
        let config = Arc::new(StdRwLock::new(cfg));
        let security = config.read().unwrap().security.clone();

        let auth = FtpAuthenticator::new(
            Arc::new(StdMutex::new(users)),
            Arc::clone(&config),
            Arc::new(Fail2BanManager::new(&dir.path().join("state"), &security)),
            Arc::new(ConnectionLimiter::new(&security)),
            Arc::new(SessionTracker::new()),
            Arc::new(Logging::new(&LoggingConfig::default())),
        );

        let creds = |password: &str| Credentials {
            password: Some(password.to_string()),
            certificate_chain: None,
            source_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            command_channel_security: ChannelEncryptionState::Plaintext,
        };

        // 合法用户 + 正确口令
        let principal = auth.authenticate("alice", &creds("secret-pw")).await.unwrap();
        assert_eq!(principal.username, "alice");

        // 合法用户 + 错误口令
        let err = auth.authenticate("alice", &creds("wrong-pw")).await.unwrap_err();
        assert!(matches!(
            err,
            unftp_core::auth::AuthenticationError::BadPassword
        ));

        // 未知用户（哑校验恒定时间后失败）
        let err = auth.authenticate("mallory", &creds("any")).await.unwrap_err();
        assert!(matches!(
            err,
            unftp_core::auth::AuthenticationError::BadPassword
        ));

        // 非法用户名直接拒绝
        let err = auth.authenticate("bad user", &creds("x")).await.unwrap_err();
        assert!(matches!(
            err,
            unftp_core::auth::AuthenticationError::BadPassword
        ));

        // 匿名登录未开启
        let err = auth.authenticate("anonymous", &creds("")).await.unwrap_err();
        assert!(matches!(
            err,
            unftp_core::auth::AuthenticationError::BadPassword
        ));

        // 开启匿名并配置匿名目录 → 成功
        let anon_home = dir.path().join("anon");
        std::fs::create_dir_all(&anon_home).unwrap();
        {
            let mut cfg = config.write().unwrap();
            cfg.ftp.allow_anonymous = true;
            cfg.ftp.anonymous_home = anon_home.to_string_lossy().into_owned();
        }
        let principal = auth.authenticate("ftp", &creds("")).await.unwrap();
        assert_eq!(principal.username, "anonymous");
    }

    /// IP 黑名单拦截测试
    #[tokio::test]
    async fn authenticate_rejects_denied_ip() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("FFTPD_CONFIG_DIR", dir.path());
            std::env::set_var("FFTPD_STATE_DIR", dir.path());
        };

        let mut cfg = Config::default();
        cfg.security.denied_ips = vec!["127.0.0.0/8".to_string()];
        let config = Arc::new(StdRwLock::new(cfg));
        let security = config.read().unwrap().security.clone();

        let auth = FtpAuthenticator::new(
            Arc::new(StdMutex::new(UserManager::new())),
            Arc::clone(&config),
            Arc::new(Fail2BanManager::new(&dir.path().join("state"), &security)),
            Arc::new(ConnectionLimiter::new(&security)),
            Arc::new(SessionTracker::new()),
            Arc::new(Logging::new(&LoggingConfig::default())),
        );

        let creds = Credentials {
            password: Some("x".to_string()),
            certificate_chain: None,
            source_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            command_channel_security: ChannelEncryptionState::Plaintext,
        };
        let err = auth.authenticate("alice", &creds).await.unwrap_err();
        assert!(matches!(
            err,
            unftp_core::auth::AuthenticationError::IpDisallowed
        ));
    }

    /// 用户详情提供者：共享根下所有用户会话根为 `.`
    #[tokio::test]
    async fn user_detail_provider_shared_root() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("FFTPD_CONFIG_DIR", dir.path());
            std::env::set_var("FFTPD_STATE_DIR", dir.path());
        };

        let home = dir.path().join("home").join("bob");
        std::fs::create_dir_all(&home).unwrap();

        let mut users = UserManager::new();
        users
            .add_user(
                "bob".to_string(),
                "pw",
                home.to_string_lossy().into_owned(),
                Permissions {
                    can_read: true,
                    can_list: true,
                    ..Permissions::default()
                },
                false,
            )
            .unwrap();
        users.save(&fftp_common::paths::users_path()).unwrap();

        let provider = FtpUserDetailProvider::new(
            Arc::new(StdMutex::new(users)),
            Arc::new(StdRwLock::new(Config::default())),
            RootMode::Shared {
                base: dir.path().canonicalize().unwrap(),
            },
        );

        let principal = unftp_core::auth::Principal {
            username: "bob".to_string(),
        };
        let user = provider.provide_user_detail(&principal).await.unwrap();
        assert_eq!(user.username, "bob");
        assert_eq!(user.session_root(), Path::new("."));
        assert!(user.permissions.can_read && user.permissions.can_list);
    }

    // ---------- 迁移自 wftpd-windows unftp.rs：TCP 目的地址行为回归 ----------

    #[tokio::test]
    async fn test_tcp_local_addr_returns_destination_ip() {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server_port = server_addr.port();

        let server_handle = tokio::spawn(async move {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            let local_addr = stream.local_addr().unwrap();
            (local_addr, peer_addr)
        });

        let client_stream = TcpStream::connect(format!("127.0.0.1:{server_port}"))
            .await
            .unwrap();
        let client_local = client_stream.local_addr().unwrap();

        let (server_local, server_peer) = server_handle.await.unwrap();

        // 服务端 local_addr 是客户端连接的目的地址（127.0.0.1），而非监听地址
        assert_eq!(
            server_local.ip(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "server local_addr should be the destination IP client connected to (127.0.0.1)"
        );
        assert_eq!(server_local.port(), server_port);
        assert_eq!(server_peer, client_local);
    }

    #[tokio::test]
    async fn test_tcp_local_addr_with_specific_bind() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.local_addr().unwrap()
        });

        TcpStream::connect(format!("127.0.0.1:{server_port}"))
            .await
            .unwrap();

        let server_local = server_handle.await.unwrap();

        // 绑定具体 IP 时 local_addr 即该 IP
        assert_eq!(
            server_local.ip(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "When bound to specific IP, local_addr should return that IP"
        );
    }

    #[tokio::test]
    async fn test_tcp_multiple_connections_same_port() {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();

        let server_handle = tokio::spawn(async move {
            let mut results = Vec::new();
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.unwrap();
                let local = stream.local_addr().unwrap();
                results.push(local.ip());
            }
            results
        });

        for _ in 0..3 {
            TcpStream::connect(format!("127.0.0.1:{server_port}"))
                .await
                .unwrap();
        }

        let results = server_handle.await.unwrap();

        // 多连接共享同一端口，local_addr 均为实际目的地址
        for ip in &results {
            assert_eq!(*ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        }
    }
}

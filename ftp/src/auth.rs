//! libunftp 认证/用户适配层
//!
//! 迁移并整合自 wftpd-windows `ftp_server/auth.rs`（认证链、会话跟踪、权限映射）
//! 与 wftpd-linux `ftp/src/auth.rs`（匿名登录），对接统一共享层：
//! - [`fftp_common::users::UserManager`]：用户库与口令校验（登录前 reload 热更新）；
//! - [`fftp_common::config::Config`]：IP 黑白名单、匿名开关、FTP 根目录；
//! - [`fftp_common::fail2ban::Fail2BanManager`]：失败统计与封禁；
//! - [`fftp_common::rate_limit::ConnectionLimiter`]：并发连接数治理；
//! - [`fftp_common::metrics`] / [`fftp_common::logging::Logging`]：指标与审计。
//!
//! 认证链顺序：用户名合法性 → IP 黑白名单 → fail2ban 封禁 → 连接数登记 →
//! 匿名分支 / 用户名口令校验；成功登记会话并清零失败计数，失败注销连接登记、
//! 累计失败并写审计。

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};

use async_trait::async_trait;
use unftp_core::auth::{
    AuthenticationError, Authenticator, Credentials, Principal, UserDetail, UserDetailError,
    UserDetailProvider,
};
use unftp_sbe_restrict::{UserWithPermissions, VfsOperations};
use unftp_sbe_rooter::UserWithRoot;

use fftp_common::fail2ban::Fail2BanManager;
use fftp_common::logging::Logging;
use fftp_common::rate_limit::ConnectionLimiter;
use fftp_common::users::is_safe_username;
use fftp_common::{Config, Permissions, UserManager};

use crate::path_safety::{path_starts_with_ignore_case, paths_equal_ignore_case};

/// 匿名登录用户名（FTP 惯例两个别名）
pub fn is_anonymous_name(username: &str) -> bool {
    username.eq_ignore_ascii_case("anonymous") || username.eq_ignore_ascii_case("ftp")
}

/// 会话根解析模式（docs/design.md §4 存储组装）
#[derive(Debug, Clone)]
pub enum RootMode {
    /// 配置了 `ftp_root`：所有用户共享同一存储根，会话根为 `.`
    Shared { base: PathBuf },
    /// 未配置：各用户 home 相对同一卷根（Unix `/`、Windows 盘符根）隔离
    Homes { base: PathBuf },
}

impl RootMode {
    /// 取存储根（unftp-sbe-fs 的 `Filesystem::new` 参数）
    #[must_use]
    pub fn base(&self) -> &Path {
        match self {
            RootMode::Shared { base } | RootMode::Homes { base } => base,
        }
    }

    /// 计算用户会话根：相对存储根的路径，`.` 表示存储根自身
    ///
    /// 注意不能返回空路径——`unftp-sbe-rooter` 对空 `user_root` 存在长度下溢
    /// panic，故 home 与 base 重合时返回 `"."`。
    ///
    /// # Errors
    /// home 不存在、与 base 不同卷（Windows）或不在 base 之下时返回描述信息
    pub fn session_root(&self, home: &Path) -> Result<PathBuf, String> {
        let RootMode::Shared { .. } = self else {
            let home_canon = home
                .canonicalize()
                .map_err(|e| format!("主目录不存在或不可访问: {} ({e})", home.display()))?;
            let base = self.base();
            if paths_equal_ignore_case(&home_canon, base) {
                return Ok(PathBuf::from("."));
            }
            if !path_starts_with_ignore_case(&home_canon, base) {
                return Err(format!(
                    "主目录 {} 与存储根 {} 不在同一卷，无法共存单存储实例",
                    home_canon.display(),
                    base.display()
                ));
            }
            let relative = home_canon
                .strip_prefix(base)
                .map_err(|e| format!("主目录相对存储根解析失败: {e}"))?;
            let joined = relative
                .components()
                .filter_map(|c| match c {
                    std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/");
            return Ok(if joined.is_empty() {
                PathBuf::from(".")
            } else {
                PathBuf::from(joined)
            });
        };
        Ok(PathBuf::from("."))
    }
}

/// 会话跟踪：用户名 → 连接 IP 列表、trace_id → IP/用户名 反查
///
/// libunftp 的 [`unftp_core`] 事件元数据只有 `trace_id`，审计与连接数注销需要
/// 由登录时登记的映射反查客户端 IP。
#[derive(Debug, Default)]
pub struct SessionTracker {
    sessions: StdMutex<HashMap<String, Vec<String>>>,
    trace_to_ip: StdMutex<HashMap<String, String>>,
    trace_to_username: StdMutex<HashMap<String, String>>,
}

impl SessionTracker {
    /// 创建空的会话跟踪器
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一次认证成功（同用户多连接按先后入栈）
    pub fn register(&self, username: &str, client_ip: String) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions
            .entry(username.to_string())
            .or_default()
            .push(client_ip);
    }

    /// 取用户最近一次登记的连接 IP
    #[must_use]
    pub fn get_ip_for_user(&self, username: &str) -> Option<String> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(username).and_then(|ips| ips.last().cloned())
    }

    /// 登记会话 trace_id 与 IP/用户名 的映射（登录事件回调时建立）
    pub fn register_trace(&self, trace_id: String, username: &str, client_ip: String) {
        self.trace_to_ip
            .lock()
            .unwrap()
            .insert(trace_id.clone(), client_ip);
        self.trace_to_username
            .lock()
            .unwrap()
            .insert(trace_id, username.to_string());
    }

    /// 注销用户最早登记的一次连接，返回其 IP
    #[must_use]
    pub fn unregister(&self, username: &str) -> Option<String> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(ips) = sessions.get_mut(username)
            && !ips.is_empty()
        {
            let ip = ips.remove(0);
            if ips.is_empty() {
                sessions.remove(username);
            }
            return Some(ip);
        }
        None
    }

    /// 按 trace_id 注销会话并同步清理用户名映射，返回其 IP
    #[must_use]
    pub fn unregister_by_trace(&self, trace_id: &str) -> Option<String> {
        let client_ip = self.trace_to_ip.lock().unwrap().remove(trace_id);
        let username = self.trace_to_username.lock().unwrap().remove(trace_id);
        if let (Some(ip), Some(user)) = (&client_ip, &username) {
            let mut sessions = self.sessions.lock().unwrap();
            if let Some(ips) = sessions.get_mut(user)
                && let Some(pos) = ips.iter().position(|x| x == ip)
            {
                ips.remove(pos);
                if ips.is_empty() {
                    sessions.remove(user);
                }
            }
        }
        client_ip
    }

    /// 按 trace_id 反查客户端 IP
    #[must_use]
    pub fn get_ip_by_trace(&self, trace_id: &str) -> Option<String> {
        self.trace_to_ip.lock().unwrap().get(trace_id).cloned()
    }
}

/// FTP 会话用户（libunftp `UserDetail` + rooter/restrict 扩展）
#[derive(Debug, Clone)]
pub struct FtpUser {
    /// 用户名（匿名登录时为 `anonymous`）
    pub username: String,
    /// 用户主目录（绝对路径，展示与配额统计用）
    pub home_dir: PathBuf,
    /// 会话根（相对存储根，unftp-sbe-rooter 语义；`.` 表示存储根自身）
    session_root: PathBuf,
    /// 账号是否启用
    pub enabled: bool,
    /// 权限位集合（含配额 `quota_mb` 与限速 `speed_limit_kbps`）
    pub permissions: Permissions,
}

impl FtpUser {
    /// 构造会话用户
    #[must_use]
    pub fn new(
        username: String,
        home_dir: PathBuf,
        session_root: PathBuf,
        enabled: bool,
        permissions: Permissions,
    ) -> Self {
        FtpUser {
            username,
            home_dir,
            session_root,
            enabled,
            permissions,
        }
    }

    /// 会话根（相对存储根）
    #[must_use]
    pub fn session_root(&self) -> &Path {
        &self.session_root
    }
}

impl PartialEq for FtpUser {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username
    }
}

impl Eq for FtpUser {}

impl fmt::Display for FtpUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "User(username: {:?}, home: {:?})",
            self.username, self.home_dir
        )
    }
}

impl UserDetail for FtpUser {
    fn account_enabled(&self) -> bool {
        self.enabled
    }

    fn home(&self) -> Option<&Path> {
        Some(&self.home_dir)
    }
}

impl UserWithRoot for FtpUser {
    fn user_root(&self) -> Option<PathBuf> {
        Some(self.session_root.clone())
    }
}

impl UserWithPermissions for FtpUser {
    fn permissions(&self) -> VfsOperations {
        let mut ops = VfsOperations::empty();

        if self.permissions.can_read {
            ops |= VfsOperations::GET;
        }
        if self.permissions.can_write || self.permissions.can_append {
            ops |= VfsOperations::PUT;
        }
        if self.permissions.can_delete {
            ops |= VfsOperations::DEL;
        }
        if self.permissions.can_list {
            ops |= VfsOperations::LIST;
        }
        if self.permissions.can_mkdir {
            ops |= VfsOperations::MK_DIR;
        }
        if self.permissions.can_rmdir {
            ops |= VfsOperations::RM_DIR;
        }
        if self.permissions.can_rename {
            ops |= VfsOperations::RENAME;
        }

        tracing::debug!(
            username = %self.username,
            permissions = ?ops,
            "用户权限映射为 VfsOperations"
        );

        ops
    }
}

/// libunftp `Authenticator` 适配：完整认证链（见模块文档）
pub struct FtpAuthenticator {
    users: Arc<StdMutex<UserManager>>,
    config: Arc<StdRwLock<Config>>,
    fail2ban: Arc<Fail2BanManager>,
    connections: Arc<ConnectionLimiter>,
    sessions: Arc<SessionTracker>,
    logging: Arc<Logging>,
    /// 未知用户恒定时间校验用的哑哈希
    dummy_hash: String,
}

impl fmt::Debug for FtpAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 共享层组件（Logging/Fail2BanManager）无 Debug，仅给出类型标识
        f.debug_struct("FtpAuthenticator").finish_non_exhaustive()
    }
}

impl FtpAuthenticator {
    /// 构造认证器
    #[must_use]
    pub fn new(
        users: Arc<StdMutex<UserManager>>,
        config: Arc<StdRwLock<Config>>,
        fail2ban: Arc<Fail2BanManager>,
        connections: Arc<ConnectionLimiter>,
        sessions: Arc<SessionTracker>,
        logging: Arc<Logging>,
    ) -> Self {
        FtpAuthenticator {
            users,
            config,
            fail2ban,
            connections,
            sessions,
            logging,
            dummy_hash: generate_dummy_hash(),
        }
    }

    /// 认证失败统一处理：注销连接登记、累计失败、写指标与审计
    async fn reject(&self, username: &str, client_ip: &str, reason: &str) -> AuthenticationError {
        self.connections.unregister(client_ip);
        self.fail2ban.add_failure(client_ip).await;
        fftp_common::metrics::record_auth_failure();
        self.logging.write_audit(
            username,
            "AUTH_FAIL",
            "ftp",
            &format!("{reason} (from {client_ip})"),
        );
        tracing::warn!(username, ip = client_ip, "FTP 认证失败: {reason}");
        AuthenticationError::BadPassword
    }

    /// 认证成功统一处理：登记会话、清零失败计数、写指标与审计
    async fn accept(&self, username: &str, client_ip: &str) -> Principal {
        self.sessions.register(username, client_ip.to_string());
        self.fail2ban.reset_failures(client_ip).await;
        fftp_common::metrics::record_auth_success();
        self.logging.write_audit(
            username,
            "LOGIN",
            "ftp",
            &format!("登录成功 (from {client_ip})"),
        );
        tracing::info!(username, ip = client_ip, "FTP 用户登录成功");
        Principal {
            username: username.to_string(),
        }
    }
}

/// 生成哑哈希：未知用户也走一次 Argon2id 校验，抹平存在性时间侧信道
fn generate_dummy_hash() -> String {
    use argon2::password_hash::PasswordHasher;
    use argon2::{Argon2, Params};

    let params = Params::new(65536, 3, 4, Some(32)).unwrap_or_default();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password(b"dummy_password_for_constant_time_verification")
        .map(|h| h.to_string())
        .unwrap_or_else(|_| {
            "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        })
}

/// 对哑哈希执行一次等价校验（结果必然失败）
fn dummy_verify(password: &str, dummy_hash: &str) {
    use argon2::password_hash::{PasswordVerifier, phc::PasswordHash};
    use argon2::Argon2;

    if let Ok(parsed) = PasswordHash::new(dummy_hash) {
        let _ = Argon2::default().verify_password(password.as_bytes(), &parsed);
    }
}

#[async_trait]
impl Authenticator for FtpAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        creds: &Credentials,
    ) -> Result<Principal, AuthenticationError> {
        let client_ip = creds.source_ip.to_string();

        // 1. 用户名合法性（认证前拦截非法输入）
        if !is_safe_username(username) {
            return Err(self
                .reject(username, &client_ip, "用户名不合法")
                .await);
        }

        // 2. IP 黑白名单（黑名单优先，见 Config::is_ip_allowed_for）
        {
            let cfg = self.config.read().unwrap();
            if !Config::is_ip_allowed_for(
                &cfg.security.allowed_ips,
                &cfg.security.denied_ips,
                &client_ip,
            ) {
                fftp_common::metrics::record_connection_rejected();
                self.logging.write_audit(
                    username,
                    "IP_BLOCKED",
                    "ftp",
                    &format!("IP 被安全策略拒绝 (from {client_ip})"),
                );
                tracing::warn!(ip = %client_ip, "FTP 连接被 IP 策略拒绝");
                return Err(AuthenticationError::IpDisallowed);
            }
        }

        // 3. fail2ban 封禁
        if self.fail2ban.is_banned(&client_ip).await {
            fftp_common::metrics::record_connection_rejected();
            tracing::warn!(ip = %client_ip, "FTP 连接来自被封禁 IP");
            return Err(AuthenticationError::IpDisallowed);
        }

        // 4. 并发连接数登记（注销在失败分支 / 登出事件中完成）
        if !self.connections.try_register(&client_ip) {
            fftp_common::metrics::record_connection_rejected();
            tracing::warn!(ip = %client_ip, "FTP 并发连接数超限");
            return Err(AuthenticationError::IpDisallowed);
        }

        // 5a. 匿名分支（先在同步作用域内完成校验，锁不可跨 await 持有）
        if is_anonymous_name(username) {
            let denied = {
                let cfg = self.config.read().unwrap();
                if !cfg.ftp.allow_anonymous {
                    Some("匿名登录未开启".to_string())
                } else {
                    match cfg.ftp.anonymous_home_opt() {
                        Some(home) => UserManager::validate_anonymous_home(home)
                            .err()
                            .map(|e| format!("匿名目录非法: {e}")),
                        None => Some("未配置匿名目录".to_string()),
                    }
                }
            };
            if let Some(reason) = denied {
                return Err(self.reject(username, &client_ip, &reason).await);
            }
            return Ok(self.accept("anonymous", &client_ip).await);
        }

        // 5b. 名义用户：口令校验（登录前 reload users.json，支持外部热更新）
        let Some(password) = creds.password.as_deref() else {
            return Err(self.reject(username, &client_ip, "缺少口令").await);
        };

        let known = {
            let mut users = self.users.lock().unwrap();
            if let Err(e) = users.reload(&fftp_common::paths::users_path()) {
                tracing::warn!("重新加载用户库失败: {e}");
            }
            match users.get_user(username) {
                Some(_) => users
                    .authenticate(username, password)
                    .unwrap_or_else(|e| {
                        tracing::error!("口令校验异常: {e}");
                        false
                    }),
                None => {
                    // 未知用户：等价耗时的哑校验后按失败处理
                    dummy_verify(password, &self.dummy_hash);
                    false
                }
            }
        };

        if known {
            Ok(self.accept(username, &client_ip).await)
        } else {
            Err(self.reject(username, &client_ip, "用户名或口令错误").await)
        }
    }

    fn name(&self) -> &str {
        "FtpAuthenticator"
    }
}

/// libunftp `UserDetailProvider` 适配：`Principal` → [`FtpUser`]
#[derive(Debug)]
pub struct FtpUserDetailProvider {
    users: Arc<StdMutex<UserManager>>,
    config: Arc<StdRwLock<Config>>,
    root_mode: RootMode,
}

impl FtpUserDetailProvider {
    /// 构造用户详情提供者
    #[must_use]
    pub fn new(
        users: Arc<StdMutex<UserManager>>,
        config: Arc<StdRwLock<Config>>,
        root_mode: RootMode,
    ) -> Self {
        FtpUserDetailProvider {
            users,
            config,
            root_mode,
        }
    }
}

#[async_trait]
impl UserDetailProvider for FtpUserDetailProvider {
    type User = FtpUser;

    async fn provide_user_detail(&self, principal: &Principal) -> Result<FtpUser, UserDetailError> {
        let username = principal.username.as_str();

        // 匿名用户：只读权限，home 取配置的匿名目录
        if is_anonymous_name(username) {
            let cfg = self.config.read().unwrap();
            let home = cfg
                .ftp
                .anonymous_home_opt()
                .ok_or_else(|| UserDetailError::Generic("未配置匿名目录".to_string()))?;
            let home_path = PathBuf::from(home);
            let session_root = self
                .root_mode
                .session_root(&home_path)
                .map_err(UserDetailError::Generic)?;
            return Ok(FtpUser::new(
                "anonymous".to_string(),
                home_path,
                session_root,
                true,
                // 安全加固：匿名仅开放读取与列目录（不默认给写权限）
                Permissions {
                    can_read: true,
                    can_list: true,
                    ..Permissions::default()
                },
            ));
        }

        let user = {
            let mut users = self.users.lock().unwrap();
            if let Err(e) = users.reload(&fftp_common::paths::users_path()) {
                tracing::warn!("重新加载用户库失败: {e}");
            }
            users.get_user(username).cloned()
        };

        match user {
            Some(u) => {
                let home_path = PathBuf::from(&u.home_dir);
                let session_root = self
                    .root_mode
                    .session_root(&home_path)
                    .map_err(UserDetailError::Generic)?;
                Ok(FtpUser::new(
                    u.username,
                    home_path,
                    session_root,
                    u.enabled,
                    u.permissions,
                ))
            }
            None => Err(UserDetailError::UserNotFound {
                username: username.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn create_test_user() -> FtpUser {
        FtpUser::new(
            "testuser".to_string(),
            PathBuf::from("/home/testuser"),
            PathBuf::from("home/testuser"),
            true,
            Permissions::full(),
        )
    }

    #[test]
    fn test_ftp_user_display_and_debug() {
        let user = create_test_user();
        assert!(format!("{user}").contains("testuser"));
        assert!(format!("{user:?}").contains("testuser"));
    }

    #[test]
    fn test_user_detail_account_enabled_and_home() {
        let mut user = create_test_user();
        assert!(user.account_enabled());
        assert_eq!(user.home(), Some(Path::new("/home/testuser")));
        user.enabled = false;
        assert!(!user.account_enabled());
    }

    #[test]
    fn test_user_with_root() {
        let user = create_test_user();
        assert_eq!(user.user_root(), Some(PathBuf::from("home/testuser")));
        assert_eq!(user.session_root(), Path::new("home/testuser"));
    }

    #[test]
    fn test_user_with_permissions_full() {
        let perms = create_test_user().permissions();
        assert!(perms.contains(VfsOperations::GET));
        assert!(perms.contains(VfsOperations::PUT));
        assert!(perms.contains(VfsOperations::DEL));
        assert!(perms.contains(VfsOperations::LIST));
        assert!(perms.contains(VfsOperations::MK_DIR));
        assert!(perms.contains(VfsOperations::RM_DIR));
        assert!(perms.contains(VfsOperations::RENAME));
    }

    #[test]
    fn test_user_with_permissions_partial() {
        let mut user = create_test_user();
        user.permissions = Permissions {
            can_read: true,
            can_list: true,
            ..Permissions::default()
        };

        let perms = user.permissions();
        assert!(perms.contains(VfsOperations::GET));
        assert!(perms.contains(VfsOperations::LIST));
        assert!(!perms.contains(VfsOperations::PUT));
        assert!(!perms.contains(VfsOperations::DEL));
    }

    #[test]
    fn test_user_with_permissions_empty() {
        let mut user = create_test_user();
        user.permissions = Permissions::default();
        assert_eq!(user.permissions(), VfsOperations::empty());
    }

    #[test]
    fn test_permissions_mapping_append_maps_to_put() {
        let mut user = create_test_user();
        user.permissions = Permissions {
            can_append: true,
            ..Permissions::default()
        };
        assert!(user.permissions().contains(VfsOperations::PUT));
    }

    #[test]
    fn test_session_tracker_lifecycle() {
        let tracker = SessionTracker::new();
        tracker.register("alice", "10.0.0.1".to_string());
        tracker.register("alice", "10.0.0.2".to_string());
        assert_eq!(tracker.get_ip_for_user("alice").as_deref(), Some("10.0.0.2"));

        tracker.register_trace("t1".to_string(), "alice", "10.0.0.1".to_string());
        assert_eq!(tracker.get_ip_by_trace("t1").as_deref(), Some("10.0.0.1"));

        // 先进先出注销
        assert_eq!(tracker.unregister("alice").as_deref(), Some("10.0.0.1"));
        assert_eq!(tracker.unregister("alice").as_deref(), Some("10.0.0.2"));
        assert_eq!(tracker.unregister("alice"), None);
    }

    #[test]
    fn test_session_tracker_unregister_by_trace() {
        let tracker = SessionTracker::new();
        tracker.register("bob", "10.0.0.9".to_string());
        tracker.register_trace("t2".to_string(), "bob", "10.0.0.9".to_string());

        assert_eq!(
            tracker.unregister_by_trace("t2").as_deref(),
            Some("10.0.0.9")
        );
        assert_eq!(tracker.get_ip_for_user("bob"), None);
        assert_eq!(tracker.get_ip_by_trace("t2"), None);
    }

    #[test]
    fn test_is_anonymous_name() {
        assert!(is_anonymous_name("anonymous"));
        assert!(is_anonymous_name("ANONYMOUS"));
        assert!(is_anonymous_name("ftp"));
        assert!(!is_anonymous_name("alice"));
    }

    #[test]
    fn test_dummy_hash_verify_always_fails() {
        let hash = generate_dummy_hash();
        assert!(hash.starts_with("$argon2id$"));
        dummy_verify("any-password", &hash);
        dummy_verify("", &hash);
    }

    #[test]
    fn test_root_mode_shared_session_root() {
        let mode = RootMode::Shared {
            base: PathBuf::from("/srv/ftp"),
        };
        assert_eq!(mode.base(), Path::new("/srv/ftp"));
        assert_eq!(
            mode.session_root(Path::new("/any/home")).unwrap(),
            PathBuf::from(".")
        );
    }

    #[test]
    fn test_root_mode_homes_session_root() {
        let base_dir = tempfile::tempdir().unwrap();
        let home = base_dir.path().join("users").join("bob");
        std::fs::create_dir_all(&home).unwrap();

        let mode = RootMode::Homes {
            base: base_dir.path().canonicalize().unwrap(),
        };
        let session_root = mode.session_root(&home).unwrap();
        // 统一用 `/` 拼接（两种平台的路径解析均接受）
        assert_eq!(session_root, PathBuf::from("users/bob"));

        // home 与 base 重合 → "."（规避 rooter 空路径下溢）
        assert_eq!(
            mode.session_root(base_dir.path()).unwrap(),
            PathBuf::from(".")
        );

        // home 不存在 → 报错
        assert!(mode.session_root(Path::new("/no-such-home-12345")).is_err());
    }

    #[test]
    fn test_root_mode_homes_rejects_other_root() {
        // base 与 home 都存在但不在同一前缀下
        let base_dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let mode = RootMode::Homes {
            base: base_dir.path().canonicalize().unwrap(),
        };
        assert!(mode.session_root(other.path()).is_err());
    }

    #[test]
    fn test_ip_class_regression_in_auth() {
        // 旧 auth 测试中的 IP 分类回归（迁移保留）
        use crate::ip_utils::{IpAddressClass, classify_ip_address};
        assert_eq!(
            classify_ip_address(&std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            IpAddressClass::Loopback
        );
        assert_eq!(
            classify_ip_address(&std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)),
            IpAddressClass::Loopback
        );
    }
}

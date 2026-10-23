//! SFTP SSH 会话处理器（`russh::server::Handler`）
//!
//! 负责认证（口令 / 公钥）与 SFTP 子系统通道接入。
//! 认证对接 `fftp-common` 的 [`UserManager`]（口令校验 + 用户名安全检查），
//! 公钥认证读取 `keys_dir()/<user>/authorized_keys`；失败计数接 Fail2Ban，指标接 prometheus。
//! SFTP 报文循环由 [`run_with_config`] 移交给 [`Session`]。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};

use russh::keys::PublicKey;
use russh::server::Msg;
use russh::{Channel, ChannelId, server};

use fftp_common::fail2ban::Fail2BanManager;
use fftp_common::logging::Logging;
use fftp_common::quota::QuotaManager;
use fftp_common::users::{UserManager, is_safe_username};

use crate::protocol::{self, run_with_config};
use crate::session::Session;
use crate::state::SftpState;

/// 每用户并发会话计数（`max_sessions_per_user` 上限治理）
#[derive(Default)]
pub struct SessionTracker {
    active_sessions: StdMutex<HashMap<String, Arc<AtomicU32>>>,
}

impl SessionTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 会话建立（认证成功后调用）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic（`fftp-common` 语义）
    pub fn increment(&self, username: &str) {
        let mut sessions = self.active_sessions.lock().unwrap();
        let counter = sessions
            .entry(username.to_string())
            .or_insert_with(|| Arc::new(AtomicU32::new(0)));
        let new_count = counter.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::debug!("User {username} session count: {new_count}");
    }

    /// 会话结束（Handler Drop 时调用），归零后移除条目
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic（`fftp-common` 语义）
    pub fn decrement(&self, username: &str) {
        let mut sessions = self.active_sessions.lock().unwrap();
        if let Some(counter) = sessions.get(username) {
            let old_count = counter.fetch_sub(1, Ordering::SeqCst);
            if old_count == 0 {
                tracing::warn!("User {username} session count underflow detected");
            } else if old_count == 1 {
                if counter.load(Ordering::SeqCst) == 0 {
                    sessions.remove(username);
                }
                tracing::debug!("User {username} removed from session tracking");
            } else {
                tracing::debug!("User {username} session decremented to {}", old_count - 1);
            }
        } else {
            tracing::warn!("User {username} not found in session tracking");
        }
    }

    /// 当前并发会话数
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic（`fftp-common` 语义）
    #[must_use]
    pub fn get_count(&self, username: &str) -> u32 {
        self.active_sessions
            .lock()
            .unwrap()
            .get(username)
            .map_or(0, |c| c.load(Ordering::SeqCst))
    }
}

/// 认证上下文（会话级：尝试次数、超时、认证结果）
pub struct AuthContext {
    pub authenticated: bool,
    pub username: Option<String>,
    pub home_dir: Option<String>,
    pub auth_attempts: u32,
    pub max_auth_attempts: u32,
    pub auth_start_time: Option<std::time::Instant>,
    pub auth_timeout_secs: u64,
}

/// SFTP 连接处理器（每个 TCP 连接一个实例）
pub struct SftpHandler {
    pub user_manager: Arc<StdMutex<UserManager>>,
    pub quota_manager: Arc<QuotaManager>,
    /// `Fail2Ban` 失败计数（未启用时为 None）
    pub fail2ban: Option<Arc<Fail2BanManager>>,
    pub sessions: Arc<SessionTracker>,
    /// 文件操作审计（`fftp-common` 日志设施，可选）
    pub logging: Option<Arc<Logging>>,
    pub auth: AuthContext,
    /// 已打开、等待 subsystem 请求的会话通道
    pub pending_channels: HashMap<ChannelId, Channel<Msg>>,
    pub client_ip: String,
    pub max_sessions_per_user: u32,
    /// 是否允许跟随符号链接（`security.allow_symlinks`）
    pub allow_symlinks: bool,
}

impl SftpHandler {
    /// 创建处理器（accept 循环为每个连接调用）
    // 构造函数聚合全部共享依赖，参数即服务装配清单，拆配置结构反而增加组装成本
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_manager: Arc<StdMutex<UserManager>>,
        quota_manager: Arc<QuotaManager>,
        fail2ban: Option<Arc<Fail2BanManager>>,
        sessions: Arc<SessionTracker>,
        logging: Option<Arc<Logging>>,
        client_ip: String,
        max_auth_attempts: u32,
        auth_timeout_secs: u64,
        max_sessions_per_user: u32,
        allow_symlinks: bool,
    ) -> Self {
        SftpHandler {
            user_manager,
            quota_manager,
            fail2ban,
            sessions,
            logging,
            auth: AuthContext {
                authenticated: false,
                username: None,
                home_dir: None,
                auth_attempts: 0,
                max_auth_attempts,
                auth_start_time: Some(std::time::Instant::now()),
                auth_timeout_secs,
            },
            pending_channels: HashMap::new(),
            client_ip,
            max_sessions_per_user,
            allow_symlinks,
        }
    }

    /// 认证前置检查：用户名安全、认证超时、尝试次数上限
    fn check_auth_preconditions(&mut self, user: &str) -> Option<server::Auth> {
        if !is_safe_username(user) {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = %user,
                action = "AUTH_REJECTED",
                "Auth rejected: unsafe username"
            );
            return Some(server::Auth::reject());
        }

        if let Some(start_time) = self.auth.auth_start_time {
            let elapsed = start_time.elapsed().as_secs();
            if elapsed > self.auth.auth_timeout_secs {
                tracing::warn!(
                    client_ip = %self.client_ip,
                    username = %user,
                    action = "AUTH_TIMEOUT",
                    protocol = "SFTP",
                    "Authentication timeout after {elapsed} seconds"
                );
                return Some(server::Auth::reject());
            }
        }

        self.auth.auth_attempts += 1;
        if self.auth.auth_attempts > self.auth.max_auth_attempts {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = %user,
                action = "AUTH_MAX_ATTEMPTS",
                protocol = "SFTP",
                "Maximum authentication attempts ({}) exceeded",
                self.auth.max_auth_attempts
            );
            return Some(server::Auth::reject());
        }

        None
    }

    /// 认证成功收尾：home 目录校验、会话上限检查、注册会话计数
    fn finalize_auth_success(
        &mut self,
        user: &str,
        home_dir: Option<String>,
        method: &str,
    ) -> server::Auth {
        if let Some(hd) = home_dir {
            match std::path::PathBuf::from(&hd).canonicalize() {
                Ok(home_canon) => {
                    self.auth.home_dir = Some(home_canon.to_string_lossy().to_string());
                }
                Err(e) => {
                    tracing::warn!(
                        client_ip = %self.client_ip,
                        username = %user,
                        action = "HOME_NOT_FOUND",
                        "Home directory not found for user {user}: {hd} ({e})"
                    );
                    return server::Auth::reject();
                }
            }
        }

        let session_count = self.sessions.get_count(user);
        if session_count >= self.max_sessions_per_user {
            tracing::warn!(
                client_ip = %self.client_ip,
                username = %user,
                action = "SESSION_LIMIT",
                protocol = "SFTP",
                "User {user} has reached maximum session limit ({})",
                self.max_sessions_per_user
            );
            return server::Auth::reject();
        }

        self.auth.authenticated = true;
        self.auth.username = Some(user.to_string());
        self.sessions.increment(user);
        fftp_common::metrics::record_auth_success();

        tracing::info!(
            client_ip = %self.client_ip,
            username = %user,
            action = "LOGIN",
            protocol = "SFTP",
            "User {user} logged in via {method}"
        );

        server::Auth::Accept
    }

    /// 记录一次认证失败（Fail2Ban + 指标）
    async fn record_auth_failure(&self) {
        if let Some(fb) = &self.fail2ban {
            fb.add_failure(&self.client_ip).await;
        }
        fftp_common::metrics::record_auth_failure();
    }

    /// 认证成功后重置 `Fail2Ban` 计数
    async fn reset_auth_failures(&self) {
        if let Some(fb) = &self.fail2ban {
            fb.reset_failures(&self.client_ip).await;
        }
    }

    /// 读取用户 `authorized_keys` 并匹配客户端公钥
    async fn public_key_matches(user: &str, public_key: &PublicKey) -> bool {
        let authorized_keys = fftp_common::paths::keys_dir()
            .join(user)
            .join("authorized_keys");
        let Ok(content) = tokio::fs::read_to_string(&authorized_keys).await else {
            return false;
        };
        content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .any(|line| authorized_key_line_matches(line, public_key))
    }
}

/// 单行 `authorized_keys` 与客户端公钥是否匹配
///
/// `PublicKey` 的相等比较包含注释字段，而 SSH 认证报文中不携带注释；
/// 若按整体比较，带注释的标准 OpenSSH 公钥行将永远无法匹配。
fn authorized_key_line_matches(line: &str, public_key: &PublicKey) -> bool {
    let stored = russh::keys::PublicKey::from_openssh(line)
        .or_else(|_| russh::keys::parse_public_key_base64(line));
    matches!(stored, Ok(k) if public_key.key_data() == k.key_data())
}

impl russh::server::Handler for SftpHandler {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        if let Some(reject) = self.check_auth_preconditions(user) {
            if self.auth.auth_attempts > self.auth.max_auth_attempts {
                self.record_auth_failure().await;
            }
            return Ok(reject);
        }

        let (auth_result, home_dir_opt) = {
            let mut users = self.user_manager.lock().unwrap();

            if users.get_user(user).is_none()
                && let Err(e) = users.reload(&fftp_common::paths::users_path())
            {
                tracing::warn!("Failed to reload users during SFTP authentication: {e}");
            }

            let result = users.authenticate(user, password);
            let home = users.get_user(user).map(|u| u.home_dir.clone());
            (result, home)
        };

        match auth_result {
            Ok(true) => {
                let result = self.finalize_auth_success(user, home_dir_opt, "password");
                if matches!(result, server::Auth::Accept) {
                    self.reset_auth_failures().await;
                }
                Ok(result)
            }
            Ok(false) => {
                self.record_auth_failure().await;
                tracing::warn!(
                    client_ip = %self.client_ip,
                    username = %user,
                    action = "AUTH_FAIL",
                    protocol = "SFTP",
                    "Failed login attempt for user {user}"
                );
                Ok(server::Auth::reject())
            }
            Err(e) => {
                self.record_auth_failure().await;
                tracing::error!(
                    client_ip = %self.client_ip,
                    username = %user,
                    action = "AUTH_ERROR",
                    protocol = "SFTP",
                    "Authentication error for user {user}: {e}"
                );
                Ok(server::Auth::reject())
            }
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        if let Some(reject) = self.check_auth_preconditions(user) {
            if self.auth.auth_attempts > self.auth.max_auth_attempts {
                self.record_auth_failure().await;
            }
            return Ok(reject);
        }

        let (enabled, home_dir) = {
            let users = self.user_manager.lock().unwrap();
            match users.get_user(user) {
                Some(u) => (u.enabled, Some(u.home_dir.clone())),
                None => (false, None),
            }
        };

        if !enabled {
            self.record_auth_failure().await;
            tracing::warn!(
                client_ip = %self.client_ip,
                username = %user,
                action = "AUTH_FAIL",
                "Public key auth failed for user {user}: user not found or disabled"
            );
            return Ok(server::Auth::reject());
        }

        if Self::public_key_matches(user, public_key).await {
            let result = self.finalize_auth_success(user, home_dir, "publickey");
            if matches!(result, server::Auth::Accept) {
                self.reset_auth_failures().await;
            }
            return Ok(result);
        }

        self.record_auth_failure().await;
        tracing::warn!(
            client_ip = %self.client_ip,
            username = %user,
            action = "AUTH_FAIL",
            "Public key auth failed for user {user}: key mismatch or not found"
        );

        Ok(server::Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if !self.auth.authenticated {
            tracing::warn!(
                client_ip = %self.client_ip,
                action = "CHANNEL_OPEN_DENIED",
                reason = "not_authenticated",
                "Reject unauthenticated channel open request"
            );
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        tracing::debug!(
            client_ip = %self.client_ip,
            action = "CHANNEL_OPEN_SESSION",
            channel_id = ?channel.id(),
            "Allow session channel open"
        );

        reply.accept().await;
        // russh 的 accept 不回传 channel，暂存等待 subsystem 请求取出
        self.pending_channels.insert(channel.id(), channel);
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        tracing::warn!(
            client_ip = %self.client_ip,
            action = "TCP_FORWARD_DISABLED",
            "TCP forwarding is disabled for SFTP"
        );
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        tracing::warn!(
            client_ip = %self.client_ip,
            action = "FORWARDED_TCP_DISABLED",
            "Forwarded TCP connection is disabled for SFTP"
        );
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    // 签名由 `russh::server::Handler` 异步 trait 决定，无法去除 async
    #[allow(clippy::unused_async_trait_impl)]
    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        tracing::warn!(
            client_ip = %self.client_ip,
            action = "TCP_PORT_FORWARD_DISABLED",
            "TCP port forwarding is disabled for SFTP"
        );
        Ok(false)
    }

    // 签名由 `russh::server::Handler` 异步 trait 决定，无法去除 async
    #[allow(clippy::unused_async_trait_impl)]
    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        _port: u32,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        tracing::warn!(
            client_ip = %self.client_ip,
            action = "TCP_FORWARD_CANCEL_DENIED",
            "Cancel TCP port forward denied: {address}"
        );
        Ok(false)
    }

    // 签名由 `russh::server::Handler` 异步 trait 决定，无法去除 async
    #[allow(clippy::unused_async_trait_impl)]
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            tracing::debug!(
                client_ip = %self.client_ip,
                subsystem = %name,
                "Rejecting non-sftp subsystem request"
            );
            if let Err(e) = session.channel_failure(channel) {
                tracing::debug!("Failed to send channel_failure (not sftp): {e}");
            }
            return Ok(());
        }

        if !self.auth.authenticated {
            tracing::warn!(
                client_ip = %self.client_ip,
                action = "SUBSYSTEM_DENIED",
                reason = "not_authenticated",
                "Reject sftp subsystem request from unauthenticated session"
            );
            if let Err(e) = session.channel_failure(channel) {
                tracing::debug!("Failed to send channel_failure (not auth): {e}");
            }
            return Ok(());
        }

        let Some(home_dir) = self.auth.home_dir.clone() else {
            tracing::error!("SFTP subsystem request failed: home directory not set");
            if let Err(e) = session.channel_failure(channel) {
                tracing::debug!("Failed to send channel_failure (no home dir): {e}");
            }
            return Ok(());
        };

        if let Err(e) = session.channel_success(channel) {
            tracing::warn!("Failed to send channel_success for sftp subsystem: {e}");
        }

        // 会话通道在 channel_open_session 暂存，此处取出并整体移交给协议层
        let Some(channel_obj) = self.pending_channels.remove(&channel) else {
            tracing::warn!(
                client_ip = %self.client_ip,
                channel_id = ?channel,
                "SFTP subsystem request on unknown channel"
            );
            return Ok(());
        };

        let state = SftpState::new(
            home_dir,
            self.auth.username.clone(),
            Arc::clone(&self.user_manager),
            Arc::clone(&self.quota_manager),
            self.logging.clone(),
            self.client_ip.clone(),
            self.allow_symlinks,
        );

        tracing::debug!(
            client_ip = %self.client_ip,
            username = ?self.auth.username,
            channel_id = ?channel,
            "Starting SFTP subsystem protocol loop"
        );

        // 报文循环移交后自持会话状态；流关闭时 Session::drop 负责清理句柄与锁
        run_with_config(
            channel_obj.into_stream(),
            Session::new(state),
            protocol::Config::default(),
        )
        .await;
        Ok(())
    }
}

impl Drop for SftpHandler {
    fn drop(&mut self) {
        // 连接断开时递减会话计数
        if let Some(username) = &self.auth.username
            && self.auth.authenticated
        {
            self.sessions.decrement(username);
            tracing::debug!("User {username} session ended");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_tracker_increment_decrement() {
        let tracker = SessionTracker::new();
        tracker.increment("alice");
        tracker.increment("alice");
        assert_eq!(tracker.get_count("alice"), 2);
        tracker.decrement("alice");
        assert_eq!(tracker.get_count("alice"), 1);
        tracker.decrement("alice");
        assert_eq!(tracker.get_count("alice"), 0);
        // 归零后条目被移除，再次查询为 0
        assert_eq!(tracker.get_count("alice"), 0);
    }

    #[test]
    fn test_session_tracker_decrement_unknown_user() {
        let tracker = SessionTracker::new();
        tracker.decrement("ghost");
        assert_eq!(tracker.get_count("ghost"), 0);
    }

    #[test]
    fn test_auth_preconditions_reject_unsafe_username() {
        let mut handler = SftpHandler::new(
            Arc::new(StdMutex::new(UserManager::new())),
            Arc::new(QuotaManager::new(&std::env::temp_dir())),
            None,
            Arc::new(SessionTracker::new()),
            None,
            "127.0.0.1".to_string(),
            3,
            60,
            4,
            false,
        );
        assert!(handler.check_auth_preconditions("../evil").is_some());
        assert!(handler.check_auth_preconditions("a/b").is_some());
        assert!(handler.check_auth_preconditions("alice").is_none());
    }

    #[test]
    fn test_auth_preconditions_max_attempts() {
        let mut handler = SftpHandler::new(
            Arc::new(StdMutex::new(UserManager::new())),
            Arc::new(QuotaManager::new(&std::env::temp_dir())),
            None,
            Arc::new(SessionTracker::new()),
            None,
            "127.0.0.1".to_string(),
            2,
            60,
            4,
            false,
        );
        assert!(handler.check_auth_preconditions("alice").is_none());
        assert!(handler.check_auth_preconditions("alice").is_none());
        // 第 3 次超过上限 2
        assert!(handler.check_auth_preconditions("alice").is_some());
    }

    #[test]
    fn authorized_keys_line_matches_ignoring_comment() {
        let bare = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF/0OFXQSRRXlUI29qILoNdMSbtW/89Z+yfvFWRPjKd6";
        let with_comment = format!("{bare} alice@example");
        let client = PublicKey::from_openssh(bare).expect("解析测试公钥");

        assert!(
            authorized_key_line_matches(&with_comment, &client),
            "带注释的标准 OpenSSH 公钥行必须匹配"
        );
        assert!(authorized_key_line_matches(bare, &client));
        assert!(!authorized_key_line_matches("not-a-key", &client));
    }
}

//! SFTP SSH 会话处理器（`russh::server::Handler`）
//!
//! 负责认证（口令 / 公钥）、会话通道管理与 SFTP 数据泵。
//! 认证对接 `fftp-common` 的 [`UserManager`]（口令校验 + 用户名安全检查），
//! 公钥认证读取 `keys_dir()/<user>/authorized_keys`；失败计数接 Fail2Ban，指标接 prometheus。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};

use russh::keys::PublicKey;
use russh::server::Msg;
use russh::{Channel, ChannelId, server};
use tokio::sync::Mutex as TokioMutex;

use fftp_common::fail2ban::Fail2BanManager;
use fftp_common::logging::Logging;
use fftp_common::quota::QuotaManager;
use fftp_common::users::{UserManager, is_safe_username};

use crate::state::SftpState;
use crate::types::{MAX_BUFFER_SIZE, MAX_PACKET_SIZE};
use crate::{cmd_dispatch, protocol};

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
    pub sftp_channel: Option<ChannelId>,
    pub sftp_state: Option<Arc<TokioMutex<SftpState>>>,
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
            sftp_channel: None,
            sftp_state: None,
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
        for line in content.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // 兼容 OpenSSH 单行公钥与纯 base64 两种存储格式
            let stored = russh::keys::PublicKey::from_openssh(line)
                .or_else(|_| russh::keys::parse_public_key_base64(line));
            if let Ok(stored_pubkey) = stored
                && public_key == &stored_pubkey
            {
                return true;
            }
        }
        false
    }

    /// SFTP 数据泵：粘包缓冲 → 逐包分发 → 拼接应答
    async fn process_sftp_data(
        state: Arc<TokioMutex<SftpState>>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let mut state = state.lock().await;

        if state.buffer.len() + data.len() > MAX_BUFFER_SIZE {
            tracing::warn!(
                "SFTP buffer overflow attempt: buffer={}, incoming={}, max={MAX_BUFFER_SIZE}",
                state.buffer.len(),
                data.len()
            );
            state.buffer.clear();
            return Ok(protocol::build_status_packet(
                0,
                crate::types::SSH_FX_FAILURE,
                "Buffer overflow",
                "",
            ));
        }

        state.buffer.extend_from_slice(&data);

        let mut responses: Vec<u8> = Vec::new();

        while state.buffer.len() >= 4 {
            let packet_len = usize::try_from(u32::from_be_bytes([
                state.buffer[0],
                state.buffer[1],
                state.buffer[2],
                state.buffer[3],
            ]))?;

            if packet_len > MAX_PACKET_SIZE {
                tracing::warn!(
                    "SFTP packet too large: {packet_len} bytes (max {MAX_PACKET_SIZE})"
                );
                state.buffer.clear();
                return Ok(protocol::build_status_packet(
                    0,
                    crate::types::SSH_FX_FAILURE,
                    "Packet too large",
                    "",
                ));
            }

            if state.buffer.len() < 4 + packet_len {
                break;
            }

            let packet: Vec<u8> = state.buffer[4..4 + packet_len].to_vec();
            state.buffer.drain(0..4 + packet_len);

            if !packet.is_empty() {
                let response = state.dispatch_packet(&packet).await?;
                responses.extend_from_slice(&response);
            }
        }

        Ok(responses)
    }
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
        if name == "sftp" && self.auth.authenticated {
            if let Some(ref home_dir) = self.auth.home_dir {
                if let Err(e) = session.channel_success(channel) {
                    tracing::warn!("Failed to send channel_success for sftp subsystem: {e}");
                }

                self.sftp_channel = Some(channel);

                let state = SftpState::new(
                    home_dir.clone(),
                    self.auth.username.clone(),
                    Arc::clone(&self.user_manager),
                    Arc::clone(&self.quota_manager),
                    self.logging.clone(),
                    self.client_ip.clone(),
                    self.allow_symlinks,
                );

                self.sftp_state = Some(Arc::new(TokioMutex::new(state)));
            } else {
                tracing::error!("SFTP subsystem request failed: home directory not set");
                if let Err(e) = session.channel_failure(channel) {
                    tracing::debug!("Failed to send channel_failure (no home dir): {e}");
                }
            }
        } else if let Err(e) = session.channel_failure(channel) {
            tracing::debug!("Failed to send channel_failure (not sftp/not auth): {e}");
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.sftp_channel != Some(channel) {
            tracing::warn!(
                client_ip = %self.client_ip,
                action = "DATA_ON_INVALID_CHANNEL",
                channel_id = ?channel,
                expected_channel = ?self.sftp_channel,
                reason = "channel_mismatch_or_not_initialized",
                "Received data on non-SFTP channel or SFTP not initialized"
            );
            if let Err(e) = session.channel_failure(channel) {
                tracing::debug!("Failed to send channel_failure (data on invalid channel): {e}");
            }
            return Ok(());
        }

        if self.sftp_state.is_none() {
            tracing::warn!(
                client_ip = %self.client_ip,
                action = "DATA_BEFORE_SFTP_INIT",
                channel_id = ?channel,
                reason = "sftp_state_not_initialized",
                "SFTP state not initialized, subsystem request may have failed"
            );
            if let Err(e) = session.channel_failure(channel) {
                tracing::debug!("Failed to send channel_failure: {e:?}");
            }
            return Ok(());
        }

        if let Some(state) = &self.sftp_state {
            match Self::process_sftp_data(Arc::clone(state), data.to_vec()).await {
                Ok(resp) => {
                    let handle = session.handle();
                    if let Err(e) = handle.data(channel, resp).await {
                        tracing::warn!("Failed to send SFTP response: {e:?}");
                    }
                }
                Err(e) => {
                    tracing::error!(
                        client_ip = %self.client_ip,
                        action = "SFTP_DATA_PROCESS_ERROR",
                        error = %e,
                        "Error processing SFTP data"
                    );
                }
            }
        }

        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.sftp_channel == Some(channel)
            && let Some(state) = &self.sftp_state
        {
            let mut state = state.lock().await;
            state.cleanup();
        }
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

/// 便捷再导出：INIT 版本协商上限
pub use cmd_dispatch::MAX_SFTP_VERSION;

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
}

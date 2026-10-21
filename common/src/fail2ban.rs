//! 登录防护（docs/design.md §4「防护」：Windows `fail2ban.rs` 为基础，合并 Linux `server/login_tracker.rs` 的统计字段）
//!
//! - 失败尝试记录：按 IP 记录窗口内失败时刻与首次失败时间（[`FailureRecord`]）；
//! - 阈值封禁：[`SecurityConfig::fail2ban_threshold`] 次失败封禁 [`SecurityConfig::fail2ban_ban_time`] 秒；
//! - 解封回调：[`Fail2BanManager::register_callback`] 注册 [`BanEvent`] 通知；
//! - 封禁持久化：`<data_dir>/fail2ban.json`，封禁/解封时落盘，进程重启后仍生效
//!   （Windows 旧版仅有内存态，此处按设计文档「含持久化」补齐）；
//! - 统计接口：[`Fail2BanManager::get_failure_count`] / [`Fail2BanManager::get_remaining_attempts`]，
//!   后者按 [`SecurityConfig::max_login_attempts`] 折算剩余尝试次数。
//!
//! 配置注入统一使用 [`SecurityConfig`]，不另行定义重复配置结构；Windows 版
//! `Fail2BanConfig::find_time` 未进入统一 schema，失败计数窗口取其旧默认值
//! （[`FAILURE_WINDOW_SECS`]）作为常量。

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::SecurityConfig;

/// 失败计数窗口（秒）：窗口内的失败累加，窗口外的记录在清理时丢弃
pub const FAILURE_WINDOW_SECS: i64 = 600;

/// 封禁事件（供回调使用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanEvent {
    Banned,
    Unbanned,
}

/// 封禁/解封回调
pub type BanCallback = dyn Fn(&str, BanEvent) + Send + Sync;

/// 单 IP 失败统计（合并 Linux `login_tracker.rs` 的 count / first_attempt 字段）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FailureRecord {
    /// 窗口内的失败时刻（同一时间戳去重，计数 = len）
    attempts: HashSet<DateTime<Utc>>,
    /// 首次失败时间
    first_attempt: DateTime<Utc>,
}

impl FailureRecord {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            attempts: HashSet::new(),
            first_attempt: now,
        }
    }

    fn count(&self) -> usize {
        self.attempts.len()
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let window = Duration::seconds(FAILURE_WINDOW_SECS);
        self.attempts.retain(|&time| now - time < window);
    }

    fn is_empty(&self) -> bool {
        self.attempts.is_empty()
    }
}

/// 持久化的封禁清单（`fail2ban.json`）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BanList {
    /// IP → 封禁截止时刻（RFC3339）
    pub banned: HashMap<String, DateTime<Utc>>,
}

#[derive(Debug, Default)]
struct Fail2BanState {
    failed_attempts: HashMap<String, FailureRecord>,
    banned_ips: HashMap<String, DateTime<Utc>>,
}

/// 登录防护管理器
pub struct Fail2BanManager {
    state: Mutex<Fail2BanState>,
    config: Mutex<SecurityConfig>,
    callbacks: Mutex<Vec<Arc<BanCallback>>>,
    cleanup_started: AtomicBool,
    ban_list_path: PathBuf,
}

impl fmt::Debug for Fail2BanManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let callback_count = self.callbacks.lock().unwrap().len();
        f.debug_struct("Fail2BanManager")
            .field("state", &self.state)
            .field("config", &self.config)
            .field("callbacks", &callback_count)
            .field("cleanup_started", &self.cleanup_started)
            .field("ban_list_path", &self.ban_list_path)
            .finish()
    }
}

impl Fail2BanManager {
    /// 创建管理器并从 `<data_dir>/fail2ban.json` 恢复封禁清单（过期封禁不恢复）
    #[must_use]
    pub fn new(data_dir: &Path, security: &SecurityConfig) -> Self {
        let ban_list_path = data_dir.join("fail2ban.json");
        let mut state = Fail2BanState::default();

        if let Ok(content) = std::fs::read_to_string(&ban_list_path)
            && let Ok(list) = serde_json::from_str::<BanList>(&content)
        {
            let now = Utc::now();
            state.banned_ips = list
                .banned
                .into_iter()
                .filter(|&(_, ban_until)| now < ban_until)
                .collect();
        }

        Self {
            state: Mutex::new(state),
            config: Mutex::new(security.clone()),
            callbacks: Mutex::new(Vec::new()),
            cleanup_started: AtomicBool::new(false),
            ban_list_path,
        }
    }

    /// 注册封禁/解封回调
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn register_callback(&self, callback: Arc<BanCallback>) {
        self.callbacks.lock().unwrap().push(callback);
    }

    /// 配置热更新（对应 IPC `save_config` 后的生效路径）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn update_config(&self, security: &SecurityConfig) {
        *self.config.lock().unwrap() = security.clone();
        tracing::info!("Fail2Ban: Configuration updated");
    }

    /// 当前生效的安全配置
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub fn get_config(&self) -> SecurityConfig {
        self.config.lock().unwrap().clone()
    }

    /// # Panics
    /// 内部互斥锁中毒时 panic
    fn trigger_callbacks(&self, ip: &str, event: BanEvent) {
        for callback in self.callbacks.lock().unwrap().iter() {
            callback(ip, event);
        }
    }

    /// 落盘封禁清单（失败仅告警，不影响内存态）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    fn persist_bans(&self) {
        let list = BanList {
            banned: self.state.lock().unwrap().banned_ips.clone(),
        };
        let content = match serde_json::to_string_pretty(&list) {
            Ok(content) => content,
            Err(e) => {
                tracing::warn!("Fail2Ban: failed to serialize ban list: {e}");
                return;
            }
        };
        if let Some(parent) = self.ban_list_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!("Fail2Ban: failed to create ban list directory: {e}");
            return;
        }
        if let Err(e) = std::fs::write(&self.ban_list_path, content) {
            tracing::warn!("Fail2Ban: failed to persist ban list: {e}");
        }
    }

    /// 记录一次认证失败；达到 [`SecurityConfig::fail2ban_threshold`] 时封禁并返回 `true`
    pub async fn add_failure(&self, ip: &str) -> bool {
        let (threshold, ban_time, enabled) = {
            let cfg = self.config.lock().unwrap();
            (
                cfg.fail2ban_threshold,
                cfg.fail2ban_ban_time,
                cfg.fail2ban_enabled,
            )
        };

        if !enabled {
            return false;
        }
        let threshold = usize::try_from(threshold).unwrap_or(usize::MAX);

        let now = Utc::now();
        let mut state = self.state.lock().unwrap();

        let record = state
            .failed_attempts
            .entry(ip.to_string())
            .or_insert_with(|| FailureRecord::new(now));
        record.attempts.insert(now);
        record.prune(now);

        if record.count() < threshold {
            return false;
        }

        let ban_until = now + Duration::seconds(i64::try_from(ban_time).unwrap_or(i64::MAX));
        state.banned_ips.insert(ip.to_string(), ban_until);
        state.failed_attempts.remove(ip);
        drop(state);

        self.persist_bans();
        tracing::warn!(
            "Fail2Ban: IP {ip} reached threshold ({threshold} failures), banning for {ban_time} seconds"
        );
        self.trigger_callbacks(ip, BanEvent::Banned);
        true
    }

    /// IP 是否处于封禁期（封禁过期时顺带解封并触发回调）
    pub async fn is_banned(&self, ip: &str) -> bool {
        let now = Utc::now();
        let mut state = self.state.lock().unwrap();

        if let Some(&ban_until) = state.banned_ips.get(ip) {
            if now < ban_until {
                return true;
            }
            state.banned_ips.remove(ip);
            drop(state);
            self.persist_bans();
            self.trigger_callbacks(ip, BanEvent::Unbanned);
        }

        false
    }

    /// 手动解封
    pub async fn unban_ip(&self, ip: &str) {
        let existed = self.state.lock().unwrap().banned_ips.remove(ip).is_some();

        if existed {
            self.persist_bans();
            tracing::info!("Fail2Ban: Manually unbanned IP {ip}");
            self.trigger_callbacks(ip, BanEvent::Unbanned);
        }
    }

    /// 清除 IP 的失败记录（登录成功后调用）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub async fn reset_failures(&self, ip: &str) {
        self.state.lock().unwrap().failed_attempts.remove(ip);
    }

    /// 窗口内的失败次数
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub async fn get_failure_count(&self, ip: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .failed_attempts
            .get(ip)
            .map_or(0, FailureRecord::count)
    }

    /// 首次失败时间（Linux `login_tracker` 统计字段）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub async fn get_first_attempt(&self, ip: &str) -> Option<DateTime<Utc>> {
        self.state
            .lock()
            .unwrap()
            .failed_attempts
            .get(ip)
            .map(|r| r.first_attempt)
    }

    /// 剩余可尝试次数（按 [`SecurityConfig::max_login_attempts`]，封禁中为 0）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub async fn get_remaining_attempts(&self, ip: &str) -> u32 {
        let max_attempts = self.config.lock().unwrap().max_login_attempts;
        let state = self.state.lock().unwrap();
        if state.banned_ips.contains_key(ip) {
            return 0;
        }
        let count = state.failed_attempts.get(ip).map_or(0, FailureRecord::count);
        max_attempts.saturating_sub(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// 当前被封禁的 IP 列表
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub async fn get_banned_ips(&self) -> Vec<String> {
        self.state.lock().unwrap().banned_ips.keys().cloned().collect()
    }

    /// 清理：解除到期封禁（触发回调）、丢弃窗口外的失败记录
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub async fn cleanup(&self) {
        let now = Utc::now();

        let mut state = self.state.lock().unwrap();

        let expired_bans: Vec<String> = state
            .banned_ips
            .iter()
            .filter(|&(_, ban_until)| now >= *ban_until)
            .map(|(ip, _)| ip.clone())
            .collect();

        for ip in &expired_bans {
            state.banned_ips.remove(ip);
        }

        for record in state.failed_attempts.values_mut() {
            record.prune(now);
        }
        state.failed_attempts.retain(|_, r| !r.is_empty());

        drop(state);

        if !expired_bans.is_empty() {
            self.persist_bans();
        }
        for ip in &expired_bans {
            self.trigger_callbacks(ip, BanEvent::Unbanned);
        }

        tracing::debug!("Fail2Ban: Cleanup completed");
    }

    /// 启动周期清理任务（每 5 分钟一次，重复调用无效）
    pub fn start_cleanup_task(self: Arc<Self>) {
        if self
            .cleanup_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                self.cleanup().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config(threshold: u32, ban_time: u64) -> SecurityConfig {
        SecurityConfig {
            fail2ban_enabled: true,
            fail2ban_threshold: threshold,
            fail2ban_ban_time: ban_time,
            ..SecurityConfig::default()
        }
    }

    fn manager(threshold: u32, ban_time: u64) -> (tempfile::TempDir, Arc<Fail2BanManager>) {
        let dir = tempfile::tempdir().unwrap();
        let manager = Arc::new(Fail2BanManager::new(
            dir.path(),
            &enabled_config(threshold, ban_time),
        ));
        (dir, manager)
    }

    #[tokio::test]
    async fn threshold_triggers_ban() {
        let (_dir, manager) = manager(3, 60);

        assert!(!manager.is_banned("192.168.1.1").await);
        assert!(!manager.add_failure("192.168.1.1").await);
        assert!(!manager.add_failure("192.168.1.1").await);
        assert_eq!(manager.get_failure_count("192.168.1.1").await, 2);

        assert!(manager.add_failure("192.168.1.1").await);
        assert!(manager.is_banned("192.168.1.1").await);

        manager.reset_failures("192.168.1.1").await;
        assert_eq!(manager.get_failure_count("192.168.1.1").await, 0);
    }

    #[tokio::test]
    async fn failures_below_threshold_allowed() {
        let (_dir, manager) = manager(5, 60);
        for _ in 0..4 {
            assert!(!manager.add_failure("1.2.3.4").await);
        }
        assert!(!manager.is_banned("1.2.3.4").await);
        assert_eq!(manager.get_remaining_attempts("1.2.3.4").await, 1);
    }

    #[tokio::test]
    async fn banned_ip_has_zero_remaining_attempts() {
        let (_dir, manager) = manager(2, 60);
        assert!(manager.get_remaining_attempts("1.2.3.4").await >= 1);
        manager.add_failure("1.2.3.4").await;
        manager.add_failure("1.2.3.4").await;
        assert!(manager.is_banned("1.2.3.4").await);
        assert_eq!(manager.get_remaining_attempts("1.2.3.4").await, 0);
        // 封禁期内继续失败仍被拒绝
        assert!(!manager.add_failure("1.2.3.4").await);
    }

    #[tokio::test]
    async fn other_ips_unaffected() {
        let (_dir, manager) = manager(2, 60);
        manager.add_failure("1.1.1.1").await;
        manager.add_failure("1.1.1.1").await;
        assert!(manager.is_banned("1.1.1.1").await);
        assert!(!manager.is_banned("2.2.2.2").await);
        assert!(!manager.add_failure("2.2.2.2").await);
    }

    #[tokio::test]
    async fn disabled_never_bans() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Fail2BanManager::new(
            dir.path(),
            &SecurityConfig {
                fail2ban_enabled: false,
                ..SecurityConfig::default()
            },
        );

        for _ in 0..10 {
            assert!(!manager.add_failure("3.3.3.3").await);
        }
        assert!(!manager.is_banned("3.3.3.3").await);
    }

    #[tokio::test]
    async fn unknown_ip_has_full_attempts() {
        let (_dir, manager) = manager(4, 60);
        let max = manager.get_config().max_login_attempts;
        assert_eq!(manager.get_remaining_attempts("9.9.9.9").await, max);
        assert!(!manager.is_banned("9.9.9.9").await);
    }

    #[tokio::test]
    async fn clear_attempts_resets_state() {
        let (_dir, manager) = manager(3, 60);
        manager.add_failure("1.2.3.4").await;
        manager.add_failure("1.2.3.4").await;
        manager.reset_failures("1.2.3.4").await;
        assert_eq!(
            manager.get_remaining_attempts("1.2.3.4").await,
            manager.get_config().max_login_attempts
        );
    }

    #[tokio::test]
    async fn ban_expires_and_resets() {
        // 封禁时长 0：立刻过期
        let (_dir, manager) = manager(2, 0);
        manager.add_failure("1.2.3.4").await;
        assert!(manager.add_failure("1.2.3.4").await);
        assert!(!manager.is_banned("1.2.3.4").await);
        assert_eq!(
            manager.get_remaining_attempts("1.2.3.4").await,
            manager.get_config().max_login_attempts
        );
    }

    #[tokio::test]
    async fn cleanup_keeps_active_bans_and_fresh_failures() {
        let (_dir, manager) = manager(2, 3600);
        manager.add_failure("1.2.3.4").await;
        manager.add_failure("1.2.3.4").await;

        manager.cleanup().await;
        assert!(manager.is_banned("1.2.3.4").await, "未过期的封禁应保留");

        manager.unban_ip("1.2.3.4").await;
        manager.add_failure("5.5.5.5").await;
        manager.cleanup().await;
        assert_eq!(manager.get_failure_count("5.5.5.5").await, 1, "1 小时内记录应保留");
    }

    #[tokio::test]
    async fn config_hot_update() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Fail2BanManager::new(dir.path(), &SecurityConfig::default());

        manager.update_config(&enabled_config(10, 7200));
        let current = manager.get_config();
        assert!(current.fail2ban_enabled);
        assert_eq!(current.fail2ban_threshold, 10);
        assert_eq!(current.fail2ban_ban_time, 7200);
    }

    #[tokio::test]
    async fn ban_unban_callbacks_fire() {
        use std::sync::atomic::AtomicUsize;

        let (_dir, manager) = manager(2, 60);

        let ban_count = Arc::new(AtomicUsize::new(0));
        let unban_count = Arc::new(AtomicUsize::new(0));

        let ban_count_clone = Arc::clone(&ban_count);
        let unban_count_clone = Arc::clone(&unban_count);
        manager.register_callback(Arc::new(move |_ip, event| match event {
            BanEvent::Banned => {
                ban_count_clone.fetch_add(1, Ordering::SeqCst);
            }
            BanEvent::Unbanned => {
                unban_count_clone.fetch_add(1, Ordering::SeqCst);
            }
        }));

        manager.add_failure("192.168.1.2").await;
        assert!(manager.add_failure("192.168.1.2").await);
        assert_eq!(ban_count.load(Ordering::SeqCst), 1);

        manager.unban_ip("192.168.1.2").await;
        assert_eq!(unban_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn duplicate_timestamps_counted_once() {
        let (_dir, manager) = manager(5, 60);
        let now = Utc::now();
        {
            let mut state = manager.state.lock().unwrap();
            let mut record = FailureRecord::new(now);
            record.attempts.insert(now);
            record.attempts.insert(now);
            state
                .failed_attempts
                .insert("192.168.1.3".to_string(), record);
        }
        assert_eq!(manager.get_failure_count("192.168.1.3").await, 1);
    }

    #[tokio::test]
    async fn bans_persist_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let manager = Fail2BanManager::new(dir.path(), &enabled_config(1, 3600));
            assert!(manager.add_failure("10.0.0.1").await);
        }

        let restored = Fail2BanManager::new(dir.path(), &enabled_config(1, 3600));
        assert!(
            restored.is_banned("10.0.0.1").await,
            "封禁应从 fail2ban.json 恢复"
        );

        restored.unban_ip("10.0.0.1").await;
        let restored2 = Fail2BanManager::new(dir.path(), &enabled_config(1, 3600));
        assert!(!restored2.is_banned("10.0.0.1").await, "解封同样持久化");
    }

    #[tokio::test]
    async fn expired_bans_not_restored_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let list = BanList {
            banned: HashMap::from([("10.0.0.2".to_string(), Utc::now() - Duration::seconds(10))]),
        };
        std::fs::write(
            dir.path().join("fail2ban.json"),
            serde_json::to_string_pretty(&list).unwrap(),
        )
        .unwrap();

        let manager = Fail2BanManager::new(dir.path(), &enabled_config(1, 3600));
        assert!(!manager.is_banned("10.0.0.2").await);
    }
}

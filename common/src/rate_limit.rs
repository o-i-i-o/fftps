//! 限速与连接数治理（docs/design.md §4「限速/配额」「防护」）
//!
//! - 限速：以 Windows `rate_limiter.rs` 的令牌桶实现为基础，吸收 Linux `server/speed_limiter.rs`
//!   的接口（[`RateLimiter::throttle`] / [`RateLimiter::set_limit`] / [`RateLimiter::get_limit`]）；
//!   全局限速取 `FtpConfig::max_speed_kbps`，每用户限速取 `Permissions.speed_limit_kbps`，
//!   用 [`effective_speed_limit_kbps`] 合成；
//! - 连接数治理：Windows `config_types.rs::ServerConfig` 的全局/per-IP 连接计数器，
//!   限制值来自 [`crate::config::SecurityConfig::max_connections`] /
//!   [`crate::config::SecurityConfig::max_connections_per_ip`]。
//!
//! 跨平台实现（不依赖 `windows` crate）。

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, ReadBuf};

use crate::config::SecurityConfig;

const MIN_BUCKET_CAPACITY: u64 = 64 * 1024;
const MAX_BUCKET_CAPACITY: u64 = 1024 * 1024;
const REFILL_INTERVAL_MS: u64 = 10;

/// 合成全局与每用户限速（KB/s）：0 表示不限速，取两者中更严格的一个
#[must_use]
pub fn effective_speed_limit_kbps(global_kbps: u64, user_kbps: u64) -> u64 {
    match (global_kbps, user_kbps) {
        (0, user) => user,
        (global, 0) => global,
        (global, user) => global.min(user),
    }
}

/// 令牌桶限速器：后台惰性补给令牌，`acquire` 按字节数扣减（不足时异步等待）
pub struct RateLimiter {
    tokens: AtomicU64,
    last_refill: AtomicI64,
    bytes_per_second: u64,
    tokens_per_interval: u64,
    bucket_capacity: u64,
}

impl RateLimiter {
    /// 按 `speed_limit_kbps` 创建（0 = 不限速）
    #[must_use]
    pub fn new(speed_limit_kbps: u64) -> Self {
        let bytes_per_second = if speed_limit_kbps == 0 {
            u64::MAX
        } else {
            speed_limit_kbps * 1024
        };

        let bucket_capacity = if bytes_per_second == u64::MAX {
            MIN_BUCKET_CAPACITY
        } else {
            bytes_per_second.clamp(MIN_BUCKET_CAPACITY, MAX_BUCKET_CAPACITY)
        };

        let tokens_per_interval = if bytes_per_second == u64::MAX {
            0
        } else {
            (bytes_per_second / (1000 / REFILL_INTERVAL_MS)).min(bucket_capacity)
        };

        Self {
            tokens: AtomicU64::new(bucket_capacity),
            last_refill: AtomicI64::new(0),
            bytes_per_second,
            tokens_per_interval,
            bucket_capacity,
        }
    }

    /// 不限速（Linux `SpeedLimiter::with_unlimited`）
    #[must_use]
    pub fn with_unlimited() -> Self {
        Self::new(0)
    }

    /// 当前限速（KB/s，0 = 不限速）
    #[must_use]
    pub fn get_limit(&self) -> u64 {
        if self.is_unlimited() {
            0
        } else {
            self.bytes_per_second / 1024
        }
    }

    /// 动态调整限速（Linux `SpeedLimiter::set_limit`）；令牌桶按新速率重建
    pub fn set_limit(&mut self, speed_limit_kbps: u64) {
        *self = Self::new(speed_limit_kbps);
    }

    /// 是否不限速
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.bytes_per_second == u64::MAX
    }

    fn try_refill(&self) {
        if self.is_unlimited() {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));

        let last = self.last_refill.load(Ordering::Acquire);

        if now - last >= REFILL_INTERVAL_MS as i64
            && self
                .last_refill
                .compare_exchange(last, now, Ordering::SeqCst, Ordering::Acquire)
                .is_ok()
        {
            let current = self.tokens.load(Ordering::Acquire);
            let new_tokens = current
                .saturating_add(self.tokens_per_interval)
                .min(self.bucket_capacity);
            self.tokens.store(new_tokens, Ordering::Release);
        }
    }

    /// 扣减 `bytes` 字节的传输额度，令牌不足时异步等待补给
    pub async fn acquire(&self, bytes: usize) {
        if self.is_unlimited() {
            return;
        }

        let mut remaining = bytes as u64;

        while remaining > 0 {
            self.try_refill();

            let current = self.tokens.load(Ordering::Acquire);
            if current == 0 {
                let wait_ms =
                    ((remaining as f64 / self.bytes_per_second as f64) * 1000.0).ceil() as u64;
                tokio::time::sleep(Duration::from_millis(
                    wait_ms.clamp(REFILL_INTERVAL_MS, 100),
                ))
                .await;
                continue;
            }

            let to_consume = remaining.min(current);
            let actual = self.tokens.fetch_sub(to_consume, Ordering::SeqCst);
            let consumed = to_consume.min(actual);
            remaining -= consumed;

            if consumed < to_consume && actual > 0 {
                let refund = to_consume - consumed;
                self.tokens.fetch_add(refund, Ordering::SeqCst);
            }

            if remaining > 0 {
                tokio::time::sleep(Duration::from_millis(REFILL_INTERVAL_MS)).await;
            }
        }
    }

    /// Linux `SpeedLimiter::throttle` 接口：等价于 [`RateLimiter::acquire`]
    pub async fn throttle(&self, bytes: usize) {
        self.acquire(bytes).await;
    }

    /// 当前可用令牌
    #[must_use]
    pub fn get_available_tokens(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }

    /// 直接扣减令牌（不等待，下溢时补回）
    pub fn consume_tokens(&self, count: u64) {
        if self.is_unlimited() || count == 0 {
            return;
        }
        let actual = self.tokens.fetch_sub(count, Ordering::SeqCst);
        if actual < count {
            self.tokens.fetch_add(count - actual, Ordering::SeqCst);
        }
    }

    /// 令牌桶容量（字节）
    #[must_use]
    pub fn get_bucket_capacity(&self) -> u64 {
        self.bucket_capacity
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_unlimited()
    }
}

/// 传输速率统计（累计字节 → 平均速率）
#[derive(Debug)]
pub struct TransferRateTracker {
    start_time: Instant,
    total_bytes: u64,
}

impl TransferRateTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_bytes: 0,
        }
    }

    pub fn add_bytes(&mut self, bytes: u64) {
        self.total_bytes += bytes;
    }

    /// 平均速率（KB/s）
    #[must_use]
    pub fn get_rate_kbps(&self) -> u64 {
        let elapsed_secs = self.start_time.elapsed().as_secs_f64();
        if elapsed_secs > 0.0 {
            let bytes_per_sec = self.total_bytes as f64 / elapsed_secs;
            (bytes_per_sec / 1024.0) as u64
        } else {
            0
        }
    }

    #[must_use]
    pub fn get_total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub fn get_elapsed_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

impl Default for TransferRateTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// 限速配置句柄（便于按会话创建限速器）
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// KB/s，0 = 不限速
    pub speed_limit_kbps: u64,
}

impl RateLimitConfig {
    #[must_use]
    pub fn new(speed_limit_kbps: u64) -> Self {
        Self { speed_limit_kbps }
    }

    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            speed_limit_kbps: 0,
        }
    }

    #[must_use]
    pub fn create_limiter(&self) -> RateLimiter {
        RateLimiter::new(self.speed_limit_kbps)
    }
}

/// 包装 `AsyncRead` 的限速读取器
pub struct RateLimitedReader<R> {
    inner: R,
    limiter: RateLimiter,
}

impl<R> RateLimitedReader<R> {
    #[must_use]
    pub fn new(inner: R, speed_limit_kbps: u64) -> Self {
        Self {
            inner,
            limiter: RateLimiter::new(speed_limit_kbps),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for RateLimitedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let remaining = buf.remaining();
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        if self.limiter.is_unlimited() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        self.limiter.try_refill();

        let available = self.limiter.get_available_tokens() as usize;
        if available == 0 {
            let bytes_per_second = self.limiter.bytes_per_second;
            let wait_ms = ((remaining as f64 / bytes_per_second as f64) * 1000.0).ceil() as u64;
            let wait_ms = wait_ms.clamp(REFILL_INTERVAL_MS, 100);

            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(wait_ms)).await;
                waker.wake();
            });
            return Poll::Pending;
        }

        let to_read = remaining.min(available);
        let mut limited_buf = ReadBuf::new(&mut buf.initialize_unfilled()[..to_read]);

        match Pin::new(&mut self.inner).poll_read(cx, &mut limited_buf) {
            Poll::Ready(Ok(())) => {
                let n = limited_buf.filled().len();
                if n > 0 {
                    self.limiter.consume_tokens(n as u64);
                    // SAFETY：limited_buf 只读取了 inner 填充的前 n 字节，
                    // initialize_unfilled 保证目标切片已初始化
                    unsafe {
                        buf.assume_init(n);
                    }
                    buf.advance(n);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// 连接数治理（Windows config_types.rs::ServerConfig 计数器）
// ---------------------------------------------------------------------------

/// 全局 / per-IP 并发连接计数与限额（[`SecurityConfig::max_connections`] /
/// [`SecurityConfig::max_connections_per_ip`]）
#[derive(Debug)]
pub struct ConnectionLimiter {
    global_connection_count: AtomicUsize,
    connection_count_per_ip: Mutex<HashMap<String, usize>>,
    limits: Mutex<ConnectionLimits>,
}

#[derive(Debug, Clone, Copy)]
struct ConnectionLimits {
    max_connections: usize,
    max_connections_per_ip: usize,
}

impl ConnectionLimiter {
    #[must_use]
    pub fn new(security: &SecurityConfig) -> Self {
        Self {
            global_connection_count: AtomicUsize::new(0),
            connection_count_per_ip: Mutex::new(HashMap::new()),
            limits: Mutex::new(ConnectionLimits {
                max_connections: security.max_connections,
                max_connections_per_ip: security.max_connections_per_ip,
            }),
        }
    }

    /// 配置热更新
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn update_config(&self, security: &SecurityConfig) {
        let mut limits = self.limits.lock().unwrap();
        limits.max_connections = security.max_connections;
        limits.max_connections_per_ip = security.max_connections_per_ip;
    }

    /// 尝试登记一个新连接：超全局或 per-IP 上限时返回 `false`
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn try_register(&self, client_ip: &str) -> bool {
        let mut map = self.connection_count_per_ip.lock().unwrap();
        let limits = *self.limits.lock().unwrap();

        let global_count = self.global_connection_count.load(Ordering::SeqCst);
        if global_count >= limits.max_connections {
            return false;
        }

        let ip_count = map.get(client_ip).copied().unwrap_or(0);
        if ip_count >= limits.max_connections_per_ip {
            return false;
        }

        self.global_connection_count.fetch_add(1, Ordering::SeqCst);
        *map.entry(client_ip.to_string()).or_insert(0) += 1;
        true
    }

    /// 连接结束时注销（下溢受保护）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn unregister(&self, client_ip: &str) {
        let old_global = self.global_connection_count.fetch_sub(1, Ordering::SeqCst);
        if old_global == 0 {
            self.global_connection_count.fetch_add(1, Ordering::SeqCst);
            tracing::warn!("Connection count underflow prevented during unregister");
        }

        let mut map = self.connection_count_per_ip.lock().unwrap();
        if let Some(count) = map.get_mut(client_ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(client_ip);
            }
        }
    }

    /// 当前全局连接数
    #[must_use]
    pub fn get_global_count(&self) -> usize {
        self.global_connection_count.load(Ordering::SeqCst)
    }

    /// 指定 IP 的当前连接数
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub fn get_ip_count(&self, ip: &str) -> usize {
        self.connection_count_per_ip
            .lock()
            .unwrap()
            .get(ip)
            .copied()
            .unwrap_or(0)
    }

    /// 全部 IP 的连接计数
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub fn get_all_ip_counts(&self) -> HashMap<String, usize> {
        self.connection_count_per_ip.lock().unwrap().clone()
    }

    /// (全局, per-IP) 连接计数
    #[must_use]
    pub fn get_counts(&self, client_ip: &str) -> (usize, usize) {
        (self.get_global_count(), self.get_ip_count(client_ip))
    }
}

impl Default for ConnectionLimiter {
    fn default() -> Self {
        Self::new(&SecurityConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    // ---- 限速（迁移自 Windows rate_limiter.rs）----

    #[test]
    fn rate_limiter_unlimited() {
        let limiter = RateLimiter::new(0);
        assert!(limiter.is_unlimited());
        assert_eq!(limiter.get_limit(), 0);
    }

    #[test]
    fn rate_limiter_limited() {
        let limiter = RateLimiter::new(1024);
        assert!(!limiter.is_unlimited());
        assert_eq!(limiter.get_limit(), 1024);
    }

    #[test]
    fn rate_limiter_initial_tokens() {
        let limiter = RateLimiter::new(1024);
        let tokens = limiter.get_available_tokens();
        assert!(tokens > 0);
        assert!(tokens <= limiter.get_bucket_capacity());
    }

    #[test]
    fn bucket_capacity_scales_with_rate() {
        assert_eq!(RateLimiter::new(10).get_bucket_capacity(), MIN_BUCKET_CAPACITY);
        assert_eq!(
            RateLimiter::new(512).get_bucket_capacity(),
            512 * 1024,
            "中速按秒速率定容"
        );
        assert_eq!(
            RateLimiter::new(10240).get_bucket_capacity(),
            MAX_BUCKET_CAPACITY
        );
    }

    #[test]
    fn rate_limit_config_creates_limiter() {
        let config = RateLimitConfig::new(1024);
        assert_eq!(config.speed_limit_kbps, 1024);
        assert!(!config.create_limiter().is_unlimited());

        let unlimited = RateLimitConfig::unlimited();
        assert_eq!(unlimited.speed_limit_kbps, 0);
        assert!(unlimited.create_limiter().is_unlimited());
    }

    #[test]
    fn transfer_rate_tracker_accumulates() {
        let mut tracker = TransferRateTracker::new();
        assert_eq!(tracker.get_total_bytes(), 0);
        assert_eq!(tracker.get_rate_kbps(), 0);

        tracker.add_bytes(1024);
        assert_eq!(tracker.get_total_bytes(), 1024);

        let defaulted: TransferRateTracker = Default::default();
        assert_eq!(defaulted.get_total_bytes(), 0);
    }

    #[test]
    fn transfer_rate_tracker_elapsed() {
        let tracker = TransferRateTracker::new();
        std::thread::sleep(Duration::from_millis(1100));
        assert!(tracker.get_elapsed_secs() >= 1);
    }

    #[test]
    fn acquire_unlimited_returns_immediately() {
        let limiter = RateLimiter::new(0);
        block_on(limiter.acquire(1024 * 1024));
    }

    #[test]
    fn refill_keeps_tokens_within_capacity() {
        let limiter = RateLimiter::new(1024);
        let initial = limiter.get_available_tokens();
        limiter.try_refill();
        let after = limiter.get_available_tokens();
        assert!(after >= initial || after == limiter.get_bucket_capacity());
    }

    // ---- Linux SpeedLimiter 接口 ----

    #[test]
    fn speed_limiter_interface() {
        let mut limiter = RateLimiter::new(64);
        assert_eq!(limiter.get_limit(), 64);

        limiter.set_limit(256);
        assert_eq!(limiter.get_limit(), 256);

        assert_eq!(RateLimiter::default().get_limit(), 0);
        assert_eq!(RateLimiter::with_unlimited().get_limit(), 0);

        block_on(limiter.throttle(1024));
        block_on(RateLimiter::with_unlimited().throttle(10 * 1024 * 1024));
        block_on(RateLimiter::new(1).throttle(0));
    }

    // ---- 全局/每用户限速合成 ----

    #[test]
    fn effective_speed_limit_takes_stricter() {
        assert_eq!(effective_speed_limit_kbps(0, 0), 0);
        assert_eq!(effective_speed_limit_kbps(512, 0), 512);
        assert_eq!(effective_speed_limit_kbps(0, 256), 256);
        assert_eq!(effective_speed_limit_kbps(512, 256), 256);
        assert_eq!(effective_speed_limit_kbps(128, 256), 128);
    }

    // ---- 连接数治理（迁移自 Windows config_types.rs::ServerConfig）----

    #[test]
    fn connection_register_and_unregister() {
        let limiter = ConnectionLimiter::new(&SecurityConfig::default());

        assert!(limiter.try_register("1.1.1.1"));
        assert!(limiter.try_register("1.1.1.1"));
        assert_eq!(limiter.get_counts("1.1.1.1"), (2, 2));

        limiter.unregister("1.1.1.1");
        assert_eq!(limiter.get_counts("1.1.1.1"), (1, 1));

        limiter.unregister("1.1.1.1");
        assert_eq!(limiter.get_counts("1.1.1.1"), (0, 0));
        assert!(limiter.get_all_ip_counts().is_empty(), "归零的 IP 应移除");
    }

    #[test]
    fn global_limit_rejects_excess() {
        let security = SecurityConfig {
            max_connections: 2,
            max_connections_per_ip: 10,
            ..SecurityConfig::default()
        };
        let limiter = ConnectionLimiter::new(&security);

        assert!(limiter.try_register("1.1.1.1"));
        assert!(limiter.try_register("2.2.2.2"));
        assert!(!limiter.try_register("3.3.3.3"), "超全局上限应拒绝");
        assert_eq!(limiter.get_global_count(), 2);
    }

    #[test]
    fn per_ip_limit_rejects_excess() {
        let security = SecurityConfig {
            max_connections: 100,
            max_connections_per_ip: 2,
            ..SecurityConfig::default()
        };
        let limiter = ConnectionLimiter::new(&security);

        assert!(limiter.try_register("1.1.1.1"));
        assert!(limiter.try_register("1.1.1.1"));
        assert!(!limiter.try_register("1.1.1.1"), "超单 IP 上限应拒绝");
        assert!(limiter.try_register("2.2.2.2"), "其他 IP 不受影响");
    }

    #[test]
    fn update_config_changes_limits() {
        let limiter = ConnectionLimiter::new(&SecurityConfig::default());
        assert!(limiter.try_register("1.1.1.1"));
        assert!(limiter.try_register("1.1.1.1"));
        assert!(limiter.try_register("1.1.1.1"));
        assert!(limiter.try_register("1.1.1.1"));
        assert!(limiter.try_register("1.1.1.1"));

        limiter.update_config(&SecurityConfig {
            max_connections_per_ip: 1,
            ..SecurityConfig::default()
        });
        assert!(!limiter.try_register("1.1.1.1"), "收紧后的上限立即生效");
    }

    #[test]
    fn unregister_without_register_does_not_underflow() {
        let limiter = ConnectionLimiter::new(&SecurityConfig::default());
        limiter.unregister("9.9.9.9");
        assert_eq!(limiter.get_global_count(), 0);
    }

    #[test]
    fn connection_limiter_default_matches_security_defaults() {
        let limiter = ConnectionLimiter::default();
        assert!(limiter.try_register("1.1.1.1"));
        assert_eq!(limiter.get_ip_count("1.1.1.1"), 1);
    }
}

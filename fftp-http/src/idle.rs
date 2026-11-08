//! 空闲自动关闭：页面心跳 / 用户操作跟踪 + 关停信号
//!
//! 关闭范围仅为 fftp-http 自身，不触碰 fftpd。`NoPage` 模式以可见页面
//! 心跳为准（浏览器关闭、标签页隐藏后计时），`NoActivity` 模式以真实
//! 用户操作为准。后台状态轮询与 SSE 日志事件不计入活动。
//!
//! 多标签页通过 `page_id` 区分：每个可见标签页周期心跳，任一标签页可见
//! 都视为“页面存在”；隐藏或关闭后其心跳过期，页面集合自然清空。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::config::{IdleConfig, IdleMode};

/// 页面心跳过期时间（秒）：超过该时间未心跳视为页面已关闭
const PAGE_STALE_SECS: u64 = 75;

/// 关停原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// 空闲超时
    Idle,
    /// 页面/API 手动请求关闭
    Manual,
}

impl ShutdownReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ShutdownReason::Idle => "空闲超时",
            ShutdownReason::Manual => "手动关闭",
        }
    }
}

/// 空闲状态快照（`GET /api/idle` 响应）
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdleSnapshot {
    pub enabled: bool,
    pub timeout_secs: u64,
    pub mode: &'static str,
    pub warn_secs: u64,
    pub remaining_secs: u64,
    pub visible_pages: usize,
}

struct Inner {
    cfg: IdleConfig,
    last_activity: Instant,
    last_page: Instant,
    pages: HashMap<String, Instant>,
    triggered: bool,
}

/// 空闲管理器（`Arc` 共享，锁内只做内存操作）
pub struct IdleState {
    inner: Mutex<Inner>,
    shutdown_tx: watch::Sender<Option<ShutdownReason>>,
}

impl IdleState {
    /// 创建并启动看门狗任务
    pub fn new(cfg: IdleConfig, shutdown_tx: watch::Sender<Option<ShutdownReason>>) -> Arc<Self> {
        let now = Instant::now();
        let state = Arc::new(Self {
            inner: Mutex::new(Inner {
                cfg,
                last_activity: now,
                last_page: now,
                pages: HashMap::new(),
                triggered: false,
            }),
            shutdown_tx,
        });
        tokio::spawn(watchdog(Arc::clone(&state)));
        state
    }

    /// 更新配置并重置计时（保存设置后不应立即触发关闭）
    pub fn update(&self, cfg: IdleConfig) {
        let mut inner = self.inner.lock().expect("空闲状态锁中毒");
        inner.cfg = cfg;
        let now = Instant::now();
        inner.last_activity = now;
        inner.last_page = now;
        inner.triggered = false;
    }

    /// 可见页面心跳；`visible=false` 表示该标签页隐藏/关闭
    pub fn touch_page(&self, page_id: &str, visible: bool) {
        let mut inner = self.inner.lock().expect("空闲状态锁中毒");
        let now = Instant::now();
        if visible {
            inner.pages.insert(page_id.to_string(), now);
            inner.last_page = now;
        } else {
            inner.pages.remove(page_id);
        }
        inner.visible_pages_cleanup(now);
    }

    /// 真实用户操作
    pub fn touch_activity(&self) {
        self.inner.lock().expect("空闲状态锁中毒").last_activity = Instant::now();
    }

    /// 当前快照（剩余秒数按当前模式计算）
    #[must_use]
    pub fn snapshot(&self) -> IdleSnapshot {
        let mut inner = self.inner.lock().expect("空闲状态锁中毒");
        let now = Instant::now();
        inner.visible_pages_cleanup(now);
        let deadline = inner.deadline();
        IdleSnapshot {
            enabled: inner.cfg.enabled,
            timeout_secs: inner.cfg.timeout_secs,
            mode: inner.cfg.mode.as_str(),
            warn_secs: inner.cfg.warn_secs,
            remaining_secs: deadline.saturating_duration_since(now).as_secs(),
            visible_pages: inner.pages.len(),
        }
    }
}

impl Inner {
    fn deadline(&self) -> Instant {
        let base = match self.cfg.mode {
            IdleMode::NoPage => self.last_page,
            IdleMode::NoActivity => self.last_activity,
        };
        base + Duration::from_secs(self.cfg.timeout_secs)
    }

    fn visible_pages_cleanup(&mut self, now: Instant) {
        let stale = Duration::from_secs(PAGE_STALE_SECS);
        self.pages
            .retain(|_, seen| now.duration_since(*seen) < stale);
    }
}

/// 看门狗：每秒检查一次，触发后只发送一次关停信号
async fn watchdog(state: Arc<IdleState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let should_stop = {
            let mut inner = state.inner.lock().expect("空闲状态锁中毒");
            let now = Instant::now();
            inner.visible_pages_cleanup(now);
            if !inner.cfg.enabled || inner.triggered {
                false
            } else if now >= inner.deadline() {
                inner.triggered = true;
                true
            } else {
                false
            }
        };
        if should_stop {
            tracing::info!("空闲超时，关闭 fftp-http（页面/操作均超过阈值）");
            let _ = state.shutdown_tx.send(Some(ShutdownReason::Idle));
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(
        enabled: bool,
        timeout_secs: u64,
        mode: IdleMode,
    ) -> (Arc<IdleState>, watch::Receiver<Option<ShutdownReason>>) {
        let (tx, rx) = watch::channel(None);
        let state = IdleState::new(
            IdleConfig {
                enabled,
                timeout_secs,
                mode,
                warn_secs: 0,
            },
            tx,
        );
        (state, rx)
    }

    #[tokio::test]
    async fn page_visibility_and_activity_are_tracked() {
        let (state, _rx) = manager(true, 30, IdleMode::NoPage);
        state.touch_page("a", true);
        state.touch_page("b", true);
        assert_eq!(state.snapshot().visible_pages, 2);
        state.touch_page("a", false);
        assert_eq!(state.snapshot().visible_pages, 1);
        state.touch_activity();
        let snap = state.snapshot();
        assert!(snap.enabled);
        assert_eq!(snap.mode, "no_page");
        assert!(snap.remaining_secs <= 30);
    }

    #[tokio::test]
    async fn disabled_config_never_triggers() {
        let (state, rx) = manager(false, 30, IdleMode::NoPage);
        assert!(!state.snapshot().enabled);
        assert!(rx.borrow().is_none());
    }

    #[tokio::test]
    async fn update_resets_timer() {
        let (state, _rx) = manager(true, 30, IdleMode::NoActivity);
        state.update(IdleConfig {
            enabled: false,
            timeout_secs: 60,
            mode: IdleMode::NoPage,
            warn_secs: 10,
        });
        let snap = state.snapshot();
        assert!(!snap.enabled);
        assert_eq!(snap.timeout_secs, 60);
        assert_eq!(snap.mode, "no_page");
    }
}

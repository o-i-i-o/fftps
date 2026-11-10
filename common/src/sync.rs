//! 锁中毒恢复
//!
//! 项目内的 `Mutex`/`RwLock` 只保护相互独立的内存数据结构：持锁线程 panic
//! 后数据本身仍处于可继续使用的一致状态（不存在需要回滚的跨字段不变量）。
//! 因此这里统一用 [`PoisonError::into_inner`] 取回数据，而不是让 `.unwrap()`
//! 把一次局部故障级联成新的 panic（进而放大为整个服务不可用）。
//!
//! 提供 [`MutexExt`] / [`RwLockExt`] 两个扩展 trait，用法与标准库一致：
//! `lock_recover()`、`read_recover()`、`write_recover()`。

use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// `std::sync::Mutex` 的中毒恢复扩展
pub trait MutexExt<T> {
    /// 获取锁；中毒时取回内部数据继续使用
    #[must_use]
    fn lock_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> MutexExt<T> for Mutex<T> {
    fn lock_recover(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `std::sync::RwLock` 的中毒恢复扩展
pub trait RwLockExt<T> {
    /// 获取读锁；中毒时取回内部数据继续使用
    #[must_use]
    fn read_recover(&self) -> RwLockReadGuard<'_, T>;

    /// 获取写锁；中毒时取回内部数据继续使用
    #[must_use]
    fn write_recover(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T> RwLockExt<T> for RwLock<T> {
    fn read_recover(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write_recover(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::{MutexExt, RwLockExt};
    use std::sync::{Mutex, RwLock};

    #[test]
    fn recovers_poisoned_mutex() {
        let mutex = Mutex::new(1);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = mutex.lock().unwrap();
            panic!("触发中毒");
        }));
        assert!(poisoned.is_err());
        assert_eq!(*mutex.lock_recover(), 1);
    }

    #[test]
    fn recovers_poisoned_rwlock() {
        let lock = RwLock::new(2);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = lock.write().unwrap();
            panic!("触发中毒");
        }));
        assert!(poisoned.is_err());
        assert_eq!(*lock.read_recover(), 2);
        *lock.write_recover() = 3;
        assert_eq!(*lock.read_recover(), 3);
    }
}

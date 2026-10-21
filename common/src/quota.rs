//! 用户配额跟踪（docs/design.md §4「限速/配额」：Windows `quota.rs` 为基础，吸收 Linux `server/quota.rs` 的用量统计）
//!
//! - 用量统计：`used_bytes` / `reserved_bytes`（预留用于传输前占位），持久化到 `<data_dir>/quota.json`；
//! - 超限拦截：[`QuotaManager::check_quota`] 判定、[`QuotaManager::try_reserve_quota`] 预留；
//! - 目录用量扫描：[`dir_size`]（同步）与 [`calculate_usage_async`]（阻塞线程池，吸收 Linux `QuotaCache` 接口）。
//!
//! 跨平台实现（不依赖 `windows` crate）。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// 单个用户的配额用量
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuotaUsage {
    /// 已用字节数
    pub used_bytes: u64,
    /// 传输中预留的字节数
    pub reserved_bytes: u64,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// 持久化的配额数据（`quota.json`）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuotaData {
    pub users: HashMap<String, QuotaUsage>,
}

/// 用户配额管理器：原子化记账 + 惰性落盘
#[derive(Debug)]
pub struct QuotaManager {
    data_path: PathBuf,
    data: Mutex<QuotaData>,
    dirty: AtomicBool,
}

impl QuotaManager {
    /// 在 `data_dir` 下读取/初始化 `quota.json`
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        let data_path = data_dir.join("quota.json");
        let data = Self::load_data(&data_path).unwrap_or_default();

        Self {
            data_path,
            data: Mutex::new(data),
            dirty: AtomicBool::new(false),
        }
    }

    fn load_data(path: &Path) -> anyhow::Result<QuotaData> {
        if !path.exists() {
            return Ok(QuotaData::default());
        }

        let content = std::fs::read_to_string(path)?;
        if content.trim().is_empty() {
            return Ok(QuotaData::default());
        }

        Ok(serde_json::from_str(&content)?)
    }

    /// # Panics
    /// 内部互斥锁中毒（持有线程 panic）时 panic
    fn save_data(&self) -> anyhow::Result<()> {
        let data = self.data.lock().unwrap();
        if let Some(parent) = self.data_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&*data)?;
        std::fs::write(&self.data_path, content)?;
        self.dirty.store(false, Ordering::Release);
        Ok(())
    }

    /// 有未落盘的变更时写入 `quota.json`
    ///
    /// # Errors
    /// 写文件失败时返回错误
    pub fn flush_if_dirty(&self) -> anyhow::Result<()> {
        if self.dirty.load(Ordering::Acquire) {
            self.save_data()
        } else {
            Ok(())
        }
    }

    /// 无条件写入 `quota.json`
    ///
    /// # Errors
    /// 写文件失败时返回错误
    pub fn force_flush(&self) -> anyhow::Result<()> {
        self.save_data()
    }

    /// 当前用量（字节）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub fn get_usage(&self, username: &str) -> u64 {
        self.data
            .lock()
            .unwrap()
            .users
            .get(username)
            .map_or(0, |u| u.used_bytes)
    }

    /// 当前预留（字节）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub fn get_reserved(&self, username: &str) -> u64 {
        self.data
            .lock()
            .unwrap()
            .users
            .get(username)
            .map_or(0, |u| u.reserved_bytes)
    }

    /// 追加 `additional_bytes` 后是否仍在配额 `quota_mb` 内（0 = 不限）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub fn check_quota(&self, username: &str, quota_mb: u64, additional_bytes: u64) -> bool {
        let data = self.data.lock().unwrap();
        let usage = data.users.get(username);
        let used = usage.map_or(0, |u| u.used_bytes);
        let reserved = usage.map_or(0, |u| u.reserved_bytes);

        let quota_bytes = quota_mb.saturating_mul(1024 * 1024);
        let total = used
            .saturating_add(reserved)
            .saturating_add(additional_bytes);
        quota_mb == 0 || total <= quota_bytes
    }

    /// 尝试预留 `bytes`；超出配额返回 `false`，否则计入预留并返回 `true`
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn try_reserve_quota(&self, username: &str, bytes: u64, quota_mb: u64) -> bool {
        let mut data = self.data.lock().unwrap();
        let quota_bytes = quota_mb.saturating_mul(1024 * 1024);

        let usage = data.users.entry(username.to_string()).or_default();
        let total = usage
            .used_bytes
            .saturating_add(usage.reserved_bytes)
            .saturating_add(bytes);

        if quota_mb != 0 && total > quota_bytes {
            return false;
        }

        usage.reserved_bytes = usage.reserved_bytes.saturating_add(bytes);
        usage.last_updated = chrono::Utc::now();
        self.dirty.store(true, Ordering::Release);

        true
    }

    /// 传输完成：释放 `reserved_bytes` 预留，把 `actual_bytes` 计入用量
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn commit_usage(&self, username: &str, reserved_bytes: u64, actual_bytes: u64) {
        let mut data = self.data.lock().unwrap();
        if let Some(usage) = data.users.get_mut(username) {
            usage.reserved_bytes = usage.reserved_bytes.saturating_sub(reserved_bytes);
            usage.used_bytes = usage.used_bytes.saturating_add(actual_bytes);
            usage.last_updated = chrono::Utc::now();
            self.dirty.store(true, Ordering::Release);
        }
    }

    /// 传输取消：回滚预留
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn rollback_reservation(&self, username: &str, bytes: u64) {
        let mut data = self.data.lock().unwrap();
        if let Some(usage) = data.users.get_mut(username) {
            usage.reserved_bytes = usage.reserved_bytes.saturating_sub(bytes);
            usage.last_updated = chrono::Utc::now();
            self.dirty.store(true, Ordering::Release);
        }
    }

    /// 直接累加用量（无预留流程的小操作）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn add_usage(&self, username: &str, bytes: u64) {
        let mut data = self.data.lock().unwrap();
        let usage = data.users.entry(username.to_string()).or_default();
        usage.used_bytes = usage.used_bytes.saturating_add(bytes);
        usage.last_updated = chrono::Utc::now();
        self.dirty.store(true, Ordering::Release);
    }

    /// 扣减用量（下溢饱和到 0）
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn subtract_usage(&self, username: &str, bytes: u64) {
        let mut data = self.data.lock().unwrap();
        if let Some(usage) = data.users.get_mut(username) {
            usage.used_bytes = usage.used_bytes.saturating_sub(bytes);
            usage.last_updated = chrono::Utc::now();
            self.dirty.store(true, Ordering::Release);
        }
    }

    /// 清除用户的配额记录
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    pub fn reset_usage(&self, username: &str) {
        let mut data = self.data.lock().unwrap();
        if data.users.remove(username).is_some() {
            self.dirty.store(true, Ordering::Release);
        }
    }

    /// 重新扫描 `home_dir` 计算实际用量（同时清空预留）
    ///
    /// # Errors
    /// 目录遍历失败时返回错误
    pub fn recalculate_usage(&self, username: &str, home_dir: &Path) -> anyhow::Result<u64> {
        let total_size = dir_size(home_dir)?;

        {
            let mut data = self.data.lock().unwrap();
            let usage = data.users.entry(username.to_string()).or_default();
            usage.used_bytes = total_size;
            usage.reserved_bytes = 0;
            usage.last_updated = chrono::Utc::now();
        }
        self.dirty.store(true, Ordering::Release);
        Ok(total_size)
    }

    /// 全部用户的用量
    ///
    /// # Panics
    /// 内部互斥锁中毒时 panic
    #[must_use]
    pub fn get_all_usage(&self) -> HashMap<String, QuotaUsage> {
        self.data.lock().unwrap().users.clone()
    }
}

/// 递归统计目录（或单文件）占用的字节数
///
/// # Errors
/// 元数据读取或目录遍历失败时返回错误
pub fn dir_size(path: &Path) -> anyhow::Result<u64> {
    let mut total_size = 0u64;

    if path.is_file() {
        return Ok(std::fs::metadata(path)?.len());
    }

    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                total_size = total_size.saturating_add(dir_size(&entry_path)?);
            } else {
                total_size = total_size.saturating_add(entry.metadata()?.len());
            }
        }
    }

    Ok(total_size)
}

/// 异步统计目录用量：目录遍历放入阻塞线程池，失败按 0 计
/// （吸收 Linux `server/quota.rs::QuotaCache::calculate_usage_async`）
pub async fn calculate_usage_async(home_dir: &Path) -> u64 {
    let path = home_dir.to_path_buf();
    tokio::task::spawn_blocking(move || dir_size(&path))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0)
}

/// 人类可读的字节数格式化（整数运算出两位小数，避免精度告警）
#[must_use]
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    fn unit(bytes: u64, unit: u64) -> String {
        format!("{}.{:02}", bytes / unit, (bytes % unit) * 100 / unit)
    }

    if bytes >= GB {
        format!("{} GB", unit(bytes, GB))
    } else if bytes >= MB {
        format!("{} MB", unit(bytes, MB))
    } else if bytes >= KB {
        format!("{} KB", unit(bytes, KB))
    } else {
        format!("{bytes} B")
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

    fn write_file(path: &Path, bytes: usize) {
        std::fs::write(path, vec![0u8; bytes]).unwrap();
    }

    // ---- 用量记账（迁移自 Windows quota.rs）----

    #[test]
    fn new_manager_reports_zero() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());
        assert_eq!(manager.get_usage("testuser"), 0);
    }

    #[test]
    fn add_usage_accumulates() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        manager.add_usage("testuser", 1024);
        assert_eq!(manager.get_usage("testuser"), 1024);

        manager.add_usage("testuser", 2048);
        assert_eq!(manager.get_usage("testuser"), 3072);
    }

    #[test]
    fn subtract_usage_saturates_at_zero() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        manager.add_usage("testuser", 100);
        manager.subtract_usage("testuser", 200);
        assert_eq!(manager.get_usage("testuser"), 0);
    }

    #[test]
    fn reset_usage_removes_record() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        manager.add_usage("testuser", 1024);
        manager.reset_usage("testuser");
        assert_eq!(manager.get_usage("testuser"), 0);
    }

    #[test]
    fn check_quota_blocks_over_limit() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        manager.add_usage("testuser", 500 * 1024 * 1024);

        assert!(manager.check_quota("testuser", 1024, 100 * 1024 * 1024));
        assert!(!manager.check_quota("testuser", 1024, 600 * 1024 * 1024));
    }

    #[test]
    fn zero_quota_means_unlimited() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        manager.add_usage("testuser", 10 * 1024 * 1024);
        assert!(manager.check_quota("testuser", 0, u64::MAX / 2));
        assert!(manager.try_reserve_quota("testuser", 1024 * 1024, 0));
    }

    #[test]
    fn try_reserve_quota_reserves_then_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        let reserve_bytes = 5 * 1024 * 1024;
        assert!(manager.try_reserve_quota("testuser", reserve_bytes, 10));
        assert_eq!(manager.get_reserved("testuser"), reserve_bytes);

        assert!(!manager.try_reserve_quota("testuser", 10 * 1024 * 1024, 10));
    }

    #[test]
    fn commit_usage_moves_reserved_to_used() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        let reserve_bytes = 5 * 1024 * 1024;
        assert!(manager.try_reserve_quota("testuser", reserve_bytes, 10));

        let actual_bytes = 4 * 1024 * 1024;
        manager.commit_usage("testuser", reserve_bytes, actual_bytes);

        assert_eq!(manager.get_usage("testuser"), actual_bytes);
        assert_eq!(manager.get_reserved("testuser"), 0);
    }

    #[test]
    fn rollback_reservation_frees_reserved() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        let reserve_bytes = 5 * 1024 * 1024;
        assert!(manager.try_reserve_quota("testuser", reserve_bytes, 10));
        manager.rollback_reservation("testuser", reserve_bytes);
        assert_eq!(manager.get_reserved("testuser"), 0);
    }

    #[test]
    fn get_all_usage_lists_users() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        manager.add_usage("user1", 1024);
        manager.add_usage("user2", 2048);

        let all = manager.get_all_usage();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("user1").unwrap().used_bytes, 1024);
        assert_eq!(all.get("user2").unwrap().used_bytes, 2048);
    }

    #[test]
    fn flush_and_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();

        {
            let manager = QuotaManager::new(dir.path());
            manager.add_usage("testuser", 4096);
            manager.flush_if_dirty().unwrap();
            manager.force_flush().unwrap();
        }

        let manager2 = QuotaManager::new(dir.path());
        assert_eq!(manager2.get_usage("testuser"), 4096);
    }

    #[test]
    fn multiple_users_tracked_separately() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());

        for i in 0..5 {
            manager.add_usage(&format!("user{i}"), (i + 1) * 100);
        }

        let all = manager.get_all_usage();
        assert_eq!(all.len(), 5);
        for i in 0..5 {
            assert_eq!(all.get(&format!("user{i}")).unwrap().used_bytes, (i + 1) * 100);
        }
    }

    // ---- 目录用量统计（吸收 Linux server/quota.rs）----

    #[test]
    fn usage_sums_files_recursively() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("a.txt"), 100);
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        write_file(&dir.path().join("sub/b.txt"), 50);

        assert_eq!(block_on(calculate_usage_async(dir.path())), 150);
    }

    #[test]
    fn usage_of_single_file_is_its_size() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("only.txt");
        write_file(&file, 42);

        assert_eq!(block_on(calculate_usage_async(&file)), 42);
    }

    #[test]
    fn usage_of_missing_path_is_zero() {
        assert_eq!(
            block_on(calculate_usage_async(Path::new("/nonexistent/fftpd/dir"))),
            0
        );
    }

    #[test]
    fn empty_dir_has_zero_usage() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(block_on(calculate_usage_async(dir.path())), 0);
    }

    #[test]
    fn recalculate_usage_scans_home_dir() {
        let dir = tempfile::tempdir().unwrap();
        let manager = QuotaManager::new(dir.path());
        manager.add_usage("u", 999_999);

        write_file(&dir.path().join("x.txt"), 10);
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        write_file(&dir.path().join("sub/y.txt"), 20);

        assert_eq!(manager.recalculate_usage("u", dir.path()).unwrap(), 30);
        assert_eq!(manager.get_usage("u"), 30);
    }

    // ---- 格式化 ----

    #[test]
    fn format_size_units() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(2 * 1024 * 1024), "2.00 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_size(2 * 1024 * 1024 * 1024), "2.00 GB");
    }
}

//! SFTP 会话状态
//!
//! 每个 SFTP 子系统通道持有一份 [`SftpState`]：cwd/home、权限缓存、限速器、
//! 打开句柄、锁文件集合与路径解析入口。对接 `fftp-common` 的用户库、配额、
//! 限速与审计日志，不重复实现这些能力。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use fftp_common::logging::{FileOpLogEntry, Logging};
use fftp_common::quota::QuotaManager;
use fftp_common::rate_limit::RateLimiter;
use fftp_common::users::{Permissions, UserManager};

use crate::path_resolve::{self, PathResolveError};
use crate::protocol;
use crate::types::{HANDLE_TIMEOUT_SECS, SftpFileHandle};

/// 权限缓存有效期
const PERMISSION_CACHE_TTL: Duration = Duration::from_secs(30);

/// SFTP 会话状态
pub struct SftpState {
    /// 用户 home（服务器绝对路径，会话级 jail 根）
    pub home_dir: String,
    /// 会话当前目录（服务器绝对路径）
    pub cwd: String,
    pub username: Option<String>,
    pub user_manager: Arc<StdMutex<UserManager>>,
    pub quota_manager: Arc<QuotaManager>,
    /// 文件操作审计（`fftp-common` 日志设施，可选）
    pub logging: Option<Arc<Logging>>,
    /// 打开的文件/目录句柄
    pub handles: HashMap<String, SftpFileHandle>,
    pub next_handle_id: u32,
    /// 协商后的 SFTP 版本
    pub sftp_version: u32,
    /// 粘包缓冲
    pub buffer: Vec<u8>,
    /// 持有 LOCK 的文件集合
    pub locked_files: HashSet<PathBuf>,
    pub client_ip: String,
    pub cached_permissions: Option<Permissions>,
    /// 用户级传输限速器（`speed_limit_kbps` 为 0/未设置时为 None）
    pub rate_limiter: Option<RateLimiter>,
    pub cache_expiry: Option<Instant>,
    pub last_handle_cleanup: Instant,
    /// 是否允许跟随符号链接（`security.allow_symlinks`）
    pub allow_symlinks: bool,
}

impl SftpState {
    /// 创建会话状态并初始化权限缓存与限速器
    #[must_use]
    pub fn new(
        home_dir: String,
        username: Option<String>,
        user_manager: Arc<StdMutex<UserManager>>,
        quota_manager: Arc<QuotaManager>,
        logging: Option<Arc<Logging>>,
        client_ip: String,
        allow_symlinks: bool,
    ) -> Self {
        let mut state = SftpState {
            home_dir: home_dir.clone(),
            cwd: home_dir,
            username,
            user_manager,
            quota_manager,
            logging,
            handles: HashMap::new(),
            next_handle_id: 0,
            sftp_version: 3,
            buffer: Vec::new(),
            locked_files: HashSet::new(),
            client_ip,
            cached_permissions: None,
            rate_limiter: None,
            cache_expiry: None,
            last_handle_cleanup: Instant::now(),
            allow_symlinks,
        };
        state.cache_permissions();
        state.init_rate_limiter();
        state
    }

    /// 审计/配额日志里的用户名（未认证兜底 anonymous）
    #[must_use]
    pub fn audit_user(&self) -> &str {
        self.username.as_deref().unwrap_or("anonymous")
    }

    /// 检查当前用户权限（带 30s 缓存）
    ///
    /// # Panics
    /// 内部用户库互斥锁中毒时 panic（`fftp-common` 语义）
    pub fn check_permission(&mut self, check_fn: impl Fn(&Permissions) -> bool) -> bool {
        if let Some(expiry) = self.cache_expiry
            && expiry < Instant::now()
        {
            self.cached_permissions = None;
            self.cache_permissions();
        }

        if let Some(perms) = &self.cached_permissions {
            return check_fn(perms);
        }

        if let Some(username) = &self.username {
            let users = self.user_manager.lock().unwrap();
            if let Some(user) = users.get_user(username) {
                check_fn(&user.permissions)
            } else {
                false
            }
        } else {
            false
        }
    }

    /// 重新加载权限缓存
    ///
    /// # Panics
    /// 内部用户库互斥锁中毒时 panic
    pub fn cache_permissions(&mut self) {
        if let Some(username) = &self.username {
            let users = self.user_manager.lock().unwrap();
            if let Some(user) = users.get_user(username) {
                self.cached_permissions = Some(user.permissions);
                self.cache_expiry = Some(Instant::now() + PERMISSION_CACHE_TTL);
            }
        }
    }

    /// 强制刷新权限缓存（配置/用户变更后调用）
    pub fn refresh_permissions(&mut self) {
        self.cached_permissions = None;
        self.cache_permissions();
    }

    /// 按用户 `speed_limit_kbps` 初始化限速器
    pub fn init_rate_limiter(&mut self) {
        if let Some(perms) = &self.cached_permissions
            && let Some(speed_kbps) = perms.speed_limit_kbps
        {
            self.rate_limiter = Some(RateLimiter::new(speed_kbps));
        }
    }

    /// 路径解析失败时转成 `SSH_FXP_STATUS` 应答
    ///
    /// # Errors
    /// 返回可直接回给客户端的 `SSH_FXP_STATUS` 报文（长度前缀完整）
    pub fn resolve_path_checked(&self, id: u32, path: &str) -> Result<PathBuf, Vec<u8>> {
        self.resolve_path(path)
            .map_err(|e| Self::resolve_error_packet(id, path, e))
    }

    /// 不跟随符号链接的路径解析（LSTAT / READLINK）：
    /// 父目录链按 [`Self::resolve_path`] 严格校验，末段文件名原样保留，
    /// 使符号链接自身可被检查而不是被解析成链接目标。
    ///
    /// # Errors
    /// 同 [`Self::resolve_path`]；路径不含末段文件名（如 `/`）时按整体解析
    pub fn resolve_path_no_follow(&self, path: &str) -> Result<PathBuf, PathResolveError> {
        let p = Path::new(path);
        if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
            let parent_str = parent.to_string_lossy();
            let base = self.resolve_path(if parent_str.is_empty() {
                "."
            } else {
                parent_str.as_ref()
            })?;
            return Ok(base.join(name));
        }
        self.resolve_path(path)
    }

    /// [`Self::resolve_path_no_follow`] 的报文化包装
    ///
    /// # Errors
    /// 返回可直接回给客户端的 `SSH_FXP_STATUS` 报文（长度前缀完整）
    pub fn resolve_path_no_follow_checked(&self, id: u32, path: &str) -> Result<PathBuf, Vec<u8>> {
        self.resolve_path_no_follow(path)
            .map_err(|e| Self::resolve_error_packet(id, path, e))
    }

    /// 路径解析错误 → `SSH_FXP_STATUS` 应答
    fn resolve_error_packet(id: u32, path: &str, e: PathResolveError) -> Vec<u8> {
        tracing::warn!("Path resolve failed for '{path}': {e}");
        protocol::build_status_packet(
            id,
            crate::types::SSH_FX_NO_SUCH_FILE,
            &e.to_string(),
            "",
        )
    }

    /// 符号链接必须指向 home 之内（rename/symlink 场景的二次校验）
    ///
    /// # Errors
    /// 返回可直接回给客户端的 `SSH_FXP_STATUS` 报文
    pub async fn check_symlink_in_home(&self, id: u32, path: &Path) -> Result<(), Vec<u8>> {
        if !path.is_symlink() {
            return Ok(());
        }
        match tokio::fs::read_link(path).await {
            Ok(link_target) => {
                let resolved = if link_target.is_absolute() {
                    link_target
                } else {
                    let parent = path
                        .parent()
                        .unwrap_or_else(|| Path::new(&self.home_dir));
                    parent.join(&link_target)
                };
                match resolved.canonicalize() {
                    Ok(canon) => {
                        let home = PathBuf::from(&self.home_dir);
                        if !crate::path_resolve::path_starts_with_ignore_case(&canon, &home) {
                            tracing::warn!("Symlink points outside home: {path:?} -> {canon:?}");
                            return Err(protocol::build_status_packet(
                                id,
                                crate::types::SSH_FX_PERMISSION_DENIED,
                                "Permission denied: symlink target outside home",
                                "",
                            ));
                        }
                        Ok(())
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Symlink target cannot be resolved (rejecting for security): \
                             {path:?} -> {resolved:?}, error: {e}"
                        );
                        Err(protocol::build_status_packet(
                            id,
                            crate::types::SSH_FX_PERMISSION_DENIED,
                            "Permission denied: symlink target cannot be resolved",
                            "",
                        ))
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Cannot read symlink {path:?}: {e}");
                Err(protocol::build_status_packet(
                    id,
                    crate::types::SSH_FX_FAILURE,
                    "Failed to read symlink",
                    "",
                ))
            }
        }
    }

    /// 会话结束清理：关闭句柄并释放锁
    pub fn cleanup(&mut self) {
        for (_, handle) in self.handles.drain() {
            if let SftpFileHandle::File { locked, path, .. } = handle
                && locked
            {
                tracing::info!("Releasing lock on {path:?} during cleanup");
                self.locked_files.remove(&path);
            }
        }
        self.locked_files.clear();
        tracing::info!("SFTP session cleanup completed");
    }

    /// 回收超时未访问的句柄（刷新文件数据并释放锁）
    pub async fn cleanup_expired_handles(&mut self) {
        let timeout = Duration::from_secs(HANDLE_TIMEOUT_SECS);
        let expired: Vec<String> = self
            .handles
            .iter()
            .filter(|(_, h)| match h {
                SftpFileHandle::File { last_access, .. }
                | SftpFileHandle::Dir { last_access, .. } => last_access.elapsed() > timeout,
            })
            .map(|(k, _)| k.clone())
            .collect();

        for handle_key in expired {
            if let Some(handle) = self.handles.remove(&handle_key) {
                match handle {
                    SftpFileHandle::File {
                        locked,
                        path,
                        mut file,
                        ..
                    } => {
                        use tokio::io::AsyncWriteExt;
                        if let Err(e) = file.flush().await {
                            tracing::warn!("Failed to flush file {path:?} on handle expiry: {e}");
                        }
                        if locked {
                            self.locked_files.remove(&path);
                        }
                        tracing::info!(
                            "SFTP handle expired and closed: {path:?} (handle={handle_key})"
                        );
                    }
                    SftpFileHandle::Dir { path, .. } => {
                        tracing::info!(
                            "SFTP dir handle expired and closed: {path:?} (handle={handle_key})"
                        );
                    }
                }
            }
        }
    }

    /// 客户端路径 → home 内服务器绝对路径（jail）
    ///
    /// # Errors
    /// 越狱/非法路径时返回 [`PathResolveError`]
    pub fn resolve_path(&self, path: &str) -> Result<PathBuf, PathResolveError> {
        path_resolve::safe_resolve_path(&self.cwd, &self.home_dir, path, self.allow_symlinks)
    }

    /// 生成递增句柄名（32 位回绕）
    pub fn generate_handle(&mut self) -> String {
        let handle = format!("h{:08x}", self.next_handle_id);
        self.next_handle_id = self.next_handle_id.wrapping_add(1);
        handle
    }

    /// 写一条文件操作审计（`UPLOAD`/`DELETE`/... 单路径操作）
    pub fn audit_file_op(&self, operation: &str, file_path: &str, file_size: u64) {
        self.write_file_op(&FileOpLogEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            username: self.audit_user().to_string(),
            client_ip: self.client_ip.clone(),
            operation: operation.to_string(),
            file_path: file_path.to_string(),
            file_size,
            protocol: "SFTP".to_string(),
            success: true,
            message: String::new(),
        });
    }

    /// 写一条文件操作审计（`RENAME`/`MOVE`/`COPY`/... 双路径操作）
    pub fn audit_file_op_pair(
        &self,
        operation: &str,
        from: &str,
        to: &str,
        file_size: u64,
        message: &str,
    ) {
        self.write_file_op(&FileOpLogEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            username: self.audit_user().to_string(),
            client_ip: self.client_ip.clone(),
            operation: operation.to_string(),
            file_path: format!("{from} -> {to}"),
            file_size,
            protocol: "SFTP".to_string(),
            success: true,
            message: message.to_string(),
        });
    }

    fn write_file_op(&self, entry: &FileOpLogEntry) {
        if let Some(logging) = &self.logging {
            logging.write_file_op(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fftp_common::quota::QuotaManager;
    use fftp_common::users::{Permissions, User, UserManager};
    use std::sync::Arc;

    fn create_test_sftp_state(dir: &Path) -> SftpState {
        let mut users = UserManager::new();
        let mut perms = Permissions::full();
        perms.quota_mb = Some(10);
        let _ = users.add_user(
            "testuser".to_string(),
            "pw",
            dir.to_string_lossy().to_string(),
            perms,
            false,
        );
        SftpState::new(
            dir.to_string_lossy().to_string(),
            Some("testuser".to_string()),
            Arc::new(StdMutex::new(users)),
            Arc::new(QuotaManager::new(&std::env::temp_dir())),
            None,
            "127.0.0.1".to_string(),
            false,
        )
    }

    #[test]
    fn test_sftp_state_initial() {
        let dir = tempfile::tempdir().unwrap();
        let state = create_test_sftp_state(dir.path());
        assert_eq!(state.home_dir, dir.path().to_string_lossy());
        assert_eq!(state.cwd, dir.path().to_string_lossy());
        assert_eq!(state.username, Some("testuser".to_string()));
        assert!(state.handles.is_empty());
        assert_eq!(state.next_handle_id, 0);
        assert_eq!(state.sftp_version, 3);
        assert_eq!(state.buffer, Vec::<u8>::new());
        assert!(state.locked_files.is_empty());
        assert_eq!(state.client_ip, "127.0.0.1");
    }

    #[test]
    fn test_generate_handle_sequential() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = create_test_sftp_state(dir.path());
        assert_eq!(state.generate_handle(), "h00000000");
        assert_eq!(state.generate_handle(), "h00000001");
        assert_eq!(state.generate_handle(), "h00000002");
    }

    #[test]
    fn test_generate_handle_wrapping() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = create_test_sftp_state(dir.path());
        state.next_handle_id = u32::MAX;
        assert_eq!(state.generate_handle(), "hffffffff");
        assert_eq!(state.generate_handle(), "h00000000");
    }

    #[test]
    fn test_check_permission_cached() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = create_test_sftp_state(dir.path());
        assert!(state.check_permission(|p| p.can_read && p.can_write));

        // 缓存路径：直接换受限权限，不再查用户库
        let mut restricted = Permissions::full();
        restricted.can_mkdir = false;
        restricted.can_rmdir = false;
        restricted.can_rename = false;
        state.cached_permissions = Some(restricted);
        assert!(!state.check_permission(|p| p.can_mkdir && p.can_rmdir && p.can_rename));
    }

    #[test]
    fn test_check_permission_unknown_user_denied() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = SftpState::new(
            dir.path().to_string_lossy().to_string(),
            Some("ghost".to_string()),
            Arc::new(StdMutex::new(UserManager::new())),
            Arc::new(QuotaManager::new(&std::env::temp_dir())),
            None,
            "127.0.0.1".to_string(),
            false,
        );
        assert!(!state.check_permission(|p| p.can_read));
    }

    #[test]
    fn test_resolve_path_checked_error_packet() {
        let dir = tempfile::tempdir().unwrap();
        let state = create_test_sftp_state(dir.path());
        let err = state.resolve_path_checked(7, "/../escape").unwrap_err();
        // 应答带 4 字节长度前缀：SSH_FXP_STATUS + id + 状态码
        let payload = &err[4..];
        assert_eq!(payload[0], crate::types::SSH_FXP_STATUS);
        let id = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        assert_eq!(id, 7);
    }

    #[test]
    fn test_rate_limiter_init_from_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let mut users = UserManager::new();
        let mut perms = Permissions::full();
        perms.speed_limit_kbps = Some(64);
        let _ = users.add_user(
            "limited".to_string(),
            "pw",
            dir.path().to_string_lossy().to_string(),
            perms,
            false,
        );
        let mut state = SftpState::new(
            dir.path().to_string_lossy().to_string(),
            Some("limited".to_string()),
            Arc::new(StdMutex::new(users)),
            Arc::new(QuotaManager::new(&std::env::temp_dir())),
            None,
            "127.0.0.1".to_string(),
            false,
        );
        assert!(state.rate_limiter.is_some());
        assert_eq!(state.rate_limiter.as_ref().map(RateLimiter::get_limit), Some(64));

        // 无速度限制 → 无限速器
        state.cached_permissions = Some(Permissions::full());
        state.rate_limiter = None;
        state.init_rate_limiter();
        assert!(state.rate_limiter.is_none());
    }

    #[test]
    fn test_cleanup_releases_locks() {
        use crate::types::SftpFileHandle;
        let dir = tempfile::tempdir().unwrap();
        let mut state = create_test_sftp_state(dir.path());
        let path = dir.path().join("locked.txt");
        let file = std::fs::File::create(&path).unwrap();
        state.handles.insert(
            "h00000000".to_string(),
            SftpFileHandle::File {
                path: path.clone(),
                file: tokio::fs::File::from_std(file),
                locked: true,
                existed: true,
                written_bytes: 0,
                read_bytes: 0,
                pending_flush_bytes: 0,
                last_access: Instant::now(),
                quota_reserved: 0,
                original_size: 0,
            },
        );
        state.locked_files.insert(path);
        state.cleanup();
        assert!(state.handles.is_empty());
        assert!(state.locked_files.is_empty());
    }

    #[test]
    fn test_audit_user_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let mut users = UserManager::new();
        let _ = users.add_user(
            "u".to_string(),
            "pw",
            dir.path().to_string_lossy().to_string(),
            Permissions::full(),
            false,
        );
        let state = SftpState::new(
            dir.path().to_string_lossy().to_string(),
            None,
            Arc::new(StdMutex::new(users)),
            Arc::new(QuotaManager::new(&std::env::temp_dir())),
            None,
            "127.0.0.1".to_string(),
            false,
        );
        assert_eq!(state.audit_user(), "anonymous");
    }

    #[test]
    fn test_user_struct_roundtrip_fields() {
        // 用户库字段与会话缓存联动的最小验证
        let dir = tempfile::tempdir().unwrap();
        let mut users = UserManager::new();
        users
            .add_user(
                "alice".to_string(),
                "pw",
                dir.path().to_string_lossy().to_string(),
                Permissions::full(),
                true,
            )
            .unwrap();
        let user: &User = users.get_user("alice").unwrap();
        assert!(user.enabled);
        assert!(user.is_admin);
    }
}

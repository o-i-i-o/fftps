//! 用户库（users.json，docs/design.md §5.2）
//!
//! 口令哈希为 Argon2id PHC 字符串，策略 `m=65536,t=3,p=4,len=32`；
//! 登录成功时若既有哈希低于当前策略（旧参数/旧版本/旧算法），惰性重哈希升级。

use anyhow::{Context, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub home_dir: String,
    pub permissions: Permissions,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub is_admin: bool,
}

/// 权限位集合；字段数量经 clippy.toml 的 `max-struct-bools` 阈值豁免
///
/// 序列化形态即 users.json 的用户权限字段，不能随意重构。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Permissions {
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
    pub can_list: bool,
    pub can_mkdir: bool,
    pub can_rmdir: bool,
    pub can_rename: bool,
    pub can_append: bool,
    pub quota_mb: Option<u64>,
    pub speed_limit_kbps: Option<u64>,
}

impl Permissions {
    #[must_use]
    pub fn full() -> Self {
        Permissions {
            can_read: true,
            can_write: true,
            can_delete: true,
            can_list: true,
            can_mkdir: true,
            can_rmdir: true,
            can_rename: true,
            can_append: true,
            quota_mb: None,
            speed_limit_kbps: None,
        }
    }
}

/// 校验用户名是否安全：仅允许字母数字、下划线与连字符，首位须为字母数字或下划线，
/// 长度 1..=64。用于认证前拦截非法输入（FTP USER 命令 / SSH 认证请求）。
#[must_use]
pub fn is_safe_username(username: &str) -> bool {
    if username.is_empty() || username.len() > 64 {
        return false;
    }
    let bytes = username.as_bytes();
    let first = bytes[0];
    if !first.is_ascii_alphanumeric() && first != b'_' {
        return false;
    }
    bytes
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut perms = Vec::new();
        if self.can_read {
            perms.push("读");
        }
        if self.can_write {
            perms.push("写");
        }
        if self.can_delete {
            perms.push("删");
        }
        if self.can_list {
            perms.push("列表");
        }
        if self.can_mkdir {
            perms.push("建目录");
        }
        if self.can_rmdir {
            perms.push("删目录");
        }
        if self.can_rename {
            perms.push("重命名");
        }
        if self.can_append {
            perms.push("追加");
        }
        write!(f, "{}", perms.join(", "))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserManager {
    users: HashMap<String, User>,
}

impl UserManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 从 JSON 文件加载用户库
    ///
    /// 文件缺失、为空、读取失败或解析失败时均回退为空用户库并记录日志，
    /// 不视为致命错误。
    ///
    /// # Errors
    /// 当前实现不会返回 `Err`；保留 `Result` 签名以便未来引入可恢复错误
    pub fn load(path: &Path) -> Result<Self> {
        debug!("[UserManager] 尝试加载用户配置文件：{:?}", path);

        if !path.exists() {
            warn!(
                "[UserManager] 用户配置文件不存在：{:?}，将创建空用户管理器",
                path
            );
            return Ok(Self::new());
        }

        info!("[UserManager] 用户配置文件存在，开始读取：{:?}", path);

        let content = match fs::read_to_string(path) {
            Ok(c) => {
                debug!("[UserManager] 成功读取用户配置文件，大小：{} 字节", c.len());
                c
            }
            Err(e) => {
                error!("[UserManager] 读取用户配置文件失败：{} - {:?}", e, path);
                eprintln!("Warning: Failed to read users file: {e}");
                return Ok(Self::new());
            }
        };

        if content.trim().is_empty() {
            warn!("[UserManager] 用户配置文件内容为空：{:?}", path);
            return Ok(Self::new());
        }

        debug!("[UserManager] 开始解析 JSON 内容...");
        let manager: UserManager = serde_json::from_str(&content).unwrap_or_else(|e| {
            error!(
                "[UserManager] 解析用户配置文件 JSON 失败：{} - 内容预览：{}",
                e,
                &content[..content.len().min(200)]
            );
            eprintln!("Warning: Failed to parse users file: {e}");
            UserManager::new()
        });

        info!("[UserManager] 成功加载 {} 个用户", manager.users.len());
        for (username, user) in &manager.users {
            debug!(
                "[UserManager]   - 用户：{}, 启用：{}, 主目录：{}, 权限：{}",
                username, user.enabled, user.home_dir, user.permissions
            );
        }

        info!("[UserManager] 用户配置加载完成");
        Ok(manager)
    }

    /// 将用户库序列化为 JSON 并写入 `path`（先写临时文件再原子重命名）
    ///
    /// # Errors
    /// 父目录创建、序列化、临时文件写入或重命名失败时返回错误
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("Failed to create users directory")?;
        }

        let content = serde_json::to_string_pretty(self).context("Failed to serialize users")?;

        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, content).context("Failed to write temp users file")?;

        fs::rename(&temp_path, path).context("Failed to rename temp users file")?;

        Ok(())
    }

    /// 使用 Argon2id 生成口令哈希（自动随机盐）
    ///
    /// 显式策略参数 `m=65536,t=3,p=4,len=32`（docs/design.md §5.2）。
    ///
    /// # Errors
    /// 参数非法或 Argon2 哈希计算失败（如盐生成失败）时返回错误
    fn hash_password(password: &str) -> Result<String> {
        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| anyhow::anyhow!("Failed to create Argon2 params: {e}"))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        // password-hash 0.6 起 hash_password 自动生成随机盐，无需外部 RNG
        let hash = argon2
            .hash_password(password.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?
            .to_string();
        Ok(hash)
    }

    fn verify_password(password: &str, hash: &str) -> bool {
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to parse password hash: {}", e);
                return false;
            }
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    /// 判断既有哈希是否低于当前策略，需要惰性重哈希升级
    ///
    /// 以下情形视为需要升级：解析失败、算法非 Argon2id、版本低于 `0x13`、
    /// 参数弱于 `m=65536,t=3,p=4` 或输出短于 32 字节。
    fn needs_rehash(hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return true;
        };

        if parsed.algorithm != argon2::Algorithm::Argon2id.ident() {
            return true;
        }

        // 版本字段缺失表示初版 Argon2（0x10），同样需要升级
        if parsed.version.unwrap_or(0x10) < u32::from(argon2::Version::V0x13) {
            return true;
        }

        let Ok(params) = argon2::Params::try_from(&parsed.params) else {
            return true;
        };
        if params.m_cost() < 65536 || params.t_cost() < 3 || params.p_cost() < 4 {
            return true;
        }

        // 哈希段长度即输出长度
        parsed.hash.is_none_or(|h| h.len() < 32)
    }

    /// 新增用户
    ///
    /// # Errors
    /// 用户名为空、用户已存在、家目录为空/不存在/不是目录，或口令哈希失败时返回错误
    pub fn add_user(
        &mut self,
        username: String,
        password: &str,
        home_dir: String,
        permissions: Permissions,
        is_admin: bool,
    ) -> Result<()> {
        if username.is_empty() {
            return Err(anyhow::anyhow!("用户名不能为空"));
        }

        if self.users.contains_key(&username) {
            return Err(anyhow::anyhow!("用户已存在: {username}"));
        }

        if home_dir.trim().is_empty() {
            return Err(anyhow::anyhow!("家目录不能为空"));
        }

        let home_path = Path::new(&home_dir);
        if !home_path.exists() {
            return Err(anyhow::anyhow!("家目录不存在: {home_dir}"));
        }
        if !home_path.is_dir() {
            return Err(anyhow::anyhow!("家目录路径不是目录: {home_dir}"));
        }

        let password_hash = Self::hash_password(password)?;
        let user = User {
            username: username.clone(),
            password_hash,
            home_dir,
            permissions,
            created_at: Utc::now(),
            last_login: None,
            enabled: true,
            is_admin,
        };

        self.users.insert(username, user);
        Ok(())
    }

    /// 删除用户
    ///
    /// # Errors
    /// 用户不存在时返回错误
    pub fn remove_user(&mut self, username: &str) -> Result<()> {
        if self.users.remove(username).is_none() {
            return Err(anyhow::anyhow!("用户不存在: {username}"));
        }
        Ok(())
    }

    /// 更新用户口令
    ///
    /// # Errors
    /// 用户不存在或新口令哈希失败时返回错误
    pub fn update_password(&mut self, username: &str, new_password: &str) -> Result<()> {
        let user = self
            .users
            .get_mut(username)
            .ok_or_else(|| anyhow::anyhow!("用户不存在: {username}"))?;

        user.password_hash = Self::hash_password(new_password)?;
        Ok(())
    }

    /// 更新用户主目录
    ///
    /// # Errors
    /// 家目录为空/不存在/不是目录，或用户不存在时返回错误
    pub fn update_home_dir(&mut self, username: &str, home_dir: String) -> Result<()> {
        if home_dir.trim().is_empty() {
            return Err(anyhow::anyhow!("家目录不能为空"));
        }

        let home_path = Path::new(&home_dir);
        if !home_path.exists() {
            return Err(anyhow::anyhow!("家目录不存在: {home_dir}"));
        }
        if !home_path.is_dir() {
            return Err(anyhow::anyhow!("家目录路径不是目录: {home_dir}"));
        }

        let user = self
            .users
            .get_mut(username)
            .ok_or_else(|| anyhow::anyhow!("用户不存在: {username}"))?;

        user.home_dir = home_dir;
        Ok(())
    }

    /// 覆盖用户权限
    ///
    /// # Errors
    /// 用户不存在时返回错误
    pub fn update_permissions(&mut self, username: &str, permissions: Permissions) -> Result<()> {
        let user = self
            .users
            .get_mut(username)
            .ok_or_else(|| anyhow::anyhow!("用户不存在: {username}"))?;

        user.permissions = permissions;
        Ok(())
    }

    /// 启用或禁用用户
    ///
    /// # Errors
    /// 用户不存在时返回错误
    pub fn set_user_enabled(&mut self, username: &str, enabled: bool) -> Result<()> {
        let user = self
            .users
            .get_mut(username)
            .ok_or_else(|| anyhow::anyhow!("用户不存在: {username}"))?;

        user.enabled = enabled;
        Ok(())
    }

    /// 校验用户口令；成功时更新 `last_login` 并落盘用户库
    ///
    /// 登录成功且既有哈希低于当前策略时惰性重哈希（旧参数/旧版本/旧算法），
    /// 随 `last_login` 一并落盘。
    /// 用户不存在、已禁用或口令不匹配均返回 `Ok(false)`。
    ///
    /// # Errors
    /// 当前实现不会返回 `Err`；保留 `Result` 签名以便未来引入可恢复错误
    pub fn authenticate(&mut self, username: &str, password: &str) -> Result<bool> {
        let Some(user) = self.users.get_mut(username) else {
            return Ok(false);
        };

        if !user.enabled {
            return Ok(false);
        }

        if Self::verify_password(password, &user.password_hash) {
            if Self::needs_rehash(&user.password_hash) {
                match Self::hash_password(password) {
                    Ok(new_hash) => user.password_hash = new_hash,
                    Err(e) => warn!("[UserManager] 口令哈希参数升级失败，保留原哈希：{e}"),
                }
            }

            user.last_login = Some(Utc::now());

            let users_path = crate::paths::users_path();
            if let Err(e) = self.save(&users_path) {
                eprintln!("Warning: Failed to persist last_login: {e}");
            }

            return Ok(true);
        }

        Ok(false)
    }

    /// 从磁盘重新加载用户库并整体替换内存副本
    ///
    /// 文件缺失、读取失败或解析失败时保留/回退为空库并记录日志，不视为致命错误。
    ///
    /// # Errors
    /// 当前实现不会返回 `Err`；保留 `Result` 签名以便未来引入可恢复错误
    pub fn reload(&mut self, path: &Path) -> Result<()> {
        debug!("[UserManager::reload] 尝试重新加载用户配置文件：{:?}", path);

        if !path.exists() {
            warn!("[UserManager::reload] 用户配置文件不存在：{:?}", path);
            return Ok(());
        }

        info!("[UserManager::reload] 开始重新加载用户配置文件：{:?}", path);

        let content = match fs::read_to_string(path) {
            Ok(c) => {
                debug!("[UserManager::reload] 成功读取文件，大小：{} 字节", c.len());
                c
            }
            Err(e) => {
                error!("[UserManager::reload] 读取文件失败：{} - {:?}", e, path);
                warn!("Failed to read users file during reload: {}", e);
                return Ok(());
            }
        };

        if content.trim().is_empty() {
            warn!("[UserManager::reload] 文件内容为空：{:?}", path);
            return Ok(());
        }

        debug!("[UserManager::reload] 开始解析 JSON...");
        let manager: UserManager = serde_json::from_str(&content).unwrap_or_else(|e| {
            error!(
                "[UserManager::reload] 解析 JSON 失败：{} - 内容预览：{}",
                e,
                &content[..content.len().min(200)]
            );
            warn!("Failed to parse users file during reload: {}", e);
            UserManager::new()
        });

        info!(
            "[UserManager::reload] 成功重新加载 {} 个用户 (原用户数：{})",
            manager.users.len(),
            self.users.len()
        );
        for (username, user) in &manager.users {
            debug!(
                "[UserManager::reload]   - 用户：{}, 启用：{}, 主目录：{}",
                username, user.enabled, user.home_dir
            );
        }

        let old_count = self.users.len();
        self.users = manager.users;
        info!(
            "[UserManager::reload] 重新加载完成，用户数变化：{} -> {}",
            old_count,
            self.users.len()
        );
        Ok(())
    }

    #[must_use]
    pub fn get_user(&self, username: &str) -> Option<&User> {
        self.users.get(username)
    }

    #[must_use]
    pub fn get_users(&self) -> &std::collections::HashMap<String, User> {
        &self.users
    }

    #[must_use]
    pub fn get_all_users(&self) -> Vec<User> {
        self.users.values().cloned().collect()
    }

    pub fn list_users(&self) -> impl Iterator<Item = (&String, &User)> {
        self.users.iter()
    }

    /// 校验匿名 FTP 主目录配置
    ///
    /// # Errors
    /// 目录为空、不存在或不是目录时返回错误
    pub fn validate_anonymous_home(home_dir: &str) -> Result<()> {
        if home_dir.trim().is_empty() {
            return Err(anyhow::anyhow!("匿名用户目录不能为空"));
        }

        let home_path = Path::new(home_dir);
        if !home_path.exists() {
            return Err(anyhow::anyhow!("匿名用户目录不存在: {home_dir}"));
        }
        if !home_path.is_dir() {
            return Err(anyhow::anyhow!("匿名用户目录路径不是目录: {home_dir}"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_safe_username_accepts_alnum_underscore_dash() {
        for name in ["alice", "a", "A_1-b", "_x", "0start", &"a".repeat(64)] {
            assert!(is_safe_username(name), "应接受: {name}");
        }
    }

    #[test]
    fn is_safe_username_rejects_bad_input() {
        for name in ["", "-lead", "has space", "中文", "a;b", "a/b", ".", ".."] {
            assert!(!is_safe_username(name), "应拒绝: {name:?}");
        }
        assert!(!is_safe_username(&"a".repeat(65)), "超过 64 字符应拒绝");
    }

    fn temp_home() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().into_owned();
        (dir, path)
    }

    // ---- 口令哈希 ----

    #[test]
    fn hash_and_verify_password_roundtrip() {
        let hash = UserManager::hash_password("s3cret-PW").unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
        assert!(UserManager::verify_password("s3cret-PW", &hash));
        assert!(!UserManager::verify_password("wrong", &hash));
    }

    #[test]
    fn verify_password_rejects_malformed_hash() {
        assert!(!UserManager::verify_password("x", "not-a-phc-hash"));
        assert!(!UserManager::verify_password("x", ""));
    }

    #[test]
    fn hash_password_uses_random_salt() {
        let a = UserManager::hash_password("same").unwrap();
        let b = UserManager::hash_password("same").unwrap();
        assert_ne!(a, b, "相同口令的两次哈希应使用不同盐");
    }

    #[test]
    fn needs_rehash_detects_weaker_params() {
        // argon2 默认参数（m=19456,t=2,p=1）低于当前策略，应判定需升级
        let old_style = Argon2::default()
            .hash_password_with_salt(b"secret-pass", b"example-salt-0k")
            .unwrap()
            .to_string();
        assert!(UserManager::needs_rehash(&old_style));
    }

    #[test]
    fn needs_rehash_accepts_current_policy() {
        let hash = UserManager::hash_password("secret-pass").unwrap();
        assert!(!UserManager::needs_rehash(&hash));
    }

    // ---- add_user 校验 ----

    #[test]
    fn add_user_rejects_empty_username() {
        let (_dir, home) = temp_home();
        let mut manager = UserManager::new();
        let err = manager
            .add_user(String::new(), "pw", home, Permissions::full(), false)
            .unwrap_err();
        assert!(err.to_string().contains("用户名不能为空"));
    }

    #[test]
    fn add_user_rejects_duplicate() {
        let (_dir, home) = temp_home();
        let mut manager = UserManager::new();
        manager
            .add_user(
                "alice".into(),
                "pw",
                home.clone(),
                Permissions::full(),
                false,
            )
            .unwrap();
        assert!(
            manager
                .add_user("alice".into(), "pw", home, Permissions::full(), false)
                .is_err()
        );
    }

    #[test]
    fn add_user_rejects_empty_home() {
        let mut manager = UserManager::new();
        assert!(
            manager
                .add_user(
                    "alice".into(),
                    "pw",
                    "  ".to_string(),
                    Permissions::full(),
                    false
                )
                .is_err()
        );
    }

    #[test]
    fn add_user_rejects_missing_home() {
        let mut manager = UserManager::new();
        assert!(
            manager
                .add_user(
                    "alice".into(),
                    "pw",
                    "/nonexistent/fftpd/home".to_string(),
                    Permissions::full(),
                    false
                )
                .is_err()
        );
    }

    #[test]
    fn add_user_rejects_file_as_home() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut manager = UserManager::new();
        let home = file.path().to_string_lossy().into_owned();
        assert!(
            manager
                .add_user("alice".into(), "pw", home, Permissions::full(), false)
                .is_err()
        );
    }

    #[test]
    fn add_user_success_sets_defaults() {
        let (_dir, home) = temp_home();
        let mut manager = UserManager::new();
        manager
            .add_user("alice".into(), "pw", home, Permissions::full(), true)
            .unwrap();

        let user = manager.get_user("alice").unwrap();
        assert!(user.enabled);
        assert!(user.is_admin);
        assert!(user.last_login.is_none());
        assert_eq!(user.permissions, Permissions::full());
    }

    // ---- 用户操作 ----

    fn manager_with_user() -> (tempfile::TempDir, UserManager) {
        let (dir, home) = temp_home();
        let mut manager = UserManager::new();
        manager
            .add_user("alice".into(), "pw", home, Permissions::full(), false)
            .unwrap();
        (dir, manager)
    }

    #[test]
    fn remove_user_missing_fails() {
        let (_dir, mut manager) = manager_with_user();
        assert!(manager.remove_user("bob").is_err());
        manager.remove_user("alice").unwrap();
        assert!(manager.get_user("alice").is_none());
    }

    #[test]
    fn update_password_changes_hash() {
        let (_dir, mut manager) = manager_with_user();
        let old_hash = manager.get_user("alice").unwrap().password_hash.clone();
        manager.update_password("alice", "new-pw").unwrap();
        let new_hash = &manager.get_user("alice").unwrap().password_hash;
        assert_ne!(old_hash, *new_hash);
        assert!(UserManager::verify_password("new-pw", new_hash));
    }

    #[test]
    fn update_password_missing_user_fails() {
        let mut manager = UserManager::new();
        assert!(manager.update_password("ghost", "pw").is_err());
    }

    #[test]
    fn update_home_dir_validates_target() {
        let (_dir, mut manager) = manager_with_user();
        assert!(manager.update_home_dir("alice", " ".into()).is_err());
        assert!(
            manager
                .update_home_dir("alice", "/nonexistent/fftpd/home".into())
                .is_err()
        );
        assert!(manager.update_home_dir("ghost", "/tmp".into()).is_err());

        let (new_dir, new_home) = temp_home();
        manager.update_home_dir("alice", new_home).unwrap();
        assert_eq!(
            manager.get_user("alice").unwrap().home_dir,
            new_dir.path().to_string_lossy()
        );
    }

    #[test]
    fn update_permissions_and_enabled() {
        let (_dir, mut manager) = manager_with_user();
        let read_only = Permissions {
            can_read: true,
            can_list: true,
            ..Permissions::default()
        };
        manager.update_permissions("alice", read_only).unwrap();
        assert_eq!(manager.get_user("alice").unwrap().permissions, read_only);
        assert!(manager.update_permissions("ghost", read_only).is_err());

        manager.set_user_enabled("alice", false).unwrap();
        assert!(!manager.get_user("alice").unwrap().enabled);
        assert!(manager.set_user_enabled("ghost", true).is_err());
    }

    // ---- authenticate（不触发落盘的分支）----
    // 注意：认证成功会写真实 users_path()（含惰性重哈希落盘），成功分支由
    // tests/password_hash_upgrade.rs 在重定向目录环境下覆盖。

    #[test]
    fn authenticate_unknown_user_returns_false() {
        let mut manager = UserManager::new();
        assert!(!manager.authenticate("ghost", "pw").unwrap());
    }

    #[test]
    fn authenticate_disabled_user_returns_false() {
        let (_dir, mut manager) = manager_with_user();
        manager.set_user_enabled("alice", false).unwrap();
        assert!(!manager.authenticate("alice", "pw").unwrap());
    }

    #[test]
    fn authenticate_wrong_password_returns_false() {
        let (_dir, mut manager) = manager_with_user();
        assert!(!manager.authenticate("alice", "definitely-wrong").unwrap());
    }

    // ---- 持久化 ----

    #[test]
    fn save_and_load_roundtrip() {
        let (dir, home) = temp_home();
        let path = dir.path().join("users.json");
        let mut manager = UserManager::new();
        manager
            .add_user("alice".into(), "pw", home, Permissions::full(), true)
            .unwrap();
        manager
            .add_user(
                "bob".into(),
                "pw2",
                dir.path().to_string_lossy().into_owned(),
                Permissions::default(),
                false,
            )
            .unwrap();
        manager.save(&path).unwrap();

        let loaded = UserManager::load(&path).unwrap();
        assert_eq!(loaded.get_users().len(), 2);
        let alice = loaded.get_user("alice").unwrap();
        assert!(alice.is_admin);
        assert!(UserManager::verify_password("pw", &alice.password_hash));
        assert_eq!(
            loaded.get_user("bob").unwrap().permissions,
            Permissions::default()
        );
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::load(&dir.path().join("absent.json")).unwrap();
        assert_eq!(manager.get_users().len(), 0);
    }

    #[test]
    fn load_empty_file_returns_empty() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "   \n ").unwrap();
        let manager = UserManager::load(file.path()).unwrap();
        assert_eq!(manager.get_users().len(), 0);
    }

    #[test]
    fn load_invalid_json_returns_empty() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "{ not json").unwrap();
        let manager = UserManager::load(file.path()).unwrap();
        assert_eq!(manager.get_users().len(), 0);
    }

    #[test]
    fn reload_replaces_users_from_disk() {
        let (dir, home) = temp_home();
        let path = dir.path().join("users.json");

        let mut disk_manager = UserManager::new();
        disk_manager
            .add_user("carol".into(), "pw", home, Permissions::full(), false)
            .unwrap();
        disk_manager.save(&path).unwrap();

        let mut manager = UserManager::new();
        manager.reload(&path).unwrap();
        assert!(manager.get_user("carol").is_some());
        assert_eq!(manager.get_users().len(), 1);
    }

    #[test]
    fn reload_missing_file_keeps_existing() {
        let (_dir, mut manager) = manager_with_user();
        manager
            .reload(Path::new("/nonexistent/fftpd/users.json"))
            .unwrap();
        assert!(manager.get_user("alice").is_some());
    }

    // ---- 列表与杂项 ----

    #[test]
    fn list_and_get_all_users_agree() {
        let (_dir, manager) = manager_with_user();
        assert_eq!(manager.list_users().count(), 1);
        assert_eq!(manager.get_all_users().len(), 1);
        assert_eq!(manager.get_all_users()[0].username, "alice");
    }

    #[test]
    fn validate_anonymous_home_rules() {
        let (dir, home) = temp_home();
        assert!(UserManager::validate_anonymous_home(&home).is_ok());
        assert!(UserManager::validate_anonymous_home(" ").is_err());
        assert!(UserManager::validate_anonymous_home("/nonexistent/fftpd/anon").is_err());

        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(UserManager::validate_anonymous_home(&file.path().to_string_lossy()).is_err());
        drop(dir);
    }

    #[test]
    fn permissions_display_lists_enabled_flags() {
        let full = Permissions::full();
        let display = full.to_string();
        for flag in [
            "读",
            "写",
            "删",
            "列表",
            "建目录",
            "删目录",
            "重命名",
            "追加",
        ] {
            assert!(display.contains(flag), "缺少权限标识: {flag}");
        }
        assert_eq!(Permissions::default().to_string(), "");
    }
}

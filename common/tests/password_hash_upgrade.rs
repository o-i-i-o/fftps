//! 口令哈希兼容与惰性升级验证（docs/design.md §5.2）
//!
//! - 既有 users.json 中的旧参数 PHC 哈希（如 argon2 默认 `m=19456,t=2,p=1`）
//!   仍可校验，格式与旧版（argon2 0.5 + SaltString）一致；
//! - 登录成功后旧参数哈希惰性重哈希到当前策略
//!   （Argon2id `m=65536,t=3,p=4,len=32`）并落盘。

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use fftp_common::{Permissions, User, UserManager};
use std::sync::{Mutex, PoisonError};

/// 环境变量是进程全局的：串行化所有改写 `FFTPD_CONFIG_DIR` 的用例
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// 与 `UserManager` 相同的校验路径
fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// 旧参数哈希（argon2 默认 `m=19456,t=2,p=1`，显式盐），模拟既有 users.json
fn old_params_hash(password: &str) -> String {
    Argon2::default()
        .hash_password_with_salt(password.as_bytes(), b"example-salt-0k")
        .unwrap()
        .to_string()
}

#[test]
fn new_hash_roundtrip() {
    let home = tempfile::tempdir().unwrap();
    let mut manager = UserManager::new();
    manager
        .add_user(
            "alice".into(),
            "secret-pass",
            home.path().to_string_lossy().into_owned(),
            Permissions::full(),
            false,
        )
        .unwrap();

    let hash = manager.get_user("alice").unwrap().password_hash.clone();
    assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
    assert!(verify_password("secret-pass", &hash));
    assert!(!verify_password("wrong-pass", &hash));
}

#[test]
fn phc_format_unchanged_explicit_salt() {
    // 旧版（argon2 0.5 + SaltString）产出的同样是标准 PHC 串；
    // 用带显式盐的哈希证明解析/校验路径对既有 users.json 中的哈希仍然有效。
    let old_style = old_params_hash("secret-pass");
    assert!(old_style.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    assert!(verify_password("secret-pass", &old_style));
    assert!(!verify_password("wrong-pass", &old_style));
}

#[test]
fn login_upgrades_old_params_hash() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let config_dir = tempfile::tempdir().unwrap();
    // 认证成功会把用户库落盘到 paths::users_path()，重定向到临时目录避免污染真实用户配置。
    // SAFETY: 持有 ENV_LOCK，同进程内不存在并发读写该环境变量的用例
    unsafe {
        std::env::set_var("FFTPD_CONFIG_DIR", config_dir.path());
    }

    let home = tempfile::tempdir().unwrap();
    let users_file = config_dir.path().join("users.json");
    let user = User {
        username: "alice".to_string(),
        password_hash: old_params_hash("secret-pass"),
        home_dir: home.path().to_string_lossy().into_owned(),
        permissions: Permissions::full(),
        created_at: chrono::Utc::now(),
        last_login: None,
        enabled: true,
        is_admin: false,
    };
    let content = serde_json::json!({ "users": { "alice": user } }).to_string();
    std::fs::write(&users_file, content).unwrap();

    let mut manager = UserManager::load(&users_file).unwrap();
    assert!(manager.authenticate("alice", "secret-pass").unwrap());

    // 登录成功后哈希已按当前策略重算
    let new_hash = manager.get_user("alice").unwrap().password_hash.clone();
    assert_ne!(new_hash, user.password_hash);
    assert!(new_hash.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
    assert!(verify_password("secret-pass", &new_hash));

    // 升级结果已落盘
    let saved = std::fs::read_to_string(&users_file).unwrap();
    assert!(saved.contains("m=65536,t=3,p=4"));

    // SAFETY: 同上，持有 ENV_LOCK
    unsafe {
        std::env::remove_var("FFTPD_CONFIG_DIR");
    }
}

#[test]
fn login_with_current_params_hash_does_not_rehash() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let config_dir = tempfile::tempdir().unwrap();
    // SAFETY: 持有 ENV_LOCK，同进程内不存在并发读写该环境变量的用例
    unsafe {
        std::env::set_var("FFTPD_CONFIG_DIR", config_dir.path());
    }

    let home = tempfile::tempdir().unwrap();
    let mut manager = UserManager::new();
    manager
        .add_user(
            "bob".into(),
            "secret-pass",
            home.path().to_string_lossy().into_owned(),
            Permissions::full(),
            false,
        )
        .unwrap();

    let before = manager.get_user("bob").unwrap().password_hash.clone();
    assert!(manager.authenticate("bob", "secret-pass").unwrap());
    assert_eq!(manager.get_user("bob").unwrap().password_hash, before);

    // SAFETY: 同上，持有 ENV_LOCK
    unsafe {
        std::env::remove_var("FFTPD_CONFIG_DIR");
    }
}

//! SFTP 主机密钥管理：加载/自动生成 Ed25519 密钥与定期轮换
//!
//! 首次启动自动生成 Ed25519 主机密钥（OpenSSH 格式私钥 + `.pub` 公钥），
//! `host_key_rotation_days > 0` 时按天数轮换（旧密钥备份为 `.backup.<时间戳>`）。

use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Utc};
use russh::keys::{PrivateKey, ssh_key};

/// 加载主机私钥；文件不存在时自动生成新的 Ed25519 密钥
///
/// # Errors
/// 密钥文件读取/解析失败、目录创建或写入失败时返回错误
pub async fn load_or_generate_host_key(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        let key_data = tokio::fs::read_to_string(path).await?;
        let key = PrivateKey::from_openssh(&key_data)?;
        tracing::info!("Loaded existing SFTP host key: {}", path.display());
        return Ok(key);
    }

    tracing::info!(
        "SFTP host key does not exist, generating new key: {}",
        path.display()
    );
    generate_new_host_key(path).await
}

/// 生成新的 Ed25519 主机密钥（私钥 + `.pub` 公钥），返回私钥
///
/// # Errors
/// 目录创建或密钥写入失败时返回错误
pub async fn generate_new_host_key(path: &Path) -> Result<PrivateKey> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        tracing::info!("Created SFTP key directory: {}", parent.display());
    }

    let mut rng = russh::keys::key::safe_rng();
    let key = PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519)?;
    let openssh = key.to_openssh(ssh_key::LineEnding::default())?;
    tokio::fs::write(path, openssh.to_string()).await?;
    tracing::info!("Generated SFTP host private key: {}", path.display());

    let pub_path = pub_key_path(path);
    let pub_openssh = key.public_key().to_openssh()?;
    tokio::fs::write(&pub_path, &pub_openssh).await?;
    tracing::info!("Generated SFTP host public key: {}", pub_path.display());

    Ok(key)
}

/// 检查并按 `rotation_days` 轮换主机密钥
///
/// 判定依据：优先用 `last_rotation`（本进程内已知的上次轮换时间），
/// 否则用密钥文件修改时间。达到周期时把旧密钥备份为
/// `<key>.backup.<YYYYmmdd_HHMMSS>` 并生成新密钥。
///
/// `last_rotation` 会在轮换成功后更新。
///
/// # Errors
/// 备份之外的密钥生成失败时返回错误（备份失败仅告警）
pub async fn check_and_rotate_key(
    path: &Path,
    rotation_days: u32,
    last_rotation: &mut Option<DateTime<Utc>>,
) -> Result<()> {
    if rotation_days == 0 {
        return Ok(());
    }

    if !path.exists() {
        tracing::info!(
            "SFTP host key does not exist, will generate new key: {}",
            path.display()
        );
        return Ok(());
    }

    let now = Utc::now();

    let should_rotate = match *last_rotation {
        Some(last_time) => {
            now.signed_duration_since(last_time).num_days() >= i64::from(rotation_days)
        }
        None => match tokio::fs::metadata(path).await.and_then(|m| m.modified()) {
            Ok(modified) => {
                let file_age = now.signed_duration_since(DateTime::<Utc>::from(modified));
                file_age.num_days() >= i64::from(rotation_days)
            }
            Err(_) => true,
        },
    };

    if should_rotate {
        tracing::info!(
            "SFTP host key has reached rotation period ({rotation_days} days), generating new key..."
        );

        let backup_path = backup_key_path(path, now);
        if let Err(e) = tokio::fs::copy(path, &backup_path).await {
            tracing::warn!("Failed to backup old key: {e}");
        } else {
            tracing::info!("Old key backed up to: {}", backup_path.display());
        }

        generate_new_host_key(path).await?;
        *last_rotation = Some(now);
        tracing::info!("SFTP host key rotation completed");
    } else {
        let age = last_rotation.map_or(0, |t| now.signed_duration_since(t).num_days());
        tracing::debug!(
            "SFTP host key rotation not needed, current age: {age} days, \
             rotation period: {rotation_days} days"
        );
    }

    Ok(())
}

fn pub_key_path(path: &Path) -> PathBuf {
    path.with_extension("pub")
}

fn backup_key_path(path: &Path, now: DateTime<Utc>) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(format!(".backup.{}", now.format("%Y%m%d_%H%M%S")));
    PathBuf::from(os)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_backup_key_path_appends_suffix() {
        let p = backup_key_path(
            Path::new("/tmp/ssh_host_ed25519_key"),
            Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
        );
        assert_eq!(
            p,
            PathBuf::from("/tmp/ssh_host_ed25519_key.backup.20260102_030405")
        );
    }

    #[test]
    fn test_pub_key_path() {
        assert_eq!(
            pub_key_path(Path::new("/a/b/ssh_host_ed25519_key")),
            PathBuf::from("/a/b/ssh_host_ed25519_key.pub")
        );
    }

    #[tokio::test]
    async fn test_generate_and_load_host_key_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("nested").join("ssh_host_ed25519_key");

        // 首次加载自动生成
        let key1 = load_or_generate_host_key(&key_path).await.unwrap();
        assert!(key_path.exists());
        assert!(key_path.with_extension("pub").exists());
        assert_eq!(key1.algorithm(), ssh_key::Algorithm::Ed25519);

        // 二次加载读取同一密钥
        let key2 = load_or_generate_host_key(&key_path).await.unwrap();
        assert_eq!(
            key1.public_key().to_bytes(),
            key2.public_key().to_bytes()
        );
    }

    #[tokio::test]
    async fn test_rotate_creates_backup_and_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ssh_host_ed25519_key");
        let old_key = load_or_generate_host_key(&key_path).await.unwrap();

        // 轮换周期 1 天、上次轮换时间 2 天前 → 触发轮换
        let mut last_rotation = Some(Utc::now() - chrono::Duration::days(2));
        check_and_rotate_key(&key_path, 1, &mut last_rotation)
            .await
            .unwrap();

        assert!(last_rotation.is_some());
        let new_key = load_or_generate_host_key(&key_path).await.unwrap();
        assert_ne!(
            old_key.public_key().to_bytes(),
            new_key.public_key().to_bytes()
        );

        // 旧密钥备份存在
        let backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".backup."))
            .collect();
        assert_eq!(backups.len(), 1);
    }

    #[tokio::test]
    async fn test_rotate_skipped_within_period() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ssh_host_ed25519_key");
        let old_key = load_or_generate_host_key(&key_path).await.unwrap();

        let before = Utc::now();
        let mut last_rotation = Some(before);
        check_and_rotate_key(&key_path, 30, &mut last_rotation)
            .await
            .unwrap();

        // 未到周期：密钥不变、last_rotation 不更新
        assert_eq!(last_rotation, Some(before));
        let key_after = load_or_generate_host_key(&key_path).await.unwrap();
        assert_eq!(
            old_key.public_key().to_bytes(),
            key_after.public_key().to_bytes()
        );
        let backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".backup."))
            .collect();
        assert_eq!(backups, Vec::<String>::new());
    }
}

//! FTPS 自签证书生成（迁移自 wftpd-windows `ftp_server/cert_gen.rs`）
//!
//! 使用 rcgen 生成自签名 X.509 证书：CN=`fftpd FTP Server`、SAN 覆盖
//! `localhost` / `127.0.0.1` / `::1`，有效期 10 年；Unix 下私钥文件权限收敛为 0600。

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::{info, warn};

/// 生成自签证书与私钥，分别写入 `cert_path` / `key_path`
///
/// # Errors
/// 路径无父目录、目录创建失败、密钥/证书写入失败或 rcgen 参数非法时返回错误
pub fn generate_self_signed_cert(cert_path: &str, key_path: &str) -> Result<()> {
    info!("正在生成 FTPS 自签证书...");

    let cert_dir = Path::new(cert_path)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("证书路径缺少父目录: {cert_path}"))?;

    fs::create_dir_all(cert_dir).context("创建证书目录失败")?;

    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "fftpd FTP Server");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "fftps");
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into()?),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        rcgen::SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];

    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(3650);

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let key_pem = key_pair.serialize_pem();
    fs::write(key_path, key_pem).context("写入私钥文件失败")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(key_path)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(key_path, permissions)?;
    }
    info!(key_path, "私钥已保存");

    let cert_pem = cert.pem();
    fs::write(cert_path, cert_pem).context("写入证书文件失败")?;
    info!(cert_path, "证书已保存");

    info!("FTPS 自签证书生成完成");
    Ok(())
}

/// 确保 `cert_path` / `key_path` 均存在；缺失时重新生成
///
/// 仅存在其一时视为不一致状态，删除残留后整体重新生成。
///
/// # Errors
/// 证书生成失败时返回错误
///
/// # Returns
/// `true` 表示本次新生成，`false` 表示沿用既有证书
pub fn ensure_cert_exists(cert_path: &str, key_path: &str) -> Result<bool> {
    let cert_file = Path::new(cert_path);
    let key_file = Path::new(key_path);

    if cert_file.exists() && key_file.exists() {
        info!("FTPS 证书文件已存在，沿用");
        return Ok(false);
    }

    if cert_file.exists() != key_file.exists() {
        warn!("证书/私钥仅存在其一，将重新生成");
        if cert_file.exists()
            && let Err(e) = fs::remove_file(cert_file)
        {
            warn!("删除残留证书失败: {e}");
        }
        if key_file.exists()
            && let Err(e) = fs::remove_file(key_file)
        {
            warn!("删除残留私钥失败: {e}");
        }
    }

    generate_self_signed_cert(cert_path, key_path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("ftps-cert.pem");
        let key_path = dir.path().join("ftps-key.pem");

        generate_self_signed_cert(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .unwrap();

        let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
        let key_pem = std::fs::read_to_string(&key_path).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn test_ensure_cert_exists_generates_once() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("certs/ftps-cert.pem");
        let key_path = dir.path().join("certs/ftps-key.pem");

        // 首次：生成
        assert!(ensure_cert_exists(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap());
        // 二次：沿用
        assert!(!ensure_cert_exists(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap());
    }

    #[test]
    fn test_ensure_cert_exists_regenerates_half_state() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("ftps-cert.pem");
        let key_path = dir.path().join("ftps-key.pem");

        // 只留残留私钥 → 整体重新生成
        std::fs::write(&key_path, "stale").unwrap();
        assert!(ensure_cert_exists(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap());
        assert!(std::fs::read_to_string(&key_path).unwrap().contains("PRIVATE KEY"));
        assert!(cert_path.exists());
    }
}

//! TLS 支持（rustls，显式 ring provider）
//!
//! 进程内同时存在两套 rustls provider（libunftp 传递引入 aws-lc-rs），
//! 任何 rustls 构建路径都必须显式 [`rustls::crypto::ring`]，不能依赖
//! 进程默认 provider（否则运行时 panic: no process-level CryptoProvider）。

use anyhow::{Context, Result};
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

/// 构建 TLS acceptor（PEM 证书链 + PEM 私钥）
///
/// # Errors
/// 证书/私钥文件读取、解析或配置失败时返回错误
pub fn build_acceptor(tls: &TlsConfig) -> Result<TlsAcceptor> {
    let certs = load_certs(&tls.cert_path)?;
    let key = load_key(&tls.key_path)?;

    let config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .context("TLS 协议版本配置失败")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .with_context(|| format!("TLS 证书/私钥不匹配: {} + {}", tls.cert_path, tls.key_path))?;

    Ok(TlsAcceptor::from(std::sync::Arc::new(config)))
}

/// 读取 PEM 证书链
fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let raw = std::fs::read(path).with_context(|| format!("读取证书文件失败: {path}"))?;
    rustls_pemfile::certs(&mut raw.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("解析 PEM 证书链失败")
}

/// 读取 PEM 私钥
fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let raw = std::fs::read(path).with_context(|| format!("读取私钥文件失败: {path}"))?;
    rustls_pemfile::private_key(&mut raw.as_slice())
        .context("解析 PEM 私钥失败")?
        .context("私钥文件中未找到私钥条目")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_ring_provider_builds_config() {
        // 锁定"显式 ring provider"路径可用（双 provider 进程下默认路径会 panic）
        let provider = rustls::crypto::ring::default_provider();
        let builder = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions();
        assert!(builder.is_ok());
    }

    #[test]
    fn missing_files_report_clearly() {
        let cfg = TlsConfig {
            enabled: true,
            cert_path: "/nonexistent/cert.pem".into(),
            key_path: "/nonexistent/key.pem".into(),
        };
        let err = build_acceptor(&cfg)
            .err()
            .expect("缺失证书文件应构建失败")
            .to_string();
        assert!(err.contains("读取证书文件失败"));
    }
}

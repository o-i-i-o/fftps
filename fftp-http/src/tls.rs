//! TLS 支持（rustls，显式 ring provider）
//!
//! workspace 统一以 ring 作为 rustls crypto provider（见根 `Cargo.toml`），
//! 这里仍显式传入 provider 而不依赖进程级默认值：任何构建路径（包括测试或
//! 后续引入的其他依赖）都能得到一致的加密后端，不会因默认 provider 未设置
//! 而在握手阶段失败。

use anyhow::{Context, Result};
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

/// ALPN：HTTP/2 over TLS 优先，回退 HTTP/1.1
const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// 构建 TLS acceptor（PEM 证书链 + PEM 私钥）
///
/// # Errors
/// 证书/私钥文件读取、解析或配置失败时返回错误
pub fn build_acceptor(tls: &TlsConfig) -> Result<TlsAcceptor> {
    let certs = load_certs(&tls.cert_path)?;
    let key = load_key(&tls.key_path)?;

    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .context("TLS 协议版本配置失败")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .with_context(|| format!("TLS 证书/私钥不匹配: {} + {}", tls.cert_path, tls.key_path))?;

    // 声明 h2 支持：浏览器/客户端经 ALPN 协商后直接使用 HTTP/2，
    // 未协商（或仅支持 http/1.1）的客户端自动回退
    config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];

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
        // 锁定显式 ring provider 路径可用，不依赖进程级默认 provider
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

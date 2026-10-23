//! fftp-http：fftps Web 管理前端入口（axum）
//!
//! 与 fftp-gui 平级的前端：经 fftp-ipc 与 fftpd 通信，自身配置/管理员
//! 独立于 fftpd（fftp-http.toml，见 [`config`]）。提供 REST API 与内嵌
//! 静态 Web UI；实时日志经 SSE 推送。
//!
//! 用法：`fftp-http`（前台服务） | `fftp-http hash <口令>`（生成口令哈希）

mod auth;
mod config;
mod daemon;
mod error;
mod ip_filter;
mod routes;
mod sse;
mod state;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("hash") => {
            let password = args.next().context("用法: fftp-http hash <口令>")?;
            let hash = fftp_common::users::UserManager::hash_password(&password)?;
            println!("{hash}");
        }
        // 未识别参数/无参数均按前台服务运行
        _ => run()?,
    }
    Ok(())
}

/// 前台服务主体
fn run() -> Result<()> {
    init_logging();

    let path = fftp_common::paths::http_config_path();
    let cfg = config::HttpConfig::load(&path)?;
    cfg.validate()?;

    tracing::info!(
        "fftp-http {} 启动（配置: {}）",
        env!("CARGO_PKG_VERSION"),
        path.display()
    );

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve(cfg))
}

/// 启动 HTTP/HTTPS 服务：统一 accept loop，TLS 按配置决定 IO 层
async fn serve(cfg: config::HttpConfig) -> Result<()> {
    let daemon = daemon::Daemon::spawn();
    let state = state::AppState::new(cfg, daemon);
    let app = routes::build_router(Arc::clone(&state));

    let acceptor = if state.config.tls.enabled {
        let a = tls::build_acceptor(&state.config.tls).context("初始化 TLS 失败")?;
        Some(a)
    } else {
        None
    };
    let scheme = if acceptor.is_some() { "https" } else { "http" };

    let addr: SocketAddr = format!("{}:{}", state.config.listen.address, state.config.listen.port)
        .parse()
        .context("监听地址解析失败")?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("绑定 {addr} 失败"))?;
    tracing::info!("Web 管理界面监听 {scheme}://{addr}");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("accept 失败: {e}");
                        continue;
                    }
                };
                tokio::spawn(handle_conn(app.clone(), acceptor.clone(), tcp, peer));
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("收到中断信号，退出");
                return Ok(());
            }
        }
    }
}

/// 单连接处理：注入 `ConnectInfo`（IP 过滤依赖），经 hyper 服务连接
///
/// TLS 启用时先完成握手（失败仅记日志，不影响其他连接），再按普通流服务。
async fn handle_conn(
    app: axum::Router,
    acceptor: Option<TlsAcceptor>,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
) {
    let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(ConnectInfo(peer));
        let app = app.clone();
        async move { app.oneshot(req.map(Body::new)).await }
    });
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());

    let result = match acceptor {
        Some(acceptor) => match acceptor.accept(tcp).await {
            Ok(stream) => {
                builder
                    .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                    .await
            }
            Err(e) => {
                tracing::debug!("TLS 握手失败（{peer}）: {e}");
                return;
            }
        },
        None => {
            builder
                .serve_connection_with_upgrades(TokioIo::new(tcp), svc)
                .await
        }
    };
    if let Err(e) = result {
        tracing::debug!("连接 {peer} 处理结束: {e}");
    }
}

/// 初始化控制台日志（RUST_LOG 可覆盖，默认 info）
fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn hash_uses_shared_argon2_policy() {
        let hash = fftp_common::users::UserManager::hash_password("test-pass").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(hash.contains("m=65536,t=3,p=4"));
        assert!(fftp_common::users::UserManager::verify_password("test-pass", &hash));
        assert!(!fftp_common::users::UserManager::verify_password("wrong", &hash));
    }
}

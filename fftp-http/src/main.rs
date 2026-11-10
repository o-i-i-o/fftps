//! fftp-http：fftps Web 管理前端入口（axum）
//!
//! 与已移除的旧图形前端平级的前端：经 fftp-ipc 与 fftpd 通信，自身配置/管理员
//! 独立于 fftpd（fftp-http.toml，见 [`config`]）。提供 REST API 与内嵌
//! 静态 Web UI；实时日志经 SSE 推送。
//!
//! 用法：`fftp-http serve`（前台服务，默认） | `fftp-http launch`（桌面入口）
//!       `fftp-http hash <口令>`（生成口令哈希）
//!       Windows 下另支持 `fftp-http --service`（SCM 服务方式，见 [`service_windows`]）

mod auth;
mod config;
mod daemon;
mod error;
mod idle;
mod ip_filter;
mod launch;
mod routes;
#[cfg(windows)]
mod service_windows;
mod setup;
mod sse;
mod state;
mod system_service;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::sync::{Semaphore, watch};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use idle::ShutdownReason;

/// Web 管理面并发连接上限（含 SSE / 静态资源 / API）
const MAX_CONNECTIONS: usize = 256;
/// TLS 握手超时：防止慢速握手长期占用连接
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// HTTP 请求头读取超时：防止 slowloris 持续占用连接
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn main() -> Result<()> {
    // Windows 下先尝试服务方式（`--service` 或 SCM 自动检测），
    // 未由 SCM 接管则回退前台运行（Linux 无平台分支）
    #[cfg(windows)]
    {
        if service_windows::try_run_as_service()? {
            return Ok(());
        }
    }
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("hash") => {
            let password = args.next().context("用法: fftp-http hash <口令>")?;
            let hash = fftp_common::users::UserManager::hash_password(&password)?;
            println!("{hash}");
        }
        // 桌面快捷方式入口：确保服务运行并打开浏览器
        Some("launch") => launch::run()?,
        // 前台服务（显式 `serve` 或省略子命令）
        Some("serve") | None => run()?,
        Some(other) => {
            anyhow::bail!("未知子命令: {other}\n用法: fftp-http [serve|launch|hash <口令>]")
        }
    }
    Ok(())
}

/// 前台服务入口（Windows 服务线程走 [`run_async`]，带 SCM 停止信号）
fn run() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_async(None))
}

/// 服务主体（前台入口与 Windows 服务线程共用）
///
/// `service_stop` 为 Windows 服务停止信号（`None` = 前台运行，仅响应 Ctrl-C）
async fn run_async(service_stop: Option<watch::Receiver<bool>>) -> Result<()> {
    init_logging();

    let path = fftp_common::paths::http_config_path();
    let cfg = config::HttpConfig::load(&path)?;
    cfg.validate()?;

    tracing::info!(
        "fftp-http {} 启动（配置: {}）",
        env!("CARGO_PKG_VERSION"),
        path.display()
    );

    if cfg.admin_users.is_empty() {
        // 首次启动：生成一次性引导令牌，桌面入口据此打开 /setup?token=...
        let token = setup::ensure_token()?;
        let base = launch::browser_url(&cfg).unwrap_or_else(|_| "http://127.0.0.1".into());
        tracing::warn!(
            "尚未配置管理员账户，已进入首次设置引导（仅限本机）：{base}/setup?token={token}"
        );
    } else {
        // 已有管理员：清理可能残留的引导令牌
        setup::clear_token();
    }

    serve(cfg, path, service_stop).await
}

/// 启动 HTTP/HTTPS 服务：统一 accept loop，TLS 按配置决定 IO 层
async fn serve(
    cfg: config::HttpConfig,
    http_config_path: std::path::PathBuf,
    service_stop: Option<watch::Receiver<bool>>,
) -> Result<()> {
    let daemon = daemon::Daemon::spawn();
    let (state, mut shutdown_rx) = state::AppState::new(cfg, daemon, http_config_path);
    let app = routes::build_router(Arc::clone(&state));

    let acceptor = if state.config.tls.enabled {
        let a = tls::build_acceptor(&state.config.tls).context("初始化 TLS 失败")?;
        Some(a)
    } else {
        None
    };
    let scheme = if acceptor.is_some() { "https" } else { "http" };

    let addr: SocketAddr = format!(
        "{}:{}",
        state.config.listen.address, state.config.listen.port
    )
    .parse()
    .context("监听地址解析失败")?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("绑定 {addr} 失败"))?;
    tracing::info!("Web 管理界面监听 {scheme}://{addr}");

    let mut service_stop = service_stop;
    let conn_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
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
                let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
                    tracing::warn!("连接数达到上限（{MAX_CONNECTIONS}），拒绝 {peer}");
                    drop(tcp);
                    continue;
                };
                let app = app.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    handle_conn(app, acceptor, tcp, peer).await;
                    drop(permit);
                });
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("收到中断信号，退出");
                return Ok(());
            }
            () = wait_service_stop(&mut service_stop) => {
                tracing::info!("收到服务停止信号，退出");
                return Ok(());
            }
            reason = wait_shutdown(&mut shutdown_rx) => {
                if let Some(reason) = reason {
                    tracing::info!("{}，关闭 fftp-http（不关闭 fftpd）", reason.as_str());
                }
                return Ok(());
            }
        }
    }
}

/// 空闲/手动关停信号；无信号时永不触发
async fn wait_shutdown(rx: &mut watch::Receiver<Option<ShutdownReason>>) -> Option<ShutdownReason> {
    loop {
        if let Some(reason) = *rx.borrow() {
            return Some(reason);
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Windows 服务停止信号；无信号源（前台运行）时永不触发
async fn wait_service_stop(stop: &mut Option<watch::Receiver<bool>>) {
    match stop {
        Some(rx) => {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        }
        None => std::future::pending::<()>().await,
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
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(HEADER_READ_TIMEOUT));

    let result = match acceptor {
        Some(acceptor) => {
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(stream)) => {
                    builder
                        .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                        .await
                }
                Ok(Err(e)) => {
                    tracing::debug!("TLS 握手失败（{peer}）: {e}");
                    return;
                }
                Err(_) => {
                    tracing::warn!("TLS 握手超时（{peer}），断开连接");
                    return;
                }
            }
        }
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

/// 初始化控制台日志（`RUST_LOG` 可覆盖，默认 info）
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
        assert!(fftp_common::users::UserManager::verify_password(
            "test-pass",
            &hash
        ));
        assert!(!fftp_common::users::UserManager::verify_password(
            "wrong", &hash
        ));
    }
}

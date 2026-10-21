//! fftpd：fftps 服务端守护进程入口
//!
//! 启动流程：日志设施 → 配置/用户库 → SFTP 主机密钥 → FTP/SFTP 服务 → IPC 控制面。
//! 运行期把日志环形缓冲的新条目实时推送给 IPC 订阅者；
//! 退出（Ctrl-C / `Shutdown` 命令 / IPC 服务异常）前优雅停止协议服务并清理端点。

mod control;
mod dirs;
mod logs;
#[cfg(windows)]
mod service_windows;
mod state;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{broadcast, watch};

use fftp_common::config::LoggingConfig;
use fftp_common::logging::Logging;
use fftp_common::users::UserManager;

use control::ControlHandler;
use state::AppState;

/// 主入口：Windows 下先尝试服务方式（`--service` 或 SCM 自动检测），
/// 否则按前台守护进程运行（Linux 无平台分支，直接前台运行）
fn main() -> Result<()> {
    #[cfg(windows)]
    {
        if service_windows::try_run_as_service()? {
            return Ok(());
        }
    }
    run_daemon_blocking(None)
}

/// 在独立 tokio 运行时中运行守护逻辑（前台入口与 Windows 服务线程共用）
///
/// `service_stop` 为 Windows 服务停止信号（`None` = 无外部停止源，永不触发）
fn run_daemon_blocking(service_stop: Option<watch::Receiver<bool>>) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_daemon(service_stop))
}

/// 守护逻辑主体（可被前台入口与 Windows 服务入口复用）
async fn run_daemon(service_stop: Option<watch::Receiver<bool>>) -> Result<()> {
    // 1. 配置 + 日志设施（Logging::init 安装全局 tracing：控制台 + 日志文件 + 环形缓冲）
    let config = control::load_config()?;
    let logging = init_logging(&config.logging);

    tracing::info!("fftpd {} 启动中", env!("CARGO_PKG_VERSION"));

    // 2. 用户库（文件缺失时为空库）
    let users = UserManager::load(&fftp_common::paths::users_path())?;

    // 3. SFTP 主机密钥：空串取 paths::default_host_key_path()，首次自动生成 Ed25519
    let host_key_path = config.sftp.resolved_host_key_path();
    if let Err(e) = fftp_sftp::host_key::load_or_generate_host_key(&host_key_path).await {
        // 主机密钥失败只影响 SFTP，不阻止守护进程与其余服务启动
        tracing::error!(
            "SFTP 主机密钥准备失败（SFTP 服务将不可用）: {} {e:#}",
            host_key_path.display()
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = AppState::new(config, users, Arc::clone(&logging), shutdown_tx);
    let (events, _) = broadcast::channel(1024);

    // 4. 日志实时推送：环形缓冲新条目 → IPC 事件广播（SubscribeLogs 订阅者）
    let log_forward = logs::spawn_log_forwarder(logging, events.clone());

    // 5. 按配置启动协议服务（单个服务启动失败不致命，状态反映未运行）
    state.start_enabled_services().await;

    // 6. IPC 控制面（阻塞运行，直至退出信号）
    tokio::select! {
        res = fftp_ipc::serve(ControlHandler::new(state.clone()), events) => {
            if let Err(e) = res {
                tracing::error!("IPC 服务端异常退出: {e:#}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("收到中断信号，退出");
        }
        () = wait_shutdown(shutdown_rx) => {
            tracing::info!("收到关停指令，退出");
        }
        () = wait_shutdown_opt(service_stop) => {
            tracing::info!("收到服务停止信号，退出");
        }
    }

    // 7. 收尾：停止协议服务、清理 IPC 端点
    log_forward.abort();
    state.stop_all().await;
    fftp_ipc::transport::cleanup();
    Ok(())
}

async fn wait_shutdown(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Windows 服务停止信号；无信号源（前台运行）时永不触发
async fn wait_shutdown_opt(stop: Option<watch::Receiver<bool>>) {
    match stop {
        Some(rx) => wait_shutdown(rx).await,
        None => std::future::pending::<()>().await,
    }
}

/// 初始化日志设施；全局 subscriber 安装失败时回退控制台输出（不阻断启动）
fn init_logging(config: &LoggingConfig) -> Arc<Logging> {
    match Logging::init(config) {
        Ok(logging) => Arc::new(logging),
        Err(e) => {
            eprintln!("Warning: 日志设施初始化失败，回退控制台输出: {e:#}");
            let _ = fftp_common::logging::init_simple();
            Arc::new(Logging::new(config))
        }
    }
}

//! fftpd：fftps 服务端守护进程入口
//!
//! 阶段 1：配置/用户控制面 + IPC 服务；FTP/SFTP 服务在阶段 2 迁入。

mod control;

use anyhow::Result;
use tokio::sync::{broadcast, watch};

use control::{load_config, AppState, ControlHandler};

#[tokio::main]
async fn main() -> Result<()> {
    let config = load_config()?;
    init_tracing(&config.logging.log_level);

    tracing::info!("fftpd {} 启动中", env!("CARGO_PKG_VERSION"));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = AppState::new(config, shutdown_tx);
    let (events, _) = broadcast::channel(1024);

    tokio::select! {
        res = fftp_ipc::serve(ControlHandler::new(state.clone()), events) => {
            if let Err(e) = res {
                tracing::error!("IPC 服务端异常退出: {e:#}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("收到中断信号，退出");
        }
        _ = wait_shutdown(shutdown_rx) => {
            tracing::info!("收到关停指令，退出");
        }
    }

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

fn init_tracing(level: &str) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| format!("fftpd={level},info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

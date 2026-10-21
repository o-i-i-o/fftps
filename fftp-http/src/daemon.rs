//! 守护进程连接管理器
//!
//! 移植 fftp-gui 的连接状态机思想并适配 HTTP handler 形态：
//! `watch::channel<Option<Client>>` 保存当前连接；后台监督任务负责
//! 连接 → 心跳探活（每 [`HEARTBEAT_SECS`] 秒 `GetStatus`）→ 断开后指数
//! 退避重连（1s 起上限 [`BACKOFF_MAX_SECS`]）。
//!
//! `Client` 为 `Clone`（Arc 内部）且按 id 多路复用，handler 并发共享同一
//! 连接；SSE 日志流例外——`SubscribeLogs` 按 IPC 连接记账，必须每流独立
//! `Client::connect()`（见 `sse.rs`）。

use std::time::Duration;

use tokio::sync::watch;

use fftp_ipc::client::{Client, ClientError};
use fftp_ipc::protocol::Command;

/// 心跳探活间隔（秒）
const HEARTBEAT_SECS: u64 = 5;
/// 重连退避上限（秒，对齐 fftp-gui）
const BACKOFF_MAX_SECS: u64 = 10;

/// 守护进程连接句柄（Clone 廉价，可放进多个 handler）
#[derive(Clone)]
pub struct Daemon {
    client_rx: watch::Receiver<Option<Client>>,
}

impl Daemon {
    /// 启动监督任务
    pub fn spawn() -> Self {
        let (tx, rx) = watch::channel(None);
        tokio::spawn(supervise(tx));
        Self { client_rx: rx }
    }

    /// 是否已连接（供 `/api/daemon` 状态查询）
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.client_rx.borrow().is_some()
    }

    /// 当前连接（断开时为 `None`；心跳窗口内可能短暂持有失活连接，
    /// 由请求自身的 Disconnected 错误兜底）
    fn client(&self) -> Option<Client> {
        self.client_rx.borrow().clone()
    }

    /// 发送命令（未连接时返回 503 语义的 [`ClientError::Disconnected`]）
    ///
    /// # Errors
    /// 未连接、连接断开或服务端业务失败时返回 [`ClientError`]
    pub async fn request(&self, cmd: Command) -> Result<serde_json::Value, ClientError> {
        match self.client() {
            Some(client) => client.request(cmd).await,
            None => Err(ClientError::Disconnected("fftpd 未连接".into())),
        }
    }
}

/// 监督循环：连接 → 心跳直到断开 → 退避重连
async fn supervise(tx: watch::Sender<Option<Client>>) {
    let mut backoff_step = 0u32;
    loop {
        match Client::connect().await {
            Ok(client) => {
                tracing::info!("已连接 fftpd（{}）", fftp_ipc::transport::endpoint_display());
                if tx.send(Some(client.clone())).is_err() {
                    return; // 应用已退出
                }
                backoff_step = 0;
                if heartbeat(client).await.is_ok() {
                    // 心跳正常退出仅发生在应用关闭（watch 发送端已 drop）
                    return;
                }
                tracing::warn!("与 fftpd 的连接已断开");
            }
            Err(e) => tracing::warn!("连接 fftpd 失败: {e:#}"),
        }
        if tx.send(None).is_err() {
            return;
        }
        let secs = (1u64 << backoff_step.min(4)).min(BACKOFF_MAX_SECS);
        backoff_step = backoff_step.saturating_add(1);
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
}

/// 心跳探活：周期性 `GetStatus`，请求失败即视为断开
async fn heartbeat(client: Client) -> Result<(), ClientError> {
    loop {
        tokio::time::sleep(Duration::from_secs(HEARTBEAT_SECS)).await;
        client.request(Command::GetStatus).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_without_daemon_reports_disconnected() {
        // 未连接 fftpd 的 Daemon：监督任务会失败重连，此处只验证空连接语义
        let daemon = Daemon {
            client_rx: watch::channel(None).1,
        };
        assert!(!daemon.is_connected());
        let err = daemon.request(Command::GetStatus).await.unwrap_err();
        assert!(matches!(err, ClientError::Disconnected(_)));
    }
}

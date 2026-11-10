//! IPC 服务端（fftpd 侧）
//!
//! 连接循环 + 命令分发骨架：`SubscribeLogs`/`UnsubscribeLogs` 由本层处理，
//! 其余命令交给业务 [`Handler`]。日志推送经广播通道扇出到各订阅连接。

use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, split};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::framing;
use crate::protocol::{Command, ErrorCode, Event, Hello, Message, Notification, Response};

/// 服务端等待客户端握手帧的上限
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// 业务处理器：实现方通常持有 `Arc<AppState>`
///
/// 返回 future 显式限定 `Send`，便于服务端按连接并发 spawn。
#[allow(async_fn_in_trait)]
pub trait Handler: Clone + Send + Sync + 'static {
    /// 处理一条控制命令，返回 JSON 应答数据
    fn handle(
        &self,
        cmd: Command,
    ) -> impl std::future::Future<Output = Result<Value, HandlerError>> + Send;
}

/// 业务错误：携带协议错误类别
#[derive(Debug)]
pub struct HandlerError {
    pub code: ErrorCode,
    pub message: String,
}

impl HandlerError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    #[must_use]
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Validation, message)
    }

    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    #[must_use]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }
}

impl From<anyhow::Error> for HandlerError {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(e.to_string())
    }
}

/// 启动服务端：监听平台端点并循环服务连接
///
/// 该 future 永久运行；由调用方（fftpd）在退出信号上做 `select!`，
/// 退出后调用 [`crate::transport::cleanup`] 清理端点。
///
/// # Errors
/// 监听失败时返回错误；单连接错误仅记录日志
pub async fn serve<H: Handler>(handler: H, events: broadcast::Sender<Event>) -> Result<()> {
    let mut listener = crate::transport::listen().await?;
    let token: Arc<str> = Arc::from(
        fftp_common::paths::load_or_create_ipc_token()
            .map_err(|e| anyhow::anyhow!("初始化 IPC 握手令牌失败: {e}"))?,
    );
    tracing::info!("IPC 服务端就绪: {}", crate::transport::endpoint_display());

    loop {
        let conn = listener.accept().await?;
        let handler = handler.clone();
        let events = events.clone();
        let token = Arc::clone(&token);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(conn, handler, events, &token).await {
                tracing::debug!("IPC 连接结束: {e:#}");
            }
        });
    }
}

/// 首帧握手：校验共享令牌后回送 [`Message::HelloAck`]
async fn handshake(conn: &mut crate::transport::Duplex, expected: &str) -> Result<()> {
    let frame = match tokio::time::timeout(HANDSHAKE_TIMEOUT, framing::read_frame(conn)).await {
        Ok(frame) => frame?,
        Err(_) => anyhow::bail!("IPC 握手超时"),
    };
    let Some(Message::Hello(Hello { token })) = frame else {
        anyhow::bail!("IPC 首帧不是握手消息");
    };
    if !constant_time_eq(token.as_bytes(), expected.as_bytes()) {
        tracing::warn!("IPC 握手令牌不匹配，拒绝连接");
        anyhow::bail!("IPC 握手令牌不匹配");
    }
    framing::write_frame(conn, &Message::HelloAck).await?;
    Ok(())
}

/// 常量时间比较，避免按字节提前返回泄露令牌前缀
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn handle_conn<H: Handler>(
    mut conn: crate::transport::Duplex,
    handler: H,
    events: broadcast::Sender<Event>,
    token: &str,
) -> Result<()> {
    handshake(&mut conn, token).await?;

    let (mut reader, writer) = split(conn);
    let writer = Arc::new(Mutex::new(writer));

    // 推送通道：订阅转发任务 → 写任务，避免与请求响应路径争抢锁序
    let (notify_tx, notify_rx) = mpsc::channel::<Event>(256);
    let notify_task = spawn_notify_writer(Arc::clone(&writer), notify_rx);

    let mut log_forward: Option<JoinHandle<()>> = None;

    let result = read_dispatch_loop(
        &mut reader,
        &writer,
        &handler,
        &events,
        &notify_tx,
        &mut log_forward,
    )
    .await;

    if let Some(task) = log_forward {
        task.abort();
    }
    drop(notify_tx);
    notify_task.await?;

    result
}

async fn read_dispatch_loop<R, H, W>(
    reader: &mut R,
    writer: &Arc<Mutex<W>>,
    handler: &H,
    events: &broadcast::Sender<Event>,
    notify_tx: &mpsc::Sender<Event>,
    log_forward: &mut Option<JoinHandle<()>>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: Handler,
{
    while let Some(frame) = framing::read_frame(reader).await? {
        let Message::Request(req) = frame else {
            tracing::warn!("忽略客户端发来的非请求消息");
            continue;
        };

        let id = req.id;
        let resp = match req.cmd {
            Command::SubscribeLogs { tail_count } => {
                // 先订阅后补推历史，保证新日志不丢
                *log_forward = Some(spawn_log_forwarder(events.subscribe(), notify_tx.clone()));
                if tail_count > 0 {
                    match handler
                        .handle(Command::GetRecentLogs { count: tail_count })
                        .await
                    {
                        Ok(data) => push_history(data, notify_tx).await,
                        Err(e) => tracing::warn!("读取订阅历史日志失败: {}", e.message),
                    }
                }
                Response::ok(id, Value::Null)
            }
            Command::UnsubscribeLogs => {
                if let Some(task) = log_forward.take() {
                    task.abort();
                }
                Response::ok(id, Value::Null)
            }
            cmd => match handler.handle(cmd).await {
                Ok(data) => Response::ok(id, data),
                Err(e) => Response::error(id, e.code, e.message),
            },
        };

        framing::write_frame(&mut *writer.lock().await, &Message::Response(resp)).await?;
    }
    Ok(())
}

/// 历史日志补推：`GetRecentLogs` 返回 `{"entries": [LogEntry, ...]}` 形状
async fn push_history(data: Value, notify_tx: &mpsc::Sender<Event>) {
    let Ok(entries) = serde_json::from_value::<Vec<crate::protocol::LogEntry>>(
        data.get("entries").cloned().unwrap_or(Value::Null),
    ) else {
        return;
    };
    for entry in entries {
        if notify_tx.send(Event::Log { entry }).await.is_err() {
            return;
        }
    }
}

fn spawn_log_forwarder(
    mut rx: broadcast::Receiver<Event>,
    tx: mpsc::Sender<Event>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("日志订阅者落后，丢弃 {n} 条");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

fn spawn_notify_writer<W>(writer: Arc<Mutex<W>>, mut rx: mpsc::Receiver<Event>) -> JoinHandle<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let msg = Message::Notification(Notification { event });
            if framing::write_frame(&mut *writer.lock().await, &msg)
                .await
                .is_err()
            {
                break;
            }
        }
    })
}

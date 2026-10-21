//! IPC 客户端（ftp-gui 侧）
//!
//! 单连接多路复用：请求/响应按 `id` 配对，服务端推送走独立广播通道。
//! 后台读任务负责分发，`request()` 经 oneshot 等待对应回包。

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::{broadcast, oneshot, Mutex};

use crate::framing;
use crate::protocol::{Command, ErrorCode, Event, Message, Notification, OpResult, Request, Response};

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Response>>>>;

/// IPC 客户端
#[derive(Clone)]
pub struct Client {
    writer: Arc<Mutex<WriteHalf<crate::transport::Duplex>>>,
    pending: Pending,
    next_id: Arc<std::sync::atomic::AtomicU64>,
    events: broadcast::Sender<Event>,
}

/// [`Client::request`] 的业务级错误
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct RequestError {
    pub code: ErrorCode,
    pub message: String,
}

impl Client {
    /// 连接服务端
    ///
    /// # Errors
    /// 连接失败时返回错误
    pub async fn connect() -> Result<Self> {
        let conn = crate::transport::connect().await?;
        Ok(Self::from_duplex(conn))
    }

    /// 从任意双工流构造客户端（测试/自定义传输用）
    #[must_use]
    pub fn from_duplex(conn: crate::transport::Duplex) -> Self {
        let (reader, writer) = split(conn);
        let (events, _) = broadcast::channel(1024);
        let pending: Pending = Arc::default();

        tokio::spawn(read_loop(reader, Arc::clone(&pending), events.clone()));

        Self {
            writer: Arc::new(Mutex::new(writer)),
            pending,
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            events,
        }
    }

    /// 订阅服务端推送事件
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    /// 发送命令并等待响应
    ///
    /// # Errors
    /// 连接断开/写入失败返回 `anyhow` 错误；服务端业务失败返回 [`RequestError`]
    pub async fn request(&self, cmd: Command) -> Result<serde_json::Value, ClientError> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        let msg = Message::Request(Request { id, cmd });
        if let Err(e) = framing::write_frame(&mut *self.writer.lock().await, &msg).await {
            self.pending.lock().await.remove(&id);
            return Err(ClientError::Disconnected(e.to_string()));
        }

        match rx.await {
            Ok(resp) => match resp.result {
                OpResult::Ok { data } => Ok(data),
                OpResult::Error { code, message } => Err(ClientError::Request(RequestError {
                    code,
                    message,
                })),
            },
            Err(_) => Err(ClientError::Disconnected("连接已断开，未收到响应".into())),
        }
    }
}

/// 客户端请求失败的两类原因
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("与 fftpd 通信失败: {0}")]
    Disconnected(String),
    #[error(transparent)]
    Request(#[from] RequestError),
}

async fn read_loop<R>(
    mut reader: ReadHalf<R>,
    pending: Pending,
    events: broadcast::Sender<Event>,
) where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        match framing::read_frame(&mut reader).await {
            Ok(Some(Message::Response(resp))) => {
                if let Some(tx) = pending.lock().await.remove(&resp.id) {
                    let _ = tx.send(resp);
                }
            }
            Ok(Some(Message::Notification(Notification { event }))) => {
                // 无订阅者时忽略发送错误
                let _ = events.send(event);
            }
            Ok(Some(other)) => {
                tracing::warn!("忽略来自服务端的非预期消息: {other:?}");
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("IPC 读取失败: {e:#}");
                break;
            }
        }
    }

    // 连接断开：清空挂起请求，唤醒所有等待方
    for (_, tx) in pending.lock().await.drain() {
        let _ = tx.send(Response::error(0, ErrorCode::Io, "连接已断开"));
    }
}

/// 便捷封装：单次请求
///
/// # Errors
/// 同 [`Client::request`]
pub async fn request_once(cmd: Command) -> Result<serde_json::Value, ClientError> {
    let client = Client::connect()
        .await
        .map_err(|e| ClientError::Disconnected(e.to_string()))?;
    client.request(cmd).await
}

/// 校验响应数据形状的辅助（服务端返回错误形状时给出明确错误）
///
/// # Errors
/// 反序列化失败时返回错误
pub fn parse_data<T: serde::de::DeserializeOwned>(data: serde_json::Value) -> Result<T> {
    serde_json::from_value(data).context("服务端响应数据形状不符合预期")
}

/// 保留给上层：判断是否值得重连（连接类错误）
#[must_use]
pub fn is_disconnected(err: &ClientError) -> bool {
    matches!(err, ClientError::Disconnected(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::LogEntry;

    fn server_conn() -> (crate::transport::Duplex, crate::transport::Duplex) {
        let (a, b) = tokio::io::duplex(4096);
        (Box::new(a), Box::new(b))
    }

    #[tokio::test]
    async fn request_response_roundtrip() {
        let (client_side, server_side) = server_conn();
        let client = Client::from_duplex(client_side);

        tokio::spawn(async move {
            let (mut _r, mut w) = split(server_side);
            // 读请求
            let mut reader = _r;
            if let Some(Message::Request(req)) = framing::read_frame(&mut reader).await.unwrap() {
                let resp = Response::ok(req.id, serde_json::json!({"pong": true}));
                framing::write_frame(&mut w, &Message::Response(resp))
                    .await
                    .unwrap();
            }
        });

        let data = client.request(Command::GetStatus).await.unwrap();
        assert_eq!(data["pong"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn server_error_surfaces_as_request_error() {
        let (client_side, server_side) = server_conn();
        let client = Client::from_duplex(client_side);

        tokio::spawn(async move {
            let (mut r, mut w) = split(server_side);
            if let Some(Message::Request(req)) = framing::read_frame(&mut r).await.unwrap() {
                let resp = Response::error(req.id, ErrorCode::NotFound, "没有这个东西");
                framing::write_frame(&mut w, &Message::Response(resp))
                    .await
                    .unwrap();
            }
        });

        match client.request(Command::GetStatus).await {
            Err(ClientError::Request(e)) => {
                assert_eq!(e.code, ErrorCode::NotFound);
                assert_eq!(e.message, "没有这个东西");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn notifications_reach_subscribers() {
        let (client_side, server_side) = server_conn();
        let client = Client::from_duplex(client_side);
        let mut rx = client.subscribe_events();

        tokio::spawn(async move {
            let (_r, mut w) = split(server_side);
            let msg = Message::Notification(Notification {
                event: Event::Log {
                    entry: LogEntry {
                        timestamp: "t".into(),
                        level: "info".into(),
                        source: "fftpd".into(),
                        message: "pushed".into(),
                        client_ip: String::new(),
                        username: String::new(),
                        action: String::new(),
                    },
                },
            });
            framing::write_frame(&mut w, &msg).await.unwrap();
        });

        match tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Event::Log { entry } => assert_eq!(entry.message, "pushed"),
        }
    }
}

//! IPC 服务端（fftpd 侧）
//!
//! 连接循环 + 命令分发骨架：`SubscribeLogs`/`UnsubscribeLogs` 与
//! `SubscribeFileOps`/`UnsubscribeFileOps` 由本层处理，其余命令交给业务
//! [`Handler`]。推送经广播通道扇出到各订阅连接，并按订阅类别过滤：
//! 程序日志流只收到 `Event::Log`，文件操作审计流只收到 `Event::FileOp`。

use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, split};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::framing;
use crate::protocol::{
    Command, ErrorCode, Event, FileOpLogEntry, Hello, LogEntry, Message, Notification, Response,
};

/// 服务端等待客户端握手帧的上限
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// 单连接订阅的事件类别
///
/// 每个 SSE 流独占一条 IPC 连接，服务端按订阅类别过滤广播事件：
/// 程序日志流只收到 [`Event::Log`]，审计流只收到 [`Event::FileOp`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventKind {
    Log,
    FileOp,
}

impl EventKind {
    fn accepts(self, event: &Event) -> bool {
        matches!(
            (self, event),
            (Self::Log, Event::Log { .. }) | (Self::FileOp, Event::FileOp { .. })
        )
    }
}

/// 连接上当前生效的事件订阅
struct Subscription {
    kind: EventKind,
    task: JoinHandle<()>,
}

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

    let mut subscription: Option<Subscription> = None;

    let result = read_dispatch_loop(
        &mut reader,
        &writer,
        &handler,
        &events,
        &notify_tx,
        &mut subscription,
    )
    .await;

    if let Some(subscription) = subscription {
        subscription.task.abort();
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
    subscription: &mut Option<Subscription>,
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
                start_subscription(subscription, events, notify_tx, EventKind::Log);
                if tail_count > 0 {
                    match handler
                        .handle(Command::GetRecentLogs { count: tail_count })
                        .await
                    {
                        Ok(data) => {
                            push_history(data, notify_tx, |entry: LogEntry| Event::Log { entry })
                                .await;
                        }
                        Err(e) => tracing::warn!("读取订阅历史日志失败: {}", e.message),
                    }
                }
                Response::ok(id, Value::Null)
            }
            Command::UnsubscribeLogs => {
                stop_subscription(subscription, EventKind::Log);
                Response::ok(id, Value::Null)
            }
            Command::SubscribeFileOps { tail_count } => {
                // 与程序日志相同的顺序：先订阅广播，再补推审计历史
                start_subscription(subscription, events, notify_tx, EventKind::FileOp);
                if tail_count > 0 {
                    match handler
                        .handle(Command::GetRecentFileOps { count: tail_count })
                        .await
                    {
                        Ok(data) => {
                            push_history(data, notify_tx, |entry: FileOpLogEntry| Event::FileOp {
                                entry,
                            })
                            .await;
                        }
                        Err(e) => tracing::warn!("读取订阅历史审计条目失败: {}", e.message),
                    }
                }
                Response::ok(id, Value::Null)
            }
            Command::UnsubscribeFileOps => {
                stop_subscription(subscription, EventKind::FileOp);
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

/// 替换连接上已有订阅（单连接只保留一个事件流）
fn start_subscription(
    subscription: &mut Option<Subscription>,
    events: &broadcast::Sender<Event>,
    notify_tx: &mpsc::Sender<Event>,
    kind: EventKind,
) {
    if let Some(previous) = subscription.take() {
        previous.task.abort();
    }
    *subscription = Some(Subscription {
        kind,
        task: spawn_event_forwarder(events.subscribe(), notify_tx.clone(), kind),
    });
}

/// 停止指定类别的订阅（不同类别的退订不影响当前订阅）
fn stop_subscription(subscription: &mut Option<Subscription>, kind: EventKind) {
    match subscription {
        Some(current) if current.kind == kind => {
            current.task.abort();
            *subscription = None;
        }
        _ => {}
    }
}

/// 历史条目补推：`GetRecentLogs` / `GetRecentFileOps` 均返回
/// `{"entries": [...]}`，按订阅类别包装为对应事件
async fn push_history<T, F>(data: Value, notify_tx: &mpsc::Sender<Event>, wrap: F)
where
    T: serde::de::DeserializeOwned,
    F: Fn(T) -> Event,
{
    let Ok(entries) =
        serde_json::from_value::<Vec<T>>(data.get("entries").cloned().unwrap_or(Value::Null))
    else {
        return;
    };
    for entry in entries {
        if notify_tx.send(wrap(entry)).await.is_err() {
            return;
        }
    }
}

fn spawn_event_forwarder(
    mut rx: broadcast::Receiver<Event>,
    tx: mpsc::Sender<Event>,
    kind: EventKind,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if !kind.accepts(&event) {
                        continue;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Request;

    #[derive(Clone)]
    struct TestHandler;

    impl Handler for TestHandler {
        // 测试处理器没有真正的异步操作，保留 async 以贴近真实实现
        #[allow(clippy::unused_async_trait_impl)]
        async fn handle(&self, cmd: Command) -> Result<Value, HandlerError> {
            match cmd {
                Command::GetRecentLogs { .. } => Ok(serde_json::json!({
                    "entries": [{
                        "timestamp": "t",
                        "level": "info",
                        "source": "test",
                        "message": "history-log",
                        "client_ip": "",
                        "username": "",
                        "action": ""
                    }]
                })),
                Command::GetRecentFileOps { .. } => Ok(serde_json::json!({
                    "entries": [{
                        "timestamp": "t",
                        "username": "alice",
                        "client_ip": "127.0.0.1",
                        "operation": "UPLOAD",
                        "file_path": "/Desktop/a.txt",
                        "file_size": 1,
                        "protocol": "FTP",
                        "success": true,
                        "message": ""
                    }, {
                        "timestamp": "t",
                        "username": "alice",
                        "client_ip": "127.0.0.1",
                        "operation": "DOWNLOAD",
                        "file_path": "/Desktop/b.txt",
                        "file_size": 2,
                        "protocol": "SFTP",
                        "success": true,
                        "message": ""
                    }]
                })),
                other => Ok(serde_json::json!({ "handled": format!("{other:?}") })),
            }
        }
    }

    fn sample_log(message: &str) -> Event {
        Event::Log {
            entry: LogEntry {
                timestamp: "t".into(),
                level: "info".into(),
                source: "test".into(),
                message: message.into(),
                client_ip: String::new(),
                username: String::new(),
                action: String::new(),
            },
        }
    }

    fn sample_file_op(operation: &str) -> Event {
        Event::FileOp {
            entry: FileOpLogEntry {
                timestamp: "t".into(),
                username: "alice".into(),
                client_ip: "127.0.0.1".into(),
                operation: operation.into(),
                file_path: "/Desktop/a.txt".into(),
                file_size: 1,
                protocol: "FTP".into(),
                success: true,
                message: String::new(),
            },
        }
    }

    /// 读取一帧直到拿到指定 id 的响应；期间收到的通知追加到 `events`
    async fn read_until_response<R: AsyncRead + Unpin>(
        reader: &mut R,
        id: u64,
        events: &mut Vec<Event>,
    ) -> Response {
        loop {
            match framing::read_frame(reader)
                .await
                .expect("读取帧")
                .expect("连接不应关闭")
            {
                Message::Notification(Notification { event }) => events.push(event),
                Message::Response(resp) if resp.id == id => return resp,
                other => panic!("unexpected message: {other:?}"),
            }
        }
    }

    async fn read_notification<R: AsyncRead + Unpin>(reader: &mut R) -> Event {
        match framing::read_frame(reader)
            .await
            .expect("读取帧")
            .expect("连接不应关闭")
        {
            Message::Notification(Notification { event }) => event,
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn event_kind_filters_by_subscription() {
        assert!(EventKind::Log.accepts(&sample_log("x")));
        assert!(!EventKind::Log.accepts(&sample_file_op("UPLOAD")));
        assert!(EventKind::FileOp.accepts(&sample_file_op("UPLOAD")));
        assert!(!EventKind::FileOp.accepts(&sample_log("x")));
    }

    #[tokio::test]
    async fn file_op_subscription_pushes_history_and_only_file_op_events() {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (mut reader, mut writer) = split(Box::new(client) as crate::transport::Duplex);
        let (events_tx, _) = broadcast::channel::<Event>(16);
        let server_task = tokio::spawn(handle_conn(
            Box::new(server) as crate::transport::Duplex,
            TestHandler,
            events_tx.clone(),
            "test-token",
        ));

        framing::write_frame(
            &mut writer,
            &Message::Hello(Hello {
                token: "test-token".into(),
            }),
        )
        .await
        .unwrap();
        assert!(matches!(
            framing::read_frame(&mut reader).await.unwrap().unwrap(),
            Message::HelloAck
        ));

        // 订阅审计流：服务端应补推 2 条历史，并只转发 FileOp
        framing::write_frame(
            &mut writer,
            &Message::Request(Request {
                id: 1,
                cmd: Command::SubscribeFileOps { tail_count: 2 },
            }),
        )
        .await
        .unwrap();
        let mut history = Vec::new();
        let resp = read_until_response(&mut reader, 1, &mut history).await;
        assert!(matches!(resp.result, crate::protocol::OpResult::Ok { .. }));
        while history.len() < 2 {
            history.push(read_notification(&mut reader).await);
        }
        assert!(matches!(history[0], Event::FileOp { .. }));
        assert!(matches!(history[1], Event::FileOp { .. }));

        // 同时广播程序日志与审计事件：审计流只应收到后者
        events_tx.send(sample_log("live-log")).unwrap();
        events_tx.send(sample_file_op("LIVE_OPERATION")).unwrap();
        match read_notification(&mut reader).await {
            Event::FileOp { entry } => assert_eq!(entry.operation, "LIVE_OPERATION"),
            Event::Log { entry } => panic!("审计流收到程序日志: {}", entry.message),
        }

        // 退订后不再收到审计事件
        framing::write_frame(
            &mut writer,
            &Message::Request(Request {
                id: 2,
                cmd: Command::UnsubscribeFileOps,
            }),
        )
        .await
        .unwrap();
        let mut ignored = Vec::new();
        let resp = read_until_response(&mut reader, 2, &mut ignored).await;
        assert!(matches!(resp.result, crate::protocol::OpResult::Ok { .. }));
        // 退订后广播通道已无接收者，send 返回 Err 属预期
        let _ = events_tx.send(sample_file_op("AFTER_UNSUBSCRIBE"));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(200),
                read_notification(&mut reader)
            )
            .await
            .is_err(),
            "退订后不应再收到推送"
        );

        drop(writer);
        drop(reader);
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), server_task)
            .await
            .expect("服务端连接应退出")
            .expect("连接任务不应 panic");
        assert!(result.is_ok());
    }
}

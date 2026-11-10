//! 实时日志 SSE 流（`GET /api/logs/stream?tail=N` / `GET /api/fileop/stream?tail=N`）
//!
//! `SubscribeLogs`/`UnsubscribeLogs` 按 IPC 连接记账（ipc/server.rs 的
//! `log_forward` 每连接持有转发任务），共享 `Client` 的任一退订会终止
//! 所有流的推送——因此**每个 SSE 流独占一条专用连接**：
//!
//! 浏览器断开 → handler future drop → 流结束 → [`Client::close`] 中止读
//! 任务 → 连接关闭 → 服务端 `handle_conn` 退出并自动 abort 推送任务。
//!
//! 订阅顺序：先 `subscribe_events()` 取广播接收端，再发订阅/取历史
//! （服务端"先订阅后补推历史"，反序会丢历史）。
//!
//! 两条流的分野：程序日志流经 `SubscribeLogs` 由 IPC 服务端补推历史
//! （`Event::Log`）；文件操作审计流经 `GetRecentFileOps` 在本层补推
//! 历史，再转发广播中的 `Event::FileOp` 实时条目。

use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio::sync::OwnedSemaphorePermit;
use tokio_stream::Stream;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};

use fftp_ipc::client::Client;
use fftp_ipc::protocol::{Command, Event as IpcEvent, FileOpLogEntry};

use crate::auth::AuthedUser;
use crate::error::ApiError;
use crate::routes::TailQuery;
use crate::state::{AppState, MAX_SSE_STREAMS};

/// 尝试占用一个 SSE 流配额；超限返回 429
fn acquire_slot(state: &AppState) -> Result<OwnedSemaphorePermit, ApiError> {
    Arc::clone(&state.sse_slots)
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_streams",
                format!("SSE 日志流数量已达上限（{MAX_SSE_STREAMS}）"),
            )
        })
}

/// GET /api/logs/stream → 程序日志 SSE 流（事件 `log`）
///
/// # Errors
/// 连接 fftpd 失败或订阅失败时返回错误
pub async fn logs_stream(
    _user: AuthedUser,
    State(state): State<Arc<AppState>>,
    Query(q): Query<TailQuery>,
) -> Result<Response, ApiError> {
    let permit = acquire_slot(&state)?;
    // 专用连接（独占订阅，见模块注释）
    let client = Client::connect()
        .await
        .map_err(|e| ApiError::internal(format!("连接 fftpd 失败: {e:#}")))?;

    // 先取广播接收端，再订阅（保证补推历史不丢）
    let events = client.subscribe_events();
    client
        .request(Command::SubscribeLogs { tail_count: q.tail })
        .await
        .map_err(ApiError::from)?;

    Ok(sse_response(EventStream {
        inner: BroadcastStream::new(events),
        client: Some(client),
        pending: VecDeque::new(),
        fileop: false,
        _permit: permit,
    }))
}

/// GET /api/fileop/stream → 文件操作审计 SSE 流（事件 `fileop`）
///
/// # Errors
/// 连接 fftpd 失败时返回错误；历史读取失败仅告警并降级为只推实时条目
pub async fn fileop_stream(
    _user: AuthedUser,
    State(state): State<Arc<AppState>>,
    Query(q): Query<TailQuery>,
) -> Result<Response, ApiError> {
    let permit = acquire_slot(&state)?;
    let client = Client::connect()
        .await
        .map_err(|e| ApiError::internal(format!("连接 fftpd 失败: {e:#}")))?;

    // 先取广播接收端再取历史：间隙条目经广播补上（可能与历史重复，少见可接受）
    let events = client.subscribe_events();
    let pending = if q.tail > 0 {
        match client
            .request(Command::GetRecentFileOps { count: q.tail })
            .await
        {
            Ok(data) => match serde_json::from_value::<FileOpEntries>(data) {
                Ok(parsed) => parsed.entries,
                Err(e) => {
                    tracing::warn!("读取订阅历史审计条目失败: {e}");
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::warn!("读取订阅历史审计条目失败: {e}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    Ok(sse_response(EventStream {
        inner: BroadcastStream::new(events),
        client: Some(client),
        pending: pending.into(),
        fileop: true,
        _permit: permit,
    }))
}

fn sse_response(stream: EventStream) -> Response {
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// `GetRecentFileOps` 响应
#[derive(Debug, Deserialize)]
struct FileOpEntries {
    #[serde(default)]
    entries: Vec<FileOpLogEntry>,
}

/// SSE 事件流：持有专用 IPC 连接直至流结束
struct EventStream {
    inner: BroadcastStream<IpcEvent>,
    /// `None` 表示连接已释放
    client: Option<Client>,
    /// 待补推的历史审计条目（仅 fileop 流；程序日志的补推由 IPC 服务端完成）
    pending: VecDeque<FileOpLogEntry>,
    /// true = 文件操作审计流（转发 `Event::FileOp`），false = 程序日志流（`Event::Log`）
    fileop: bool,
    /// 流存活期间持有的并发配额（drop 时归还）
    _permit: OwnedSemaphorePermit,
}

impl EventStream {
    /// 流结束时释放专用连接（服务端随之自动清理推送任务）
    fn release(&mut self) {
        if let Some(client) = self.client.take() {
            client.close();
        }
    }

    /// 序列化为 SSE 事件；失败（不应发生）返回 `None` 并由调用方跳过该条
    fn emit(entry: &impl serde::Serialize, name: &str) -> Option<Result<Event, Infallible>> {
        match serde_json::to_string(entry) {
            Ok(data) => Some(Ok(Event::default().event(name).data(data))),
            Err(e) => {
                tracing::warn!("日志条目序列化失败，已跳过: {e}");
                None
            }
        }
    }
}

impl Stream for EventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // 先补推历史条目（仅 fileop 流有存量）
        while let Some(entry) = self.pending.pop_front() {
            if let Some(item) = Self::emit(&entry, "fileop") {
                return Poll::Ready(Some(item));
            }
        }

        loop {
            match std::task::ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(IpcEvent::Log { entry })) if !self.fileop => {
                    return match Self::emit(&entry, "log") {
                        Some(item) => Poll::Ready(Some(item)),
                        None => continue,
                    };
                }
                Some(Ok(IpcEvent::FileOp { entry })) if self.fileop => {
                    return match Self::emit(&entry, "fileop") {
                        Some(item) => Poll::Ready(Some(item)),
                        None => continue,
                    };
                }
                // 另一通道的事件不归本流，跳过
                Some(Ok(_)) => {}
                Some(Err(BroadcastStreamRecvError::Lagged(n))) => {
                    // 广播通道积压丢弃：告知客户端缺口
                    let msg = format!("接收落后，丢弃 {n} 条日志");
                    tracing::warn!("{msg}");
                    return Poll::Ready(Some(Ok(Event::default().event("notice").data(msg))));
                }
                None => {
                    self.release();
                    return Poll::Ready(None);
                }
            }
        }
    }
}

impl Drop for EventStream {
    fn drop(&mut self) {
        // 覆盖未走正常流结束路径的 drop（如响应被提前取消）
        self.release();
    }
}

//! 实时日志 SSE 流（`GET /api/logs/stream?tail=N`）
//!
//! `SubscribeLogs`/`UnsubscribeLogs` 按 IPC 连接记账（ipc/server.rs 的
//! `log_forward` 每连接持有转发任务），共享 `Client` 的任一退订会终止
//! 所有流的推送——因此**每个 SSE 流独占一条专用连接**：
//!
//! 浏览器断开 → handler future drop → 流结束 → [`Client::close`] 中止读
//! 任务 → 连接关闭 → 服务端 `handle_conn` 退出并自动 abort 推送任务。
//!
//! 订阅顺序：先 `subscribe_events()` 取广播接收端，再发 `SubscribeLogs`
//! （服务端"先订阅后补推历史"，反序会丢历史）。

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::Query;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
use tokio_stream::Stream;

use fftp_ipc::client::Client;
use fftp_ipc::protocol::{Command, Event as IpcEvent};

use crate::auth::AuthedUser;
use crate::error::ApiError;
use crate::routes::TailQuery;

/// GET /api/logs/stream → SSE 日志流
///
/// # Errors
/// 连接 fftpd 失败或订阅失败时返回错误
pub async fn logs_stream(
    _user: AuthedUser,
    Query(q): Query<TailQuery>,
) -> Result<Response, ApiError> {
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

    let stream = LogStream {
        inner: BroadcastStream::new(events),
        client: Some(client),
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()).into_response())
}

/// SSE 事件流：持有专用 IPC 连接直至流结束
struct LogStream {
    inner: BroadcastStream<IpcEvent>,
    /// `None` 表示连接已释放
    client: Option<Client>,
}

impl LogStream {
    /// 流结束时释放专用连接（服务端随之自动清理推送任务）
    fn release(&mut self) {
        if let Some(client) = self.client.take() {
            client.close();
        }
    }
}

impl Stream for LogStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match std::task::ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(IpcEvent::Log { entry })) => {
                    match serde_json::to_string(&entry) {
                        Ok(data) => {
                            return Poll::Ready(Some(Ok(Event::default().event("log").data(data))));
                        }
                        Err(e) => tracing::warn!("日志条目序列化失败，已跳过: {e}"),
                    }
                }
                Some(Err(BroadcastStreamRecvError::Lagged(n))) => {
                    // 广播通道积压丢弃：告知客户端缺口
                    let msg = format!("接收落后，丢弃 {n} 条日志");
                    tracing::warn!("{msg}");
                    return Poll::Ready(Some(Ok(
                        Event::default().event("notice").data(msg)
                    )));
                }
                None => {
                    self.release();
                    return Poll::Ready(None);
                }
            }
        }
    }
}

impl Drop for LogStream {
    fn drop(&mut self) {
        // 覆盖未走正常流结束路径的 drop（如响应被提前取消）
        self.release();
    }
}

//! 实时日志 SSE 流（`GET /api/logs/stream?tail=N` / `GET /api/fileop/stream?tail=N` /
//! `GET /api/status/stream`）
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
//! 三条流的分野：程序日志流订阅 `SubscribeLogs`，文件操作审计流订阅
//! `SubscribeFileOps`，服务状态流订阅 `SubscribeServiceState`；
//! 历史补推与实时事件过滤均由 IPC 服务端按订阅类别完成
//! （见 `fftp_ipc::server`），本层只负责序列化为对应 SSE 事件名。

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use tokio::sync::OwnedSemaphorePermit;
use tokio_stream::Stream;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};

use fftp_ipc::client::Client;
use fftp_ipc::protocol::{Command, Event as IpcEvent};

use crate::auth::AuthedUser;
use crate::error::ApiError;
use crate::session::session_token_from_cookie;
use crate::state::{AppState, MAX_SSE_STREAMS};

/// SSE 尾随条数查询参数
#[derive(Debug, serde::Deserialize)]
pub struct TailQuery {
    #[serde(default = "default_tail")]
    pub tail: u32,
}

fn default_tail() -> u32 {
    200
}

/// 已建立 SSE 流的会话复核间隔
///
/// 登出/会话过期/管理员改密后，`SessionStore` 会移除或判定 token 失效；
/// 流若只在建立时校验一次，客户端保持连接即可继续接收日志，故运行期
/// 按此间隔复核（keep-alive 保证 `poll_next` 至少每 15s 被调用一次）。
const AUTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

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
    user: AuthedUser,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<TailQuery>,
) -> Result<Response, ApiError> {
    let permit = acquire_slot(&state)?;
    let token = session_token_for_stream(&user, &headers);
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
        kind: StreamKind::Log,
        state,
        token,
        last_auth_check: Instant::now(),
        _permit: permit,
    }))
}

/// GET /api/fileop/stream → 文件操作审计 SSE 流（事件 `fileop`）
///
/// # Errors
/// 连接 fftpd 失败或订阅失败时返回错误
pub async fn fileop_stream(
    user: AuthedUser,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<TailQuery>,
) -> Result<Response, ApiError> {
    let permit = acquire_slot(&state)?;
    let token = session_token_for_stream(&user, &headers);
    let client = Client::connect()
        .await
        .map_err(|e| ApiError::internal(format!("连接 fftpd 失败: {e:#}")))?;

    // 先取广播接收端，再订阅（服务端先订阅后补推历史，保证不丢）
    let events = client.subscribe_events();
    client
        .request(Command::SubscribeFileOps { tail_count: q.tail })
        .await
        .map_err(ApiError::from)?;

    Ok(sse_response(EventStream {
        inner: BroadcastStream::new(events),
        client: Some(client),
        kind: StreamKind::FileOp,
        state,
        token,
        last_auth_check: Instant::now(),
        _permit: permit,
    }))
}

/// GET /api/status/stream → 协议服务状态变更 SSE 流（事件 `service_state`）
///
/// 当 FTP/SFTP 启停/重启/配置热重载后 fftpd 广播状态变更事件，
/// 本流实时透传给前端以驱动服务标签页状态徽章自动刷新。
///
/// # Errors
/// 连接 fftpd 失败或订阅失败时返回错误
pub async fn status_stream(
    user: AuthedUser,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let permit = acquire_slot(&state)?;
    let token = session_token_for_stream(&user, &headers);
    let client = Client::connect()
        .await
        .map_err(|e| ApiError::internal(format!("连接 fftpd 失败: {e:#}")))?;

    let events = client.subscribe_events();
    client
        .request(Command::SubscribeServiceState)
        .await
        .map_err(ApiError::from)?;

    Ok(sse_response(EventStream {
        inner: BroadcastStream::new(events),
        client: Some(client),
        kind: StreamKind::ServiceState,
        state,
        token,
        last_auth_check: Instant::now(),
        _permit: permit,
    }))
}

/// 取运行期复核用的会话 token；`api_token` 认证无会话，返回 `None` 跳过复核
fn session_token_for_stream(user: &AuthedUser, headers: &HeaderMap) -> Option<String> {
    if user.0 == "api_token" {
        return None;
    }
    session_token_from_cookie(headers)
}

fn sse_response(stream: EventStream) -> Response {
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// 流类别：决定对 IPC 广播的过滤与输出的 SSE 事件名
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamKind {
    Log,
    FileOp,
    ServiceState,
}

/// SSE 事件流：持有专用 IPC 连接直至流结束
struct EventStream {
    inner: BroadcastStream<IpcEvent>,
    /// `None` 表示连接已释放
    client: Option<Client>,
    kind: StreamKind,
    /// 运行期复核会话所需的共享状态
    state: Arc<AppState>,
    /// 建立流时的会话 token（`api_token` 认证为 `None`，不复核）
    token: Option<String>,
    /// 上次会话复核时间
    last_auth_check: Instant,
    /// 流存活期间持有的并发配额（drop 时归还）
    _permit: OwnedSemaphorePermit,
}

impl EventStream {
    /// 会话已失效（登出/过期/改密）则返回 `true`
    fn session_expired(&mut self) -> bool {
        let Some(token) = &self.token else {
            return false;
        };
        if self.last_auth_check.elapsed() < AUTH_CHECK_INTERVAL {
            return false;
        }
        self.last_auth_check = Instant::now();
        self.state
            .sessions
            .get_valid(token, &self.state.admins())
            .is_none()
    }

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
        // 会话已失效（登出/过期/改密）则主动断开，避免登出后继续收日志
        if self.session_expired() {
            self.release();
            return Poll::Ready(None);
        }

        loop {
            match std::task::ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(IpcEvent::Log { entry })) if self.kind == StreamKind::Log => {
                    return match Self::emit(&entry, "log") {
                        Some(item) => Poll::Ready(Some(item)),
                        None => continue,
                    };
                }
                Some(Ok(IpcEvent::FileOp { entry })) if self.kind == StreamKind::FileOp => {
                    return match Self::emit(&entry, "fileop") {
                        Some(item) => Poll::Ready(Some(item)),
                        None => continue,
                    };
                }
                Some(Ok(IpcEvent::ServiceStateChanged {
                    target,
                    action,
                    ftp_running,
                    sftp_running,
                })) if self.kind == StreamKind::ServiceState => {
                    let payload = serde_json::json!({
                        "target": target,
                        "action": action,
                        "ftp_running": ftp_running,
                        "sftp_running": sftp_running,
                    });
                    return match Self::emit(&payload, "service_state") {
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

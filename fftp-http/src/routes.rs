//! 路由组装与 IPC 命令代理 handler
//!
//! REST API 是 fftp-ipc 命令面的 1:1 映射：fftpd 仍是配置/用户数据的
//! 唯一写入者，本层不做业务校验（SaveConfig/SaveUsers 由 fftpd 侧
//! fftp-common 类型校验并回传错误）。写操作统一经 `AppState::audit`
//! 落审计日志。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{middleware, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use fftp_ipc::client::parse_data;
use fftp_ipc::protocol::{Command, ServiceTarget};

use crate::auth::{self, AuthedUser};
use crate::error::{ApiError, ApiResult};
use crate::ip_filter;
use crate::state::AppState;

// ---------- DTO（形状对齐 fftp-gui/src/ipc_service.rs） ----------

/// `GetStatus` 响应
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerStatus {
    pub ftp_running: bool,
    pub sftp_running: bool,
    pub version: String,
    pub config_path: String,
    pub users_path: String,
    pub endpoint: String,
}

/// `GetInitialState` 响应
#[derive(Debug, Serialize, Deserialize)]
pub struct InitialState {
    pub config: String,
    pub users: String,
}

/// `GetConfig`/`SaveConfig`/`GetUsers`/`SaveUsers` 响应
#[derive(Debug, Serialize, Deserialize)]
pub struct TextContent {
    pub content: String,
}

/// 文本写入请求体
#[derive(Debug, Deserialize)]
pub struct TextBody {
    pub content: String,
}

/// 路径请求体（目录辅助、日志文件内容）
#[derive(Debug, Deserialize)]
pub struct PathBody {
    pub path: String,
}

/// 路径 + 条数请求体（日志文件内容）
#[derive(Debug, Deserialize)]
pub struct PathCountBody {
    pub path: String,
    #[serde(default = "default_count")]
    pub count: u32,
}

/// 服务操作请求体
#[derive(Debug, Deserialize)]
pub struct ServiceBody {
    #[serde(default)]
    pub which: ServiceTarget,
}

/// 日志配置请求体（`SaveLogConfig`）
#[derive(Debug, Deserialize)]
pub struct LogConfigBody {
    pub log_dir: String,
    pub log_level: String,
    pub max_log_size: u64,
    pub max_log_files: u32,
    pub enable_gui_logging: bool,
}

/// 近期日志条数查询参数
#[derive(Debug, Deserialize)]
pub struct CountQuery {
    #[serde(default = "default_count")]
    pub count: u32,
}

/// SSE 尾随条数查询参数
#[derive(Debug, Deserialize)]
pub struct TailQuery {
    #[serde(default = "default_count")]
    pub tail: u32,
}

fn default_count() -> u32 {
    200
}

// ---------- Router 组装 ----------

/// 组装完整 Router：public（login/logout）+ protected（认证中间件）
/// + 静态资源；IP 过滤最后套上覆盖全部路由
pub fn build_router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/daemon", get(daemon_state))
        .route("/api/service/{action}", post(service_action))
        .route("/api/shutdown", post(shutdown))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/users", get(get_users).put(put_users))
        .route("/api/initial", get(get_initial))
        .route("/api/user-directories/ensure", post(ensure_user_dirs))
        .route("/api/user-directory", post(create_user_dir))
        .route("/api/directory-permissions", post(setup_dir_perms))
        .route("/api/logs", get(recent_logs))
        .route("/api/logs/files", get(log_files))
        .route("/api/logs/content", post(log_content))
        .route("/api/logs/stream", get(crate::sse::logs_stream))
        .route("/api/fileop/files", get(fileop_files))
        .route("/api/fileop/content", post(fileop_content))
        .route("/api/log-config", put(put_log_config))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::auth_middleware,
        ));

    let public = Router::new()
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout));

    public
        .merge(protected)
        .route("/", get(index))
        .route("/static/{file}", get(static_asset))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            ip_filter::ip_filter,
        ))
        .with_state(state)
}

// ---------- 静态资源 ----------

/// 首页
async fn index() -> Response {
    (
        [(CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../ui/index.html"),
    )
        .into_response()
}

/// 静态资源（app.js / style.css）
async fn static_asset(Path(file): Path<String>) -> Response {
    match file.as_str() {
        "app.js" => (
            [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
            include_str!("../ui/app.js"),
        )
            .into_response(),
        "style.css" => (
            [(CONTENT_TYPE, "text/css; charset=utf-8")],
            include_str!("../ui/style.css"),
        )
            .into_response(),
        _ => ApiError::not_found().into_response(),
    }
}

// ---------- 状态与生命周期 ----------

/// GET /api/status → GetStatus
async fn get_status(State(state): State<Arc<AppState>>) -> ApiResult<Json<ServerStatus>> {
    let data = state.daemon.request(Command::GetStatus).await?;
    Ok(Json(parse_data(data)?))
}

/// GET /api/daemon → 连接管理器状态（UI 离线横幅）
async fn daemon_state(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(serde_json::json!({"connected": state.daemon.is_connected()}))
}

/// POST /api/service/{start|stop|restart}，body `{"which": "all"|"ftp"|"sftp"}`
async fn service_action(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Path(action): Path<String>,
    Json(body): Json<ServiceBody>,
) -> ApiResult<Json<Value>> {
    let cmd = match action.as_str() {
        "start" => Command::StartService { which: body.which },
        "stop" => Command::StopService { which: body.which },
        "restart" => Command::RestartService { which: body.which },
        _ => return Err(ApiError::not_found()),
    };
    let data = state.daemon.request(cmd).await?;
    state
        .audit(&user.0, "service", &action, &format!("{:?}", body.which))
        .await;
    Ok(Json(data))
}

/// POST /api/shutdown（UI 需二次确认）
async fn shutdown(State(state): State<Arc<AppState>>, user: AuthedUser) -> ApiResult<Json<Value>> {
    state
        .audit(&user.0, "shutdown", "fftpd", "守护进程关停")
        .await;
    let data = state.daemon.request(Command::Shutdown).await?;
    Ok(Json(data))
}

// ---------- 配置与用户 ----------

/// GET /api/config → GetConfig
async fn get_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<TextContent>> {
    let data = state.daemon.request(Command::GetConfig).await?;
    Ok(Json(parse_data(data)?))
}

/// PUT /api/config，body `{"content": "..."}` → SaveConfig
async fn put_config(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<TextBody>,
) -> ApiResult<Json<Value>> {
    let result = state
        .daemon
        .request(Command::SaveConfig { content: body.content.clone() })
        .await;
    match &result {
        Ok(_) => state.audit(&user.0, "save_config", "config.toml", "配置已保存").await,
        Err(e) => state.audit(&user.0, "save_config_failed", "config.toml", &e.to_string()).await,
    }
    Ok(Json(result?))
}

/// GET /api/users → GetUsers
async fn get_users(State(state): State<Arc<AppState>>) -> ApiResult<Json<TextContent>> {
    let data = state.daemon.request(Command::GetUsers).await?;
    Ok(Json(parse_data(data)?))
}

/// PUT /api/users，body `{"content": "..."}` → SaveUsers
async fn put_users(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<TextBody>,
) -> ApiResult<Json<Value>> {
    let result = state
        .daemon
        .request(Command::SaveUsers { content: body.content.clone() })
        .await;
    match &result {
        Ok(_) => state.audit(&user.0, "save_users", "users.json", "用户库已保存").await,
        Err(e) => state.audit(&user.0, "save_users_failed", "users.json", &e.to_string()).await,
    }
    Ok(Json(result?))
}

/// GET /api/initial → GetInitialState（config + users 原文）
async fn get_initial(State(state): State<Arc<AppState>>) -> ApiResult<Json<InitialState>> {
    let data = state.daemon.request(Command::GetInitialState).await?;
    Ok(Json(parse_data(data)?))
}

// ---------- 目录辅助 ----------

/// POST /api/user-directories/ensure → EnsureUserDirectories
async fn ensure_user_dirs(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let data = state.daemon.request(Command::EnsureUserDirectories).await?;
    Ok(Json(data))
}

/// POST /api/user-directory，body `{"path": "..."}` → CreateUserDirectory
async fn create_user_dir(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<PathBody>,
) -> ApiResult<Json<Value>> {
    let data = state
        .daemon
        .request(Command::CreateUserDirectory { path: body.path.clone() })
        .await?;
    state.audit(&user.0, "create_dir", &body.path, "创建用户主目录").await;
    Ok(Json(data))
}

/// POST /api/directory-permissions，body `{"path": "..."}` → SetupDirectoryPermissions
async fn setup_dir_perms(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<PathBody>,
) -> ApiResult<Json<Value>> {
    let data = state
        .daemon
        .request(Command::SetupDirectoryPermissions { path: body.path.clone() })
        .await?;
    state.audit(&user.0, "setup_permissions", &body.path, "设置目录权限").await;
    Ok(Json(data))
}

// ---------- 日志 ----------

/// GET /api/logs?count=200 → GetRecentLogs
async fn recent_logs(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CountQuery>,
) -> ApiResult<Json<Value>> {
    let data = state
        .daemon
        .request(Command::GetRecentLogs { count: q.count })
        .await?;
    Ok(Json(data))
}

/// GET /api/logs/files → GetLogFiles
async fn log_files(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let data = state.daemon.request(Command::GetLogFiles).await?;
    Ok(Json(data))
}

/// POST /api/logs/content，body `{"path": "...", "count": 200}` → GetLogFileContent
async fn log_content(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PathCountBody>,
) -> ApiResult<Json<Value>> {
    let data = state
        .daemon
        .request(Command::GetLogFileContent { path: body.path, count: body.count })
        .await?;
    Ok(Json(data))
}

/// PUT /api/log-config → SaveLogConfig
async fn put_log_config(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<LogConfigBody>,
) -> ApiResult<Json<Value>> {
    let result = state
        .daemon
        .request(Command::SaveLogConfig {
            log_dir: body.log_dir,
            log_level: body.log_level,
            max_log_size: body.max_log_size,
            max_log_files: body.max_log_files,
            enable_gui_logging: body.enable_gui_logging,
        })
        .await;
    match &result {
        Ok(_) => state.audit(&user.0, "save_log_config", "logging", "日志配置已保存").await,
        Err(e) => state.audit(&user.0, "save_log_config_failed", "logging", &e.to_string()).await,
    }
    Ok(Json(result?))
}

// ---------- 文件操作日志 ----------

/// GET /api/fileop/files → GetFileOpLogFiles
async fn fileop_files(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let data = state.daemon.request(Command::GetFileOpLogFiles).await?;
    Ok(Json(data))
}

/// POST /api/fileop/content，body `{"path": "...", "count": 200}` → GetFileOpLogContent
async fn fileop_content(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PathCountBody>,
) -> ApiResult<Json<Value>> {
    let data = state
        .daemon
        .request(Command::GetFileOpLogContent { path: body.path, count: body.count })
        .await?;
    Ok(Json(data))
}

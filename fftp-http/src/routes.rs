//! 路由组装与 IPC 命令代理 handler
//!
//! REST API 是 fftp-ipc 命令面的 1:1 映射：fftpd 仍是配置/用户数据的
//! 唯一写入者，本层不做业务校验（SaveConfig/SaveUsers 由 fftpd 侧
//! fftp-common 类型校验并回传错误）。写操作统一经 `AppState::audit`
//! 落审计日志。
//!
//! 例外：`/api/admin-users` 管理 fftp-http 自身管理员账户，不经 IPC，
//! 直接读写 fftp-http.toml（见 [`crate::config`]）。

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

/// 口令哈希请求体（`UserManager::hash_password` 本地计算，不经 IPC）
#[derive(Debug, Deserialize)]
pub struct UserHashBody {
    pub password: String,
}

/// 管理员账户条目（GET 响应；PUT 输入，password 仅新增/改密时携带）
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminUserEntry {
    pub username: String,
    #[serde(default, skip_serializing)]
    pub password: String,
}

/// 管理员账户列表响应/请求体
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminUsersBody {
    pub users: Vec<AdminUserEntry>,
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
        .route("/api/user-hash", post(user_hash))
        .route("/api/admin-users", get(get_admin_users).put(put_admin_users))
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
        .route("/api/fileop/stream", get(crate::sse::fileop_stream))
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

/// POST /api/user-hash，body `{"password": "..."}` → Argon2id PHC 哈希
/// （新增用户时前端本地调用，与 fftpd 口令校验同策略参数）
async fn user_hash(
    _user: AuthedUser,
    Json(body): Json<UserHashBody>,
) -> ApiResult<Json<Value>> {
    if body.password.is_empty() {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "validation",
            "口令不能为空",
        ));
    }
    let hash = fftp_common::users::UserManager::hash_password(&body.password)
        .map_err(|e| ApiError::internal(format!("口令哈希失败: {e:#}")))?;
    Ok(Json(serde_json::json!({ "hash": hash })))
}

/// GET /api/initial → GetInitialState（config + users 原文）
async fn get_initial(State(state): State<Arc<AppState>>) -> ApiResult<Json<InitialState>> {
    let data = state.daemon.request(Command::GetInitialState).await?;
    Ok(Json(parse_data(data)?))
}

// ---------- fftp-http 自身管理员（不经 IPC，本地配置文件） ----------

/// GET /api/admin-users → fftp-http 管理员账户列表（不含口令哈希）
async fn get_admin_users(State(state): State<Arc<AppState>>) -> Json<AdminUsersBody> {
    Json(AdminUsersBody {
        users: state
            .admins()
            .iter()
            .map(|u| AdminUserEntry { username: u.username.clone(), password: String::new() })
            .collect(),
    })
}

/// PUT /api/admin-users，body `{"users": [{"username", "password"?}]}`
///
/// 全量替换管理员列表：带 `password` 的条目为新增/改密（本地 Argon2id 哈希），
/// 不带的沿用现有哈希（用户名必须已存在）。规则：至少保留一名管理员、
/// 用户名唯一且不含空白/路径分隔符、不能移除当前登录账户。
async fn put_admin_users(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<AdminUsersBody>,
) -> ApiResult<Json<AdminUsersBody>> {
    if body.users.is_empty() {
        return Err(ApiError::bad_request("至少保留一名管理员账户"));
    }
    let existing = state.admins();
    let mut new_users: Vec<crate::config::AdminUser> = Vec::with_capacity(body.users.len());
    for entry in &body.users {
        let name = entry.username.trim();
        if name.is_empty() {
            return Err(ApiError::bad_request("用户名不能为空"));
        }
        if name.len() > 64 || name.chars().any(|c| c.is_whitespace() || c.is_control() || "/\\\"'".contains(c)) {
            return Err(ApiError::bad_request(format!(
                "用户名 {name:?} 含非法字符（空白/引号/路径分隔符）或超过 64 字符"
            )));
        }
        if new_users.iter().any(|u| u.username == name) {
            return Err(ApiError::bad_request(format!("用户名重复: {name}")));
        }
        let password_hash = if entry.password.is_empty() {
            existing
                .iter()
                .find(|u| u.username == name)
                .map(|u| u.password_hash.clone())
                .ok_or_else(|| {
                    ApiError::bad_request(format!("新用户 {name} 必须提供口令"))
                })?
        } else {
            fftp_common::users::UserManager::hash_password(&entry.password)
                .map_err(|e| ApiError::internal(format!("口令哈希失败: {e:#}")))?
        };
        new_users.push(crate::config::AdminUser {
            username: name.to_string(),
            password_hash,
        });
    }
    // Web 会话操作者必须保留在列表中，避免自锁（api_token 认证无对应账户）
    if user.0 != "api_token" && !new_users.iter().any(|u| u.username == user.0) {
        return Err(ApiError::bad_request("不能移除当前登录账户"));
    }

    // 先落盘（校验通过才写），成功后再更新运行期列表
    crate::config::HttpConfig::save_admin_users(&state.http_config_path, &new_users)?;
    let count = new_users.len();
    state.set_admins(new_users);
    state
        .audit(&user.0, "save_admin_users", "fftp-http.toml", &format!("管理员共 {count} 名"))
        .await;
    Ok(Json(AdminUsersBody {
        users: body.users, // 原样回显（password 字段已被 skip_serializing 剔除）
    }))
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

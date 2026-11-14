//! 路由组装与 IPC 命令代理 handler
//!
//! REST API 是 fftp-ipc 命令面的 1:1 映射：fftpd 仍是配置/用户数据的
//! 唯一写入者，本层不做业务校验（SaveConfig/SaveUsers 由 fftpd 侧
//! fftp-common 类型校验并回传错误）。写操作统一经 `AppState::audit`
//! 落审计日志。
//!
//! 例外：`/api/admin-users` 管理 fftp-http 自身管理员账户，不经 IPC，
//! 直接读写 fftp-http.toml（见 [`crate::config`]）。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, SET_COOKIE};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router, middleware};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use fftp_ipc::client::parse_data;
use fftp_ipc::protocol::{Command, ServiceTarget};

use crate::auth::{self, AuthedUser};
use crate::error::{ApiError, ApiResult};
use crate::idle::{IdleSnapshot, ShutdownReason};
use crate::ip_filter;
use crate::state::AppState;
use crate::system_service;

// ---------- DTO ----------

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

fn default_true() -> bool {
    true
}

/// 页面心跳请求体
#[derive(Debug, Deserialize)]
pub struct HeartbeatBody {
    /// 标签页标识（同一浏览器多标签页各自独立）
    pub page_id: String,
    /// 页面是否可见（隐藏/关闭时上报 false）
    #[serde(default = "default_true")]
    pub visible: bool,
}

/// 主目录建议请求体
#[derive(Debug, Deserialize)]
pub struct SuggestBody {
    #[serde(default)]
    pub username: String,
}

/// 主目录建议响应
#[derive(Debug, Serialize)]
pub struct SuggestResponse {
    pub directories: Vec<String>,
}

/// 首次设置请求体
#[derive(Debug, Deserialize)]
pub struct SetupBody {
    #[serde(default)]
    pub token: String,
    pub username: String,
    pub password: String,
}

/// `/api/health` 响应（launcher 校验 `app` 身份，避免误开占用端口的其他程序）
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub app: &'static str,
    pub version: &'static str,
    pub setup_required: bool,
}

// ---------- Router 组装 ----------

/// 组装完整 Router：public（login/logout）+ protected（认证中间件）
/// + 静态资源；IP 过滤最后套上覆盖全部路由
pub fn build_router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/me", get(get_me))
        .route("/api/status", get(get_status))
        .route("/api/daemon", get(daemon_state))
        .route("/api/service/{action}", post(service_action))
        .route("/api/shutdown", post(shutdown))
        .route("/api/idle", get(get_idle).put(put_idle))
        .route("/api/activity", post(activity))
        .route("/api/heartbeat", post(heartbeat))
        .route("/api/self-shutdown", post(self_shutdown))
        .route("/api/system-service/status", get(system_service_status))
        .route("/api/system-service/{action}", post(system_service_action))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/users", get(get_users).put(put_users))
        .route("/api/user-hash", post(user_hash))
        .route(
            "/api/admin-users",
            get(get_admin_users).put(put_admin_users),
        )
        .route("/api/initial", get(get_initial))
        .route("/api/user-directories/ensure", post(ensure_user_dirs))
        .route("/api/user-directories/suggest", post(suggest_user_dirs))
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
        .route("/api/health", get(health))
        .route("/api/setup", post(do_setup))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout));

    public
        .merge(protected)
        .route("/", get(index))
        .route("/setup", get(setup_page))
        .route("/static/{file}", get(static_asset))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            ip_filter::ip_filter,
        ))
        .with_state(state)
}

// ---------- 静态资源 ----------

/// 首页：未完成首次设置时跳转引导页
async fn index(State(state): State<Arc<AppState>>) -> Response {
    if state.setup_required() {
        return Redirect::temporary("/setup").into_response();
    }
    (
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../ui/index.html"),
    )
        .into_response()
}

/// 首次设置引导页（POST 校验令牌与回环来源；页面本身无敏感信息）
async fn setup_page(State(state): State<Arc<AppState>>) -> Response {
    if !state.setup_required() {
        return Redirect::temporary("/").into_response();
    }
    (
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../ui/setup.html"),
    )
        .into_response()
}

/// GET /api/health → 身份与初始化状态（launcher 与监控使用，无需认证）
async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        app: "fftp-http",
        version: env!("CARGO_PKG_VERSION"),
        setup_required: state.setup_required(),
    })
}

/// POST /api/setup → 首次设置：创建第一名管理员并自动登录
///
/// 三重限制：仅在未配置管理员时可用、仅回环来源、须匹配启动时写入的
/// 一次性令牌（桌面入口从令牌文件拼到 URL 中）。
async fn do_setup(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<SetupBody>,
) -> Response {
    if !state.setup_required() {
        return ApiError::bad_request("已完成初始化，请直接登录").into_response();
    }
    if !crate::setup::is_loopback(peer) {
        return ApiError::forbidden("首次设置仅允许本机访问").into_response();
    }
    match crate::setup::read_token() {
        Some(expected) if auth::ct_eq(expected.as_str(), body.token.trim()) => {}
        Some(_) => {
            return ApiError::forbidden("引导令牌无效，请从桌面快捷方式重新打开").into_response();
        }
        None => {
            return ApiError::bad_request("引导令牌缺失，请重启 fftp-http 后重试").into_response();
        }
    }

    let name = body.username.trim();
    if name.is_empty() {
        return ApiError::bad_request("用户名不能为空").into_response();
    }
    if name.chars().count() > 64
        || name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/\\\"'".contains(c))
    {
        return ApiError::bad_request("用户名含非法字符（空白/引号/路径分隔符）或超过 64 字符")
            .into_response();
    }
    if body.password.chars().count() < 8 {
        return ApiError::bad_request("口令至少 8 个字符").into_response();
    }
    let hash = match tokio::task::spawn_blocking(move || {
        fftp_common::users::UserManager::hash_password(&body.password)
    })
    .await
    {
        Ok(Ok(hash)) => hash,
        Ok(Err(e)) => return ApiError::internal(format!("口令哈希失败: {e:#}")).into_response(),
        Err(e) => return ApiError::internal(format!("口令哈希任务失败: {e}")).into_response(),
    };
    let users = vec![crate::config::AdminUser {
        username: name.to_string(),
        password_hash: hash.clone(),
    }];
    let config_path = state.http_config_path.clone();
    let users_for_save = users.clone();
    let save_result = tokio::task::spawn_blocking(move || {
        crate::config::HttpConfig::save_admin_users(&config_path, &users_for_save)
    })
    .await;
    match save_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return ApiError::internal(format!("写入管理员配置失败: {e:#}")).into_response();
        }
        Err(e) => {
            return ApiError::internal(format!("写入管理员配置任务失败: {e}")).into_response();
        }
    }

    state.set_admins(users);
    crate::setup::clear_token();
    let token = state.sessions.create(name, &hash);
    let cookie = auth::session_cookie(&state, &token);
    state
        .audit(
            name,
            "setup",
            "fftp-http.toml",
            "首次设置完成，已创建管理员",
        )
        .await;
    tracing::info!("首次设置完成，管理员账户: {name}");
    (
        [(SET_COOKIE, cookie)],
        Json(serde_json::json!({"ok": true, "username": name})),
    )
        .into_response()
}

/// 静态资源（app.js / style.css）
async fn static_asset(Path(file): Path<String>) -> Response {
    match file.as_str() {
        "app.js" => (
            [
                (CONTENT_TYPE, "application/javascript; charset=utf-8"),
                (CACHE_CONTROL, "no-cache"),
            ],
            include_str!("../ui/app.js"),
        )
            .into_response(),
        "style.css" => (
            [
                (CONTENT_TYPE, "text/css; charset=utf-8"),
                (CACHE_CONTROL, "no-cache"),
            ],
            include_str!("../ui/style.css"),
        )
            .into_response(),
        _ => ApiError::not_found().into_response(),
    }
}

// ---------- 状态与生命周期 ----------

/// GET /api/me → 当前会话身份（页面刷新后恢复登录状态；不依赖 fftpd）
async fn get_me(user: AuthedUser) -> Json<Value> {
    Json(serde_json::json!({ "username": user.0 }))
}

/// GET /api/status → `GetStatus`
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

// ---------- fftp-http 自身生命周期（空闲关闭 / 关停） ----------

/// GET /api/idle → 当前空闲配置与剩余时间
async fn get_idle(State(state): State<Arc<AppState>>) -> Json<IdleSnapshot> {
    Json(state.idle.snapshot())
}

/// PUT /api/idle → 保存空闲自动关闭配置（仅关闭 fftp-http，不关闭 fftpd）
async fn put_idle(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(idle): Json<crate::config::IdleConfig>,
) -> ApiResult<Json<IdleSnapshot>> {
    if idle.enabled {
        if idle.timeout_secs < 30 {
            return Err(ApiError::bad_request("空闲时长不能小于 30 秒"));
        }
        if idle.warn_secs > idle.timeout_secs {
            return Err(ApiError::bad_request("倒计时提示不能大于空闲时长"));
        }
    }
    // 配置文件读写是同步 IO，移入阻塞线程避免占用异步 worker
    let config_path = state.http_config_path.clone();
    let idle_for_save = idle.clone();
    tokio::task::spawn_blocking(move || {
        crate::config::HttpConfig::save_idle(&config_path, &idle_for_save)
    })
    .await
    .map_err(|e| ApiError::internal(format!("保存空闲配置任务失败: {e}")))??;
    let snapshot = {
        state.idle.update(idle);
        state.idle.snapshot()
    };
    state
        .audit(
            &user.0,
            "save_idle",
            "fftp-http.toml",
            &format!(
                "enabled={} timeout={}s mode={} warn={}s",
                snapshot.enabled, snapshot.timeout_secs, snapshot.mode, snapshot.warn_secs
            ),
        )
        .await;
    Ok(Json(snapshot))
}

/// POST /api/activity → 真实用户操作（仅 `no_activity` 模式计时使用）
async fn activity(State(state): State<Arc<AppState>>, _user: AuthedUser) -> Json<Value> {
    state.idle.touch_activity();
    Json(serde_json::json!({"ok": true}))
}

/// POST /api/heartbeat → 可见页面心跳（页面隐藏/关闭时 `visible=false`）
async fn heartbeat(
    State(state): State<Arc<AppState>>,
    _user: AuthedUser,
    Json(body): Json<HeartbeatBody>,
) -> Json<Value> {
    let page_id = if body.page_id.trim().is_empty() {
        "default"
    } else {
        body.page_id.trim()
    };
    state.idle.touch_page(page_id, body.visible);
    Json(serde_json::json!({"ok": true}))
}

/// POST /api/self-shutdown → 手动关闭 fftp-http（不关闭 fftpd）
async fn self_shutdown(State(state): State<Arc<AppState>>, user: AuthedUser) -> Json<Value> {
    state
        .audit(&user.0, "self_shutdown", "fftp-http", "Web 服务手动关闭")
        .await;
    // 稍作延迟，确保响应先送达浏览器（页面据此显示关闭提示）
    let state = Arc::clone(&state);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        state.request_shutdown(ShutdownReason::Manual);
    });
    Json(serde_json::json!({"ok": true}))
}

// ---------- 系统服务（fftpd 守护进程 安装/卸载/启停/自启） ----------

/// GET /api/system-service/status → fftpd 系统服务状态
async fn system_service_status() -> ApiResult<Json<system_service::ServiceStatus>> {
    system_service::status()
        .await
        .map(Json)
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, "system_service", e))
}

/// POST /api/system-service/{install|uninstall|start|stop|restart|autostart-on|autostart-off}
async fn system_service_action(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Path(action): Path<String>,
) -> ApiResult<Json<Value>> {
    let action = system_service::Action::parse(&action).ok_or_else(ApiError::not_found)?;
    let result = system_service::perform(action).await;
    match &result {
        Ok(_) => {
            state
                .audit(&user.0, "system_service", action.as_str(), action.ok_text())
                .await;
        }
        Err(e) => {
            state
                .audit(
                    &user.0,
                    "system_service_failed",
                    action.as_str(),
                    &e.clone(),
                )
                .await;
        }
    }
    let output = result.map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, "system_service", e))?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "message": action.ok_text(),
        "output": output,
    })))
}

// ---------- 配置与用户 ----------

/// GET /api/config → `GetConfig`
async fn get_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<TextContent>> {
    let data = state.daemon.request(Command::GetConfig).await?;
    Ok(Json(parse_data(data)?))
}

/// PUT /api/config，body `{"content": "..."}` → `SaveConfig`
async fn put_config(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<TextBody>,
) -> ApiResult<Json<Value>> {
    let result = state
        .daemon
        .request(Command::SaveConfig {
            content: body.content.clone(),
        })
        .await;
    match &result {
        Ok(_) => {
            state
                .audit(&user.0, "save_config", "config.toml", "配置已保存")
                .await;
        }
        Err(e) => {
            state
                .audit(&user.0, "save_config_failed", "config.toml", &e.to_string())
                .await;
        }
    }
    Ok(Json(result?))
}

/// GET /api/users → `GetUsers`
async fn get_users(State(state): State<Arc<AppState>>) -> ApiResult<Json<TextContent>> {
    let data = state.daemon.request(Command::GetUsers).await?;
    Ok(Json(parse_data(data)?))
}

/// PUT /api/users，body `{"content": "..."}` → `SaveUsers`
async fn put_users(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<TextBody>,
) -> ApiResult<Json<Value>> {
    let result = state
        .daemon
        .request(Command::SaveUsers {
            content: body.content.clone(),
        })
        .await;
    match &result {
        Ok(_) => {
            state
                .audit(&user.0, "save_users", "users.json", "用户库已保存")
                .await;
        }
        Err(e) => {
            state
                .audit(&user.0, "save_users_failed", "users.json", &e.to_string())
                .await;
        }
    }
    Ok(Json(result?))
}

/// POST /api/user-hash，body `{"password": "..."}` → Argon2id PHC 哈希
/// （新增用户时前端本地调用，与 fftpd 口令校验同策略参数）
async fn user_hash(_user: AuthedUser, Json(body): Json<UserHashBody>) -> ApiResult<Json<Value>> {
    if body.password.is_empty() {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "validation",
            "口令不能为空",
        ));
    }
    let hash = tokio::task::spawn_blocking(move || {
        fftp_common::users::UserManager::hash_password(&body.password)
    })
    .await
    .map_err(|e| ApiError::internal(format!("口令哈希任务失败: {e}")))?
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
            .map(|u| AdminUserEntry {
                username: u.username.clone(),
                password: String::new(),
            })
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
        if name.len() > 64
            || name
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || "/\\\"'".contains(c))
        {
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
                .ok_or_else(|| ApiError::bad_request(format!("新用户 {name} 必须提供口令")))?
        } else {
            let password = entry.password.clone();
            tokio::task::spawn_blocking(move || {
                fftp_common::users::UserManager::hash_password(&password)
            })
            .await
            .map_err(|e| ApiError::internal(format!("口令哈希任务失败: {e}")))?
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
    let config_path = state.http_config_path.clone();
    let users_for_save = new_users.clone();
    tokio::task::spawn_blocking(move || {
        crate::config::HttpConfig::save_admin_users(&config_path, &users_for_save)
    })
    .await
    .map_err(|e| ApiError::internal(format!("写入管理员配置任务失败: {e}")))??;
    let count = new_users.len();
    state.set_admins(new_users);
    state
        .audit(
            &user.0,
            "save_admin_users",
            "fftp-http.toml",
            &format!("管理员共 {count} 名"),
        )
        .await;
    Ok(Json(AdminUsersBody {
        users: body.users, // 原样回显（password 字段已被 skip_serializing 剔除）
    }))
}

// ---------- 目录辅助 ----------

/// POST /api/user-directories/suggest → 按用户名给出主目录候选
///
/// 单用户桌面环境下，为了在**不允许遍历目录**的前提下提升填写体验，这里只
/// 返回词法拼接的桌面路径（`~/Desktop` 与 `~/Desktop/<用户名>`）。管理端仍
/// 可填写任意有权限的目录；候选仅作快速填充，不表示目录已存在或必须位于
/// 桌面。函数**不探测文件系统**（不遍历、不判断 `is_dir`），避免管理前端被
/// 用作目录探测器。
async fn suggest_user_dirs(
    _user: AuthedUser,
    Json(body): Json<SuggestBody>,
) -> Json<SuggestResponse> {
    Json(SuggestResponse {
        directories: suggested_dirs(&body.username),
    })
}

/// 建议的主目录候选：桌面本身 + 桌面下以用户名命名的子目录
fn suggested_dirs(username: &str) -> Vec<String> {
    let name = username.trim();
    // 与 FTP/SFTP 认证使用同一套用户名规则，避免把 "." / ".." 拼进路径
    if !fftp_common::users::is_safe_username(name) {
        return Vec::new();
    }

    let desktop = fftp_common::paths::desktop_dir();
    let mut dirs = vec![desktop.to_string_lossy().into_owned()];
    let named = desktop.join(name);
    if named != desktop {
        dirs.push(named.to_string_lossy().into_owned());
    }
    dirs
}

/// POST /api/user-directories/ensure → `EnsureUserDirectories`
async fn ensure_user_dirs(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let data = state.daemon.request(Command::EnsureUserDirectories).await?;
    Ok(Json(data))
}

/// POST /api/user-directory，body `{"path": "..."}` → `CreateUserDirectory`
async fn create_user_dir(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<PathBody>,
) -> ApiResult<Json<Value>> {
    let data = state
        .daemon
        .request(Command::CreateUserDirectory {
            path: body.path.clone(),
        })
        .await?;
    state
        .audit_file_op(&user.0, "MKDIR", &body.path, "创建用户主目录")
        .await;
    Ok(Json(data))
}

/// POST /api/directory-permissions，body `{"path": "..."}` → `SetupDirectoryPermissions`
async fn setup_dir_perms(
    State(state): State<Arc<AppState>>,
    user: AuthedUser,
    Json(body): Json<PathBody>,
) -> ApiResult<Json<Value>> {
    let data = state
        .daemon
        .request(Command::SetupDirectoryPermissions {
            path: body.path.clone(),
        })
        .await?;
    state
        .audit_file_op(&user.0, "CHMOD", &body.path, "设置目录权限")
        .await;
    Ok(Json(data))
}

// ---------- 日志 ----------

/// GET /api/logs?count=200 → `GetRecentLogs`
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

/// GET /api/logs/files → `GetLogFiles`
async fn log_files(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let data = state.daemon.request(Command::GetLogFiles).await?;
    Ok(Json(data))
}

/// POST /api/logs/content，body `{"path": "...", "count": 200}` → `GetLogFileContent`
async fn log_content(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PathCountBody>,
) -> ApiResult<Json<Value>> {
    let data = state
        .daemon
        .request(Command::GetLogFileContent {
            path: body.path,
            count: body.count,
        })
        .await?;
    Ok(Json(data))
}

/// PUT /api/log-config → `SaveLogConfig`
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
        Ok(_) => {
            state
                .audit(&user.0, "save_log_config", "logging", "日志配置已保存")
                .await;
        }
        Err(e) => {
            state
                .audit(&user.0, "save_log_config_failed", "logging", &e.to_string())
                .await;
        }
    }
    Ok(Json(result?))
}

// ---------- 文件操作日志 ----------

/// GET /api/fileop/files → `GetFileOpLogFiles`
async fn fileop_files(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let data = state.daemon.request(Command::GetFileOpLogFiles).await?;
    Ok(Json(data))
}

/// POST /api/fileop/content，body `{"path": "...", "count": 200}` → `GetFileOpLogContent`
async fn fileop_content(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PathCountBody>,
) -> ApiResult<Json<Value>> {
    let data = state
        .daemon
        .request(Command::GetFileOpLogContent {
            path: body.path,
            count: body.count,
        })
        .await?;
    Ok(Json(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggested_dirs_are_lexical_desktop_paths() {
        let desktop = fftp_common::paths::desktop_dir();
        let dirs = suggested_dirs("alice");
        assert_eq!(
            dirs,
            vec![
                desktop.to_string_lossy().into_owned(),
                desktop.join("alice").to_string_lossy().into_owned(),
            ]
        );
        // 仅做词法拼接，不探测目录是否存在
        assert!(
            dirs.iter()
                .all(|dir| std::path::Path::new(dir).starts_with(&desktop))
        );
    }

    #[test]
    fn suggested_dirs_reject_unsafe_usernames() {
        for name in [
            "",
            " ",
            ".",
            "..",
            "../escape",
            "a/b",
            "a\\b",
            "-lead",
            "中文",
        ] {
            assert!(suggested_dirs(name).is_empty(), "应拒绝用户名: {name:?}");
        }
    }
}

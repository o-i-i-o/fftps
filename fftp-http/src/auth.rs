//! 认证：管理员登录、API token 与路由保护
//!
//! 认证途径（按序）：
//! 1. `Authorization: Bearer <api_token>`——静态 token（配置于 `[auth]`），
//!    供脚本/程序化访问；常量时间比较；
//! 2. 会话 Cookie `fftp_session`——`POST /api/login` 校验管理员口令后签发，
//!    `HttpOnly` + SameSite=Strict（TLS 下追加 Secure）。
//!
//! 会话存储与登录失败限流见 [`crate::session`]。
//!
//! 路由保护采用结构化中间件（[`auth_middleware`]）：校验通过后把
//! [`AuthedUser`] 注入 extensions，handler 经 extractor 取回操作者身份。

use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::error::ApiError;
use crate::session::{SESSION_COOKIE, ct_eq, session_token_from_cookie};
use crate::state::AppState;

// ---------- 请求身份 ----------

/// 已认证操作者（中间件注入 extensions，handler 经 extractor 取用）
#[derive(Clone, Debug)]
pub struct AuthedUser(pub String);

impl axum::extract::FromRequestParts<Arc<AppState>> for AuthedUser {
    type Rejection = ApiError;

    // trait 签名固定为 async，但取 extensions 是同步操作
    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthedUser>()
            .cloned()
            .ok_or_else(|| ApiError::internal("认证中间件未生效（路由配置错误）"))
    }
}

/// 路由保护中间件：校验通过注入 [`AuthedUser`]，否则 401
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    match authenticate(&state, &req) {
        Some(user) => {
            req.extensions_mut().insert(AuthedUser(user));
            next.run(req).await
        }
        None => ApiError::unauthorized("未登录或会话已过期").into_response(),
    }
}

/// 认证判定：Bearer `api_token` 优先，其次会话 Cookie
fn authenticate(state: &AppState, req: &Request<axum::body::Body>) -> Option<String> {
    if let Some(v) = req.headers().get(axum::http::header::AUTHORIZATION)
        && let Ok(s) = v.to_str()
        && let Some(token) = s.strip_prefix("Bearer ")
    {
        let configured = &state.config.auth.api_token;
        if !configured.is_empty() && ct_eq(token.trim(), configured) {
            return Some("api_token".into());
        }
    }
    let token = session_token_from_cookie(req.headers())?;
    state.sessions.get_valid(&token, &state.admins())
}

// ---------- 登录 / 登出 ----------

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

/// 构造会话 Cookie（HttpOnly + SameSite=Strict；TLS 下追加 Secure）
#[must_use]
pub fn session_cookie(state: &AppState, token: &str) -> String {
    let secure = if state.config.tls.enabled {
        "; Secure"
    } else {
        ""
    };
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/{secure}")
}

/// 登录：限流 + 校验管理员口令，签发会话 Cookie（成功与失败均写审计）
pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> Response {
    let limiter_key = format!("{}|{}", peer.ip(), body.username.to_lowercase());
    if state.login_limiter.is_blocked(&limiter_key) {
        state
            .audit(
                &body.username,
                "login_blocked",
                "web",
                &peer.ip().to_string(),
            )
            .await;
        return ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "登录尝试过于频繁，请稍后再试",
        )
        .into_response();
    }

    let admins = state.admins();
    let password_hash = admins
        .iter()
        .find(|u| u.username == body.username)
        .map(|u| u.password_hash.clone());

    // Argon2id 校验是同步 CPU 密集操作，放入阻塞线程避免占满 tokio worker
    let ok = match password_hash.clone() {
        Some(hash) => {
            let password = body.password.clone();
            tokio::task::spawn_blocking(move || {
                fftp_common::users::UserManager::verify_password(&password, &hash)
            })
            .await
            .unwrap_or_else(|e| {
                tracing::error!("登录口令校验任务失败: {e}");
                false
            })
        }
        None => false,
    };

    if !ok {
        state.login_limiter.record_failure(&limiter_key);
        state
            .audit(
                &body.username,
                "login_failed",
                "web",
                &peer.ip().to_string(),
            )
            .await;
        return ApiError::unauthorized("用户名或口令错误").into_response();
    }

    state.login_limiter.reset(&limiter_key);
    // 仅在口令校验通过后才可能存在哈希；此处取快照绑定到会话
    let token = state
        .sessions
        .create(&body.username, password_hash.as_deref().unwrap_or_default());
    state
        .audit(&body.username, "login", "web", &peer.ip().to_string())
        .await;

    let cookie = session_cookie(&state, &token);
    (
        [(SET_COOKIE, cookie)],
        Json(json!({"ok": true, "username": body.username})),
    )
        .into_response()
}

/// 登出：撤销会话并清除 Cookie
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token_from_cookie(&headers) {
        state.sessions.remove(&token);
    }
    let cookie = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    (
        StatusCode::OK,
        [(SET_COOKIE, cookie)],
        Json(json!({"ok": true})),
    )
        .into_response()
}

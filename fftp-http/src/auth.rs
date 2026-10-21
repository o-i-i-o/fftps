//! 认证：管理员登录、会话存储、API token 与路由保护
//!
//! 认证途径（按序）：
//! 1. `Authorization: Bearer <api_token>`——静态 token（配置于 `[auth]`），
//!    供脚本/程序化访问；常量时间比较；
//! 2. 会话 Cookie `fftp_session`——`POST /api/login` 校验管理员口令后签发，
//!    HttpOnly + SameSite=Strict（TLS 下追加 Secure）。
//!
//! 路由保护采用结构化中间件（[`auth_middleware`]）：校验通过后把
//! [`AuthedUser`] 注入 extensions，handler 经 extractor 取回操作者身份。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::config::AdminUser;
use crate::error::ApiError;
use crate::state::AppState;

/// 会话 Cookie 名
pub const SESSION_COOKIE: &str = "fftp_session";

// ---------- 会话存储 ----------

/// 内存会话存储（进程内有效；重启后所有会话失效，重新登录即可）
#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<Mutex<HashMap<String, Session>>>,
    ttl: Duration,
}

struct Session {
    username: String,
    expires: Instant,
}

impl SessionStore {
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        let store = Self {
            inner: Arc::default(),
            ttl: Duration::from_secs(ttl_secs),
        };
        tokio::spawn(cleanup_loop(Arc::clone(&store.inner)));
        store
    }

    /// 签发会话，返回 token
    pub fn create(&self, username: &str) -> String {
        let token = new_token();
        let session = Session {
            username: username.to_string(),
            expires: Instant::now() + self.ttl,
        };
        self.inner.lock().expect("会话存储锁中毒").insert(token.clone(), session);
        token
    }

    /// 查询会话（惰性淘汰过期项）
    #[must_use]
    pub fn get(&self, token: &str) -> Option<String> {
        let mut map = self.inner.lock().expect("会话存储锁中毒");
        let expired = |s: &Session| Instant::now() >= s.expires;
        match map.get(token) {
            Some(s) if !expired(s) => Some(s.username.clone()),
            Some(_) => {
                map.remove(token);
                None
            }
            None => None,
        }
    }

    /// 撤销会话（登出）
    pub fn remove(&self, token: &str) {
        self.inner.lock().expect("会话存储锁中毒").remove(token);
    }
}

/// 每小时清扫过期会话
async fn cleanup_loop(inner: Arc<Mutex<HashMap<String, Session>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let now = Instant::now();
        inner
            .lock()
            .expect("会话存储锁中毒")
            .retain(|_, s| now < s.expires);
    }
}

/// 生成 256bit 会话 token（两个 u128 十六进制拼接）
fn new_token() -> String {
    format!("{:032x}{:032x}", rand::random::<u128>(), rand::random::<u128>())
}

/// 常量时间字符串比较（防时序侧信道；长度不等立即失败，仅泄露长度）
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------- 请求身份 ----------

/// 已认证操作者（中间件注入 extensions，handler 经 extractor 取用）
#[derive(Clone, Debug)]
pub struct AuthedUser(pub String);

impl axum::extract::FromRequestParts<Arc<AppState>> for AuthedUser {
    type Rejection = ApiError;

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

/// 认证判定：Bearer api_token 优先，其次会话 Cookie
fn authenticate(state: &AppState, req: &Request<axum::body::Body>) -> Option<String> {
    if let Some(v) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                let configured = &state.config.auth.api_token;
                if !configured.is_empty() && ct_eq(token.trim(), configured) {
                    return Some("api_token".into());
                }
            }
        }
    }
    let token = session_token_from_cookie(req.headers())?;
    state.sessions.get(&token)
}

/// 从 `Cookie` 头提取会话 token
fn session_token_from_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        pair.trim()
            .strip_prefix(SESSION_COOKIE)
            .and_then(|rest| rest.strip_prefix('='))
            .map(str::to_string)
    })
}

// ---------- 登录 / 登出 ----------

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

/// 登录：校验管理员口令，签发会话 Cookie（成功与失败均写审计）
pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> Response {
    let admin = state
        .config
        .admin_users
        .iter()
        .find(|u| u.username == body.username);
    let ok = admin.is_some_and(|AdminUser { password_hash, .. }| {
        fftp_common::users::UserManager::verify_password(&body.password, password_hash)
    });

    if !ok {
        state.audit(&body.username, "login_failed", "web", &peer.ip().to_string()).await;
        return ApiError::unauthorized("用户名或口令错误").into_response();
    }

    let token = state.sessions.create(&body.username);
    state.audit(&body.username, "login", "web", &peer.ip().to_string()).await;

    let secure = if state.config.tls.enabled { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/{secure}"
    );
    ([(SET_COOKIE, cookie)], Json(json!({"ok": true, "username": body.username}))).into_response()
}

/// 登出：撤销会话并清除 Cookie
pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(token) = session_token_from_cookie(&headers) {
        state.sessions.remove(&token);
    }
    let cookie = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    (StatusCode::OK, [(SET_COOKIE, cookie)], Json(json!({"ok": true}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_lifecycle() {
        let store = SessionStore::new(3600);
        let token = store.create("admin");
        assert_eq!(store.get(&token).as_deref(), Some("admin"));
        store.remove(&token);
        assert_eq!(store.get(&token), None);
    }

    #[tokio::test]
    async fn expired_session_is_rejected() {
        let store = SessionStore::new(1);
        let token = store.create("admin");
        // 直接注入过期会话，避免真实等待
        store.inner.lock().unwrap().get_mut(&token).unwrap().expires = Instant::now();
        assert_eq!(store.get(&token), None);
    }

    #[test]
    fn ct_eq_matches_only_identical() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "a"));
    }

    #[test]
    fn cookie_parsing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "other=x; fftp_session=token123; y=z".parse().unwrap(),
        );
        assert_eq!(session_token_from_cookie(&headers).as_deref(), Some("token123"));

        let headers = HeaderMap::new();
        assert_eq!(session_token_from_cookie(&headers), None);
    }
}

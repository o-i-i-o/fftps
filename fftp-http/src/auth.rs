//! 认证：管理员登录、会话存储、API token 与路由保护
//!
//! 认证途径（按序）：
//! 1. `Authorization: Bearer <api_token>`——静态 token（配置于 `[auth]`），
//!    供脚本/程序化访问；常量时间比较；
//! 2. 会话 Cookie `fftp_session`——`POST /api/login` 校验管理员口令后签发，
//!    `HttpOnly` + SameSite=Strict（TLS 下追加 Secure）。
//!
//! 路由保护采用结构化中间件（[`auth_middleware`]）：校验通过后把
//! [`AuthedUser`] 注入 extensions，handler 经 extractor 取回操作者身份。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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
    /// 签发时的口令哈希快照：管理员改密后旧会话立即失效
    password_hash: String,
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
    pub fn create(&self, username: &str, password_hash: &str) -> String {
        let token = new_token();
        let session = Session {
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            expires: Instant::now() + self.ttl,
        };
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(token.clone(), session);
        token
    }

    /// 查询会话（惰性淘汰过期项；仅测试使用）
    #[cfg(test)]
    #[must_use]
    pub fn get(&self, token: &str) -> Option<String> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    /// 查询会话并校验管理员仍存在且口令哈希未变更
    ///
    /// 管理员被删除或改密后，既有 Cookie 在 TTL 内也不能继续使用。
    #[must_use]
    pub fn get_valid(&self, token: &str, admins: &[AdminUser]) -> Option<String> {
        let (username, stored_hash) = {
            let mut map = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match map.get(token) {
                Some(s) if Instant::now() < s.expires => {
                    (s.username.clone(), s.password_hash.clone())
                }
                Some(_) => {
                    map.remove(token);
                    return None;
                }
                None => return None,
            }
        };

        let Some(admin) = admins.iter().find(|u| u.username == username) else {
            // 管理员已被删除：撤销会话
            self.remove(token);
            return None;
        };
        if ct_eq(&admin.password_hash, &stored_hash) {
            Some(username)
        } else {
            // 口令已变更：撤销该会话
            self.remove(token);
            None
        }
    }

    /// 撤销会话（登出）
    pub fn remove(&self, token: &str) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(token);
    }
}

/// 每小时清扫过期会话
async fn cleanup_loop(inner: Arc<Mutex<HashMap<String, Session>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let now = Instant::now();
        inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, s| now < s.expires);
    }
}

/// 生成 256bit 会话 token（两个 u128 十六进制拼接）
fn new_token() -> String {
    format!(
        "{:032x}{:032x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    )
}

/// 常量时间字符串比较（防时序侧信道；长度不等立即失败，仅泄露长度）
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
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

/// 登录失败限流参数
const LOGIN_MAX_FAILURES: u32 = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(300);
/// 限流表条目上限（防止攻击者用海量用户名撑爆内存）
const LOGIN_LIMITER_CAPACITY: usize = 4096;

struct LoginFailures {
    count: u32,
    last: Instant,
}

/// 按「客户端 IP + 用户名」限制登录失败次数
///
/// 只对失败计数，成功登录会清零；窗口内达到上限后返回 429。
#[derive(Default)]
pub struct LoginLimiter {
    inner: Mutex<HashMap<String, LoginFailures>>,
}

impl LoginLimiter {
    /// 是否已被锁定
    #[must_use]
    pub fn is_blocked(&self, key: &str) -> bool {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match map.get(key) {
            Some(f) if f.last.elapsed() <= LOGIN_WINDOW => f.count >= LOGIN_MAX_FAILURES,
            Some(_) => {
                map.remove(key);
                false
            }
            None => false,
        }
    }

    /// 记录一次失败
    pub fn record_failure(&self, key: &str) {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= LOGIN_LIMITER_CAPACITY {
            map.retain(|_, f| f.last.elapsed() <= LOGIN_WINDOW);
            if map.len() >= LOGIN_LIMITER_CAPACITY {
                map.clear();
            }
        }

        let entry = map.entry(key.to_string()).or_insert(LoginFailures {
            count: 0,
            last: Instant::now(),
        });
        if entry.last.elapsed() > LOGIN_WINDOW {
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
        entry.last = Instant::now();
    }

    /// 登录成功后清除失败记录
    pub fn reset(&self, key: &str) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use fftp_common::sync::MutexExt;

    #[tokio::test]
    async fn session_lifecycle() {
        let store = SessionStore::new(3600);
        let token = store.create("admin", "hash-v1");
        assert_eq!(store.get(&token).as_deref(), Some("admin"));
        store.remove(&token);
        assert_eq!(store.get(&token), None);
    }

    #[tokio::test]
    async fn expired_session_is_rejected() {
        let store = SessionStore::new(1);
        let token = store.create("admin", "hash-v1");
        // 直接注入过期会话，避免真实等待
        store.inner.lock_recover().get_mut(&token).unwrap().expires = Instant::now();
        assert_eq!(store.get(&token), None);
    }

    #[tokio::test]
    async fn admin_removal_or_password_change_invalidates_session() {
        let store = SessionStore::new(3600);
        let token = store.create("admin", "hash-v1");
        let admin = |hash: &str| AdminUser {
            username: "admin".into(),
            password_hash: hash.into(),
        };

        // 管理员仍在且哈希未变：有效
        assert_eq!(
            store.get_valid(&token, &[admin("hash-v1")]).as_deref(),
            Some("admin")
        );
        // 改密：旧会话失效
        assert_eq!(store.get_valid(&token, &[admin("hash-v2")]), None);
        assert_eq!(store.get(&token), None);

        // 管理员被删除：旧会话失效
        let token = store.create("admin", "hash-v1");
        assert_eq!(store.get_valid(&token, &[]), None);
        assert_eq!(store.get(&token), None);
    }

    #[test]
    fn login_limiter_blocks_after_repeated_failures() {
        let limiter = LoginLimiter::default();
        let key = "127.0.0.1|admin";
        assert!(!limiter.is_blocked(key));
        for _ in 0..LOGIN_MAX_FAILURES {
            limiter.record_failure(key);
        }
        assert!(limiter.is_blocked(key));
        limiter.reset(key);
        assert!(!limiter.is_blocked(key));
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
        assert_eq!(
            session_token_from_cookie(&headers).as_deref(),
            Some("token123")
        );

        let headers = HeaderMap::new();
        assert_eq!(session_token_from_cookie(&headers), None);
    }
}

//! IP 黑白名单中间件（最外层，先于认证）
//!
//! 直接取 TCP 对端地址（不信任 `X-Forwarded-For`，防伪造）；
//! 匹配规则复用 `fftp_common::config::Config::is_ip_allowed_for`
//! （黑名单优先，白名单非空即白名单制，支持 CIDR）。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;
use crate::state::AppState;

/// IP 过滤：拒绝时返回 403（含静态资源与登录页，黑名单 IP 完全不可见）
pub async fn ip_filter(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = peer.ip().to_string();
    let filter = &state.config.ip_filter;
    if !fftp_common::config::Config::is_ip_allowed_for(&filter.whitelist, &filter.blacklist, &ip) {
        tracing::warn!("IP 过滤拒绝: {ip} {} {}", req.method(), req.uri().path());
        return ApiError::forbidden("IP 不在允许范围内").into_response();
    }
    next.run(req).await
}

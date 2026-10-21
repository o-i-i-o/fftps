//! API 错误类型：统一 JSON 错误体 + HTTP 状态映射
//!
//! 错误体 `{"error": {"code": "...", "message": "..."}}`；
//! IPC `ErrorCode` → HTTP：Validation→400、NotFound→404、Conflict→409、
//! Io/Protocol/Internal→502；连接断开→503（UI 据此显示离线横幅）。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use fftp_ipc::client::ClientError;
use fftp_ipc::protocol::ErrorCode;
use serde_json::json;

/// API 错误
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

impl ApiError {
    #[must_use]
    pub fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.to_string(),
            message: message.into(),
        }
    }

    #[must_use]
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    #[must_use]
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "资源不存在")
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
}

impl From<ClientError> for ApiError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Disconnected(reason) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "daemon_disconnected",
                format!("fftpd 未连接: {reason}"),
            ),
            ClientError::Request(e) => {
                let (status, code) = match e.code {
                    ErrorCode::Validation => (StatusCode::BAD_REQUEST, "validation"),
                    ErrorCode::NotFound => (StatusCode::NOT_FOUND, "not_found"),
                    ErrorCode::Conflict => (StatusCode::CONFLICT, "conflict"),
                    ErrorCode::Io
                    | ErrorCode::Protocol
                    | ErrorCode::Internal => (StatusCode::BAD_GATEWAY, "upstream"),
                };
                Self::new(status, code, e.message)
            }
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(format!("{e:#}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({"error": {"code": self.code, "message": self.message}});
        (self.status, Json(body)).into_response()
    }
}

/// handler 统一返回类型
pub type ApiResult<T> = Result<T, ApiError>;

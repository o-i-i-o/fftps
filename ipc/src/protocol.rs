//! IPC 协议类型定义
//!
//! 线上格式为 JSON（外层 4 字节大端长度前缀，见 [`crate::framing`]）：
//!
//! ```jsonc
//! { "type": "request", "id": 1, "cmd": "save_config", "content": "..." }
//! { "type": "response", "id": 1, "status": "ok", "data": { } }
//! { "type": "response", "id": 1, "status": "error", "code": "validation", "message": "..." }
//! { "type": "notification", "event": "log", "entry": { ... } }
//! ```
//!
//! 设计约定（沿用 wftpd.proto 的策略）：配置/用户以原文字符串传输，
//! 由 fftp-common 的共享类型解析校验，保证前后端对 schema 的理解一致。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 单帧载荷上限（4 MiB）：防止损坏/恶意帧导致内存耗尽
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// 一帧 = 一条 [`Message`]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Request(Request),
    Response(Response),
    Notification(Notification),
}

/// 请求：`id` 由客户端分配，响应原样回带
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    #[serde(flatten)]
    pub cmd: Command,
}

/// 响应：结果内联（`status` 判别成功/失败）
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    #[serde(flatten)]
    pub result: OpResult,
}

/// 操作结果
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OpResult {
    Ok {
        #[serde(default)]
        data: Value,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

impl Response {
    #[must_use]
    pub fn ok(id: u64, data: Value) -> Self {
        Self {
            id,
            result: OpResult::Ok { data },
        }
    }

    #[must_use]
    pub fn error(id: u64, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            id,
            result: OpResult::Error {
                code,
                message: message.into(),
            },
        }
    }
}

/// 服务端主动推送（日志订阅等），不与任何请求 id 关联
#[derive(Debug, Serialize, Deserialize)]
pub struct Notification {
    #[serde(flatten)]
    pub event: Event,
}

/// 推送事件
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Log { entry: LogEntry },
}

/// 控制命令面：wftpd.proto 全量操作 ∪ Windows reload 通道
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    // ---- 服务生命周期 ----
    GetStatus,
    StartService { which: ServiceTarget },
    StopService { which: ServiceTarget },
    RestartService { which: ServiceTarget },
    /// 停止守护进程自身
    Shutdown,
    // ---- 配置与用户 ----
    GetConfig,
    SaveConfig { content: String },
    GetUsers,
    SaveUsers { content: String },
    GetInitialState,
    // ---- 目录辅助（后端是配置/用户数据的唯一写入者） ----
    EnsureUserDirectories,
    CreateUserDirectory { path: String },
    SetupDirectoryPermissions { path: String },
    // ---- 日志 ----
    GetRecentLogs {
        #[serde(default)]
        count: u32,
    },
    /// 订阅实时日志：先由服务端补推 `tail_count` 条历史，随后持续推送
    SubscribeLogs {
        #[serde(default)]
        tail_count: u32,
    },
    UnsubscribeLogs,
    GetLogFiles,
    GetLogFileContent { path: String, count: u32 },
    GetFileOpLogFiles,
    GetFileOpLogContent { path: String, count: u32 },
    SaveLogConfig {
        log_dir: String,
        log_level: String,
        max_log_size: u64,
        max_log_files: u32,
        enable_gui_logging: bool,
    },
    WriteAuditLog {
        user: String,
        action: String,
        target: String,
        details: String,
    },
}

/// 服务操作目标
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceTarget {
    #[default]
    All,
    Ftp,
    Sftp,
}

/// 错误类别（序列化为 snake_case 字符串）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 本地 IO / 连接失败
    Io,
    /// 帧或 JSON 不合法
    Protocol,
    /// 参数/配置校验失败
    Validation,
    /// 目标不存在
    NotFound,
    /// 状态冲突（如用户已存在）
    Conflict,
    /// 服务端内部错误
    Internal,
}

/// 日志条目（程序日志与实时推送共用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub source: String,
    pub message: String,
    #[serde(default)]
    pub client_ip: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub action: String,
}

/// 文件操作审计日志条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOpLogEntry {
    pub timestamp: String,
    pub username: String,
    pub client_ip: String,
    pub operation: String,
    pub file_path: String,
    pub file_size: u64,
    pub protocol: String,
    pub success: bool,
    #[serde(default)]
    pub message: String,
}

/// 日志文件信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFileInfo {
    pub name: String,
    pub path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: &Message) -> Message {
        serde_json::from_str(&serde_json::to_string(msg).unwrap()).unwrap()
    }

    #[test]
    fn request_roundtrip_flattens_cmd() {
        let msg = Message::Request(Request {
            id: 7,
            cmd: Command::SaveConfig {
                content: "[ftp]".into(),
            },
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""cmd":"save_config""#));
        assert!(json.contains(r#""id":7"#));
        match roundtrip(&msg) {
            Message::Request(req) => {
                assert_eq!(req.id, 7);
                assert!(matches!(req.cmd, Command::SaveConfig { .. }));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unit_variant_command_roundtrip() {
        let msg = Message::Request(Request {
            id: 1,
            cmd: Command::GetStatus,
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""cmd":"get_status""#));
        match roundtrip(&msg) {
            Message::Request(req) => assert!(matches!(req.cmd, Command::GetStatus)),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn response_roundtrip() {
        let ok = Message::Response(Response::ok(3, serde_json::json!({"ftp_running": true})));
        match roundtrip(&ok) {
            Message::Response(resp) => {
                assert_eq!(resp.id, 3);
                assert!(matches!(resp.result, OpResult::Ok { .. }));
            }
            other => panic!("unexpected: {other:?}"),
        }

        let err = Message::Response(Response::error(4, ErrorCode::Validation, "bad"));
        match roundtrip(&err) {
            Message::Response(resp) => match resp.result {
                OpResult::Error { code, message } => {
                    assert_eq!(code, ErrorCode::Validation);
                    assert_eq!(message, "bad");
                }
                other => panic!("unexpected: {other:?}"),
            },
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn notification_roundtrip() {
        let msg = Message::Notification(Notification {
            event: Event::Log {
                entry: LogEntry {
                    timestamp: "t".into(),
                    level: "info".into(),
                    source: "fftpd".into(),
                    message: "hello".into(),
                    client_ip: String::new(),
                    username: String::new(),
                    action: String::new(),
                },
            },
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"notification""#));
        assert!(json.contains(r#""event":"log""#));
        match roundtrip(&msg) {
            Message::Notification(Notification {
                event: Event::Log { entry },
            }) => assert_eq!(entry.message, "hello"),
            other => panic!("unexpected: {other:?}"),
        }
    }
}

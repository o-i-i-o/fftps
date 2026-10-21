//! 日志命令面：环形缓冲拉取、日志文件读取（防逃逸）、日志参数热更新与审计写入
//!
//! 另提供 [`spawn_log_forwarder`]：把 [`fftp_common::logging::LogBuffer`] 的
//! 新条目转发进 IPC 的 `broadcast::Sender<Event>`，供 `SubscribeLogs` 订阅者
//! 收到 `Event::Log` 实时推送。

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use fftp_common::config::LoggingConfig;
use fftp_common::logging::{self, Logging};
use fftp_ipc::protocol::Event;
use fftp_ipc::server::HandlerError;

use crate::state::AppState;

/// `GetRecentLogs` 的 `count` 语义：0 = 全部（缓冲容量上限）
fn recent_limit(count: u32) -> usize {
    if count == 0 {
        usize::MAX
    } else {
        usize::try_from(count).unwrap_or(usize::MAX)
    }
}

/// 最近日志：从环形缓冲取，形状 `{"entries": [LogEntry, ...]}`
/// （与 `fftp_ipc::server` 的 `push_history` 约定一致）
#[must_use]
pub fn recent_logs(state: &AppState, count: u32) -> Value {
    if !state.logging.live_config().enable_gui_logging {
        return json!({ "entries": [] });
    }
    let entries: Vec<fftp_ipc::protocol::LogEntry> = state
        .logging
        .log_buffer()
        .recent(recent_limit(count))
        .into_iter()
        .map(to_ipc_entry)
        .collect();
    json!({ "entries": entries })
}

/// 程序日志文件列表（新→旧），形状 `{"files": [LogFileInfo, ...]}`
#[must_use]
pub fn log_files(state: &AppState) -> Value {
    let files: Vec<fftp_ipc::protocol::LogFileInfo> = state
        .logging
        .list_log_files()
        .into_iter()
        .map(to_ipc_file_info)
        .collect();
    json!({ "files": files })
}

/// 读取程序日志文件最后 `count` 条，形状 `{"entries": [...]}`
///
/// # Errors
/// `path` 不存在返回 `NotFound`，位于日志目录之外返回 `Validation`
pub fn log_file_content(
    state: &AppState,
    path: &str,
    count: u32,
) -> Result<Value, HandlerError> {
    let path = check_log_path(state, path)?;
    let entries: Vec<fftp_ipc::protocol::LogEntry> = state
        .logging
        .read_log_file(&path, recent_limit(count))
        .map_err(|e| HandlerError::internal(format!("读取日志文件失败: {e:#}")))?
        .into_iter()
        .map(to_ipc_entry)
        .collect();
    Ok(json!({ "entries": entries }))
}

/// file-ops 审计日志文件列表（新→旧），形状 `{"files": [...]}`
#[must_use]
pub fn file_op_log_files(state: &AppState) -> Value {
    let files: Vec<fftp_ipc::protocol::LogFileInfo> = state
        .logging
        .list_file_op_log_files()
        .into_iter()
        .map(to_ipc_file_info)
        .collect();
    json!({ "files": files })
}

/// 读取 file-ops 审计日志文件最后 `count` 条，形状 `{"entries": [...]}`
///
/// # Errors
/// `path` 不存在返回 `NotFound`，位于日志目录之外返回 `Validation`
pub fn file_op_log_content(
    state: &AppState,
    path: &str,
    count: u32,
) -> Result<Value, HandlerError> {
    let path = check_log_path(state, path)?;
    let entries: Vec<fftp_ipc::protocol::FileOpLogEntry> = state
        .logging
        .read_file_op_log(&path, recent_limit(count))
        .map_err(|e| HandlerError::internal(format!("读取审计日志文件失败: {e:#}")))?
        .into_iter()
        .map(to_ipc_file_op)
        .collect();
    Ok(json!({ "entries": entries }))
}

/// 日志文件路径防逃逸校验：必须是日志目录内已存在的文件
///
/// # Errors
/// 路径不存在返回 `NotFound`；无法解析或位于日志目录之外返回 `Validation`
fn check_log_path(state: &AppState, path: &str) -> Result<PathBuf, HandlerError> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err(HandlerError::not_found(format!(
            "日志文件不存在: {}",
            path.display()
        )));
    }
    logging::ensure_path_in_dir(&path, &state.logging.live_config().resolved_log_dir()).map_err(
        |e| HandlerError::validation(format!("日志路径越权访问: {e:#}")),
    )?;
    Ok(path)
}

/// `SaveLogConfig`：更新 [`LoggingConfig`] 并落盘，随后热更新日志设施
///
/// # Errors
/// 日志级别非法、`max_log_files` 为 0、日志目录创建或配置落盘失败时返回错误
pub fn save_log_config(
    state: &AppState,
    log_dir: String,
    log_level: String,
    max_log_size: u64,
    max_log_files: u32,
    enable_gui_logging: bool,
) -> Result<Value, HandlerError> {
    if !is_valid_log_level(&log_level) {
        return Err(HandlerError::validation(format!("非法日志级别: {log_level}")));
    }
    if max_log_files == 0 {
        return Err(HandlerError::validation("max_log_files 至少为 1"));
    }

    let mut config = state.current_config();
    config.logging = LoggingConfig {
        log_dir,
        log_level,
        max_log_files: usize::try_from(max_log_files).unwrap_or(usize::MAX),
        max_log_size,
        enable_json: config.logging.enable_json, // 命令面未覆盖，沿用现值
        enable_gui_logging,
    };

    config
        .save(&fftp_common::paths::config_path())
        .map_err(|e| HandlerError::internal(format!("配置落盘失败: {e:#}")))?;
    state.store_config(config.clone());
    apply_logging_config(&state.logging, &config.logging)?;

    Ok(json!({
        "log_dir": config.logging.resolved_log_dir().display().to_string(),
        "log_level": config.logging.log_level,
        "max_log_size": config.logging.max_log_size,
        "max_log_files": config.logging.max_log_files,
        "enable_gui_logging": config.logging.enable_gui_logging,
        "enable_json": config.logging.enable_json,
    }))
}

/// 把 [`LoggingConfig`] 应用到日志设施：参数热更新 + 动态调整日志级别
///
/// 文件 appender 的目录/格式在 `Logging::init` 时确定，变更需重启进程完整生效；
/// 这里同步创建新日志目录，保证文件读取 API 立即指向新目录。
///
/// # Errors
/// 日志目录创建或级别更新失败时返回错误
pub fn apply_logging_config(
    logging: &Logging,
    config: &LoggingConfig,
) -> Result<(), HandlerError> {
    let log_dir = config.resolved_log_dir();
    std::fs::create_dir_all(&log_dir).map_err(|e| {
        HandlerError::internal(format!("创建日志目录 {} 失败: {e}", log_dir.display()))
    })?;

    logging.update_config(config.clone());
    logging::set_log_level(&config.log_level)
        .map_err(|e| HandlerError::internal(format!("日志级别更新失败: {e:#}")))?;
    tracing::info!(
        "日志参数已更新：dir={} level={} gui_logging={}",
        log_dir.display(),
        config.log_level,
        config.enable_gui_logging
    );
    Ok(())
}

/// 日志级别白名单（与 `fftp_common::logging` 的级别解析一致）
fn is_valid_log_level(level: &str) -> bool {
    matches!(
        level.to_lowercase().as_str(),
        "trace" | "debug" | "info" | "warn" | "warning" | "error" | "off"
    )
}

/// `WriteAuditLog`：经共享层写入文件操作审计
pub fn write_audit_log(
    state: &AppState,
    user: &str,
    action: &str,
    target: &str,
    details: &str,
) -> Value {
    state
        .logging
        .write_audit(user, action, target, details);
    json!({ "recorded": true })
}

/// 日志实时推送：环形缓冲新条目 → IPC 事件广播（`SubscribeLogs` 订阅者收 `Event::Log`）
///
/// `enable_gui_logging` 关闭期间不推送（与缓冲语义一致）。
#[must_use]
pub fn spawn_log_forwarder(
    logging: Arc<Logging>,
    events: broadcast::Sender<Event>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = logging.log_buffer().subscribe();
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    if !logging.live_config().enable_gui_logging {
                        continue;
                    }
                    // 无订阅者时 send 返回 Err，属常态（订阅者随时上下线），继续转发
                    let _ = events.send(Event::Log {
                        entry: to_ipc_entry(entry),
                    });
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("日志转发落后，丢弃 {n} 条");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// 共享层条目 → IPC 线格式（字段一一对应）
fn to_ipc_entry(entry: fftp_common::logging::LogEntry) -> fftp_ipc::protocol::LogEntry {
    fftp_ipc::protocol::LogEntry {
        timestamp: entry.timestamp,
        level: entry.level,
        source: entry.source,
        message: entry.message,
        client_ip: entry.client_ip,
        username: entry.username,
        action: entry.action,
    }
}

/// 共享层审计条目 → IPC 线格式
fn to_ipc_file_op(
    entry: fftp_common::logging::FileOpLogEntry,
) -> fftp_ipc::protocol::FileOpLogEntry {
    fftp_ipc::protocol::FileOpLogEntry {
        timestamp: entry.timestamp,
        username: entry.username,
        client_ip: entry.client_ip,
        operation: entry.operation,
        file_path: entry.file_path,
        file_size: entry.file_size,
        protocol: entry.protocol,
        success: entry.success,
        message: entry.message,
    }
}

/// 共享层日志文件信息 → IPC 线格式
fn to_ipc_file_info(info: fftp_common::logging::LogFileInfo) -> fftp_ipc::protocol::LogFileInfo {
    fftp_ipc::protocol::LogFileInfo {
        name: info.name,
        path: info.path,
    }
}

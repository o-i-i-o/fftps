//! IPC 服务层：连接管理与请求封装
//!
//! 界面层不直接使用 fftp-ipc：请求封装为 future，由 update 以
//! [`iced::Task::perform`] 驱动，任何界面路径都不做阻塞 IO。
//! 本模块只提供纯异步请求与连接状态记账，重连调度由应用壳负责。

use std::fmt;
use std::time::Duration;

use fftp_ipc::client::{parse_data, Client, ClientError};
use fftp_ipc::protocol::{Command, FileOpLogEntry, LogEntry, LogFileInfo};
use serde::de::DeserializeOwned;
use serde::Deserialize;

/// 重连退避上限（秒）
const BACKOFF_MAX_SECS: u64 = 10;

/// 连接状态（底部状态栏展示）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ConnState {
    /// 正在连接
    #[default]
    Connecting,
    /// 已连接
    Connected,
    /// 已断开（附带原因），等待退避重连
    Disconnected(String),
}

impl ConnState {
    /// 状态栏展示文案
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            ConnState::Connecting => "连接中…".to_owned(),
            ConnState::Connected => "已连接".to_owned(),
            ConnState::Disconnected(reason) => format!("已断开（{reason}）"),
        }
    }
}

/// 请求失败原因
#[derive(Debug, Clone)]
pub enum IpcError {
    /// 连接断开（应用层应触发重连）
    Disconnected(String),
    /// 服务端业务错误（如校验失败），消息直接展示
    Request(String),
    /// 响应数据形状不符预期
    BadResponse(String),
}

impl IpcError {
    /// 错误描述（界面展示）
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            IpcError::Disconnected(message)
            | IpcError::Request(message)
            | IpcError::BadResponse(message) => message,
        }
    }

    /// 是否为连接断开
    #[must_use]
    pub fn is_disconnected(&self) -> bool {
        matches!(self, IpcError::Disconnected(_))
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// 包装 IPC 客户端：`Client` 未实现 `Debug`，而界面消息需要
#[derive(Clone)]
pub struct IpcConn(pub Client);

impl fmt::Debug for IpcConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IpcConn")
    }
}

/// 连接管理器：持有当前连接并跟踪连接状态
#[derive(Debug, Default)]
pub struct IpcService {
    conn: Option<IpcConn>,
    state: ConnState,
    /// 连接代数：每次成功连接自增，用作日志订阅的订阅身份
    generation: u64,
    /// 重连退避计数
    backoff_step: u32,
}

impl IpcService {
    /// 当前连接状态
    #[must_use]
    pub fn state(&self) -> &ConnState {
        &self.state
    }

    /// 当前连接（未连接时为 `None`）
    #[must_use]
    pub fn conn(&self) -> Option<&IpcConn> {
        self.conn.as_ref()
    }

    /// 是否已连接（写操作是否可用）
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ConnState::Connected)
    }

    /// 连接代数（日志订阅身份）
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// 标记为连接中
    pub fn mark_connecting(&mut self) {
        self.state = ConnState::Connecting;
    }

    /// 标记为已连接（连接代数自增、退避复位）
    pub fn mark_connected(&mut self, conn: IpcConn) {
        self.conn = Some(conn);
        self.state = ConnState::Connected;
        self.generation = self.generation.wrapping_add(1);
        self.backoff_step = 0;
    }

    /// 标记为已断开并清空连接
    pub fn mark_disconnected(&mut self, reason: String) {
        self.conn = None;
        self.state = ConnState::Disconnected(reason);
    }

    /// 计算下次重连退避时长（1s 起指数递增，上限 [`BACKOFF_MAX_SECS`]）
    pub fn next_backoff(&mut self) -> Duration {
        let exp = self.backoff_step.min(4);
        self.backoff_step = self.backoff_step.saturating_add(1);
        let secs = (1u64 << exp).min(BACKOFF_MAX_SECS);
        Duration::from_secs(secs)
    }
}

/// 连接 fftpd
///
/// # Errors
/// 连接失败时返回原因文本
pub async fn connect() -> Result<IpcConn, String> {
    Client::connect()
        .await
        .map(IpcConn)
        .map_err(|e| format!("{e:#}"))
}

/// 发送命令并把响应解析为指定形状
///
/// 连接按值传入（内部持有 `Arc`，克隆廉价），以便 future 满足 `'static`。
///
/// # Errors
/// 连接断开、服务端业务失败或响应形状不符时返回 [`IpcError`]
pub async fn request<T: DeserializeOwned>(conn: IpcConn, cmd: Command) -> Result<T, IpcError> {
    let data = conn.0.request(cmd).await.map_err(map_error)?;
    parse_data(data).map_err(|e| IpcError::BadResponse(e.to_string()))
}

/// 把 fftp-ipc 的错误映射为界面可展示的形式
#[must_use]
pub fn map_error(err: ClientError) -> IpcError {
    match err {
        ClientError::Disconnected(reason) => IpcError::Disconnected(reason),
        ClientError::Request(e) => IpcError::Request(e.message),
    }
}

/// `GetStatus` 响应
#[derive(Debug, Clone, Deserialize)]
pub struct ServerStatus {
    /// FTP 服务是否运行
    pub ftp_running: bool,
    /// SFTP 服务是否运行
    pub sftp_running: bool,
    /// fftpd 版本
    pub version: String,
    /// 配置文件路径
    pub config_path: String,
    /// 用户库路径
    pub users_path: String,
    /// IPC 端点
    pub endpoint: String,
}

/// `GetInitialState` 响应（运行状态字段以 `GetStatus` 为准）
#[derive(Debug, Clone, Deserialize)]
pub struct InitialState {
    /// config.toml 原文
    pub config: String,
    /// users.json 原文
    pub users: String,
}

/// `GetConfig`/`SaveConfig`/`GetUsers`/`SaveUsers` 响应
#[derive(Debug, Clone, Deserialize)]
pub struct TextContent {
    /// 文本原文
    pub content: String,
}

/// `GetRecentLogs`/`GetLogFileContent` 响应
#[derive(Debug, Clone, Deserialize)]
pub struct LogEntries {
    /// 日志条目
    pub entries: Vec<LogEntry>,
}

/// `GetFileOpLogContent` 响应
#[derive(Debug, Clone, Deserialize)]
pub struct FileOpEntries {
    /// 文件操作审计条目
    pub entries: Vec<FileOpLogEntry>,
}

/// `GetLogFiles`/`GetFileOpLogFiles` 响应
#[derive(Debug, Clone, Deserialize)]
pub struct LogFiles {
    /// 日志文件列表
    pub files: Vec<LogFileInfo>,
}

/// 发送无需关心响应体的命令（服务启停、审计、目录辅助等）
///
/// # Errors
/// 同 [`request`]
pub async fn request_ok(conn: IpcConn, cmd: Command) -> Result<(), IpcError> {
    request::<serde_json::Value>(conn, cmd).await.map(|_| ())
}

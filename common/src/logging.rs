//! 日志与文件操作审计（docs/design.md §4「日志」：Linux `tracing_logger` 架构 + Windows `log_types` 字段）
//!
//! - tracing 初始化：控制台 / 程序日志文件 / file-ops 审计文件三层；
//!   程序日志支持 JSON 与文本两种格式（[`LoggingConfig::enable_json`]），审计日志恒为 JSON 行；
//!   两类文件均按「日期 + 单文件大小」轮转，保留 [`LoggingConfig::max_log_files`] 份；
//! - 内存环形缓冲（[`RingBuffer`]）：程序日志经常驻的 [`MemoryLogLayer`] 捕获
//!   （逐条按 `enable_gui_logging` 判断，运行期切换即时生效），审计条目由
//!   [`Logging::write_file_op`] 直接写入，供 IPC 拉取（`recent`）与订阅（`subscribe`）；
//! - 日志文件管理：[`Logging::list_log_files`] / [`Logging::read_log_file`]（程序日志）与
//!   [`Logging::list_file_op_log_files`] / [`Logging::read_file_op_log`]（审计）。
//!
//! 线格式对应关系（common 不依赖 fftp-ipc，此处定义字段完全一致的本地结构，
//! 与 `fftp_ipc::protocol::{LogEntry, FileOpLogEntry, LogFileInfo}` 逐字段对应，
//! serde 形状相同，可直接按字段拷贝/`serde_json` 转换）：
//!
//! | 本模块 | fftp-ipc 线格式 |
//! |---|---|
//! | [`LogEntry`] | `LogEntry`：`timestamp/level/source/message/client_ip/username/action` |
//! | [`FileOpLogEntry`] | `FileOpLogEntry`：`timestamp/username/client_ip/operation/file_path/file_size/protocol/success/message` |
//! | [`LogFileInfo`] | `LogFileInfo`：`name/path` |

use crate::sync::MutexExt;
use anyhow::{Context, Result, bail};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use tracing::field::Visit;
use tracing::{Event, Subscriber};
use tracing_appender::non_blocking;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::layer::{Context as LayerContext, Layer, SubscriberExt};
use tracing_subscriber::reload::{self, Handle};
use tracing_subscriber::{Registry, fmt};

use crate::config::LoggingConfig;

/// 程序日志文件名前缀（`fftpd.2026-10-21.log`）
pub const PROGRAM_LOG_PREFIX: &str = "fftpd";
/// 文件操作审计日志文件名前缀（`file-ops.2026-10-21.log`）
pub const FILE_OP_LOG_PREFIX: &str = "file-ops";
/// 文件操作审计的 tracing target（与旧版一致，路由到审计日志文件）
pub const AUDIT_TARGET: &str = "file_ops";

/// 程序日志条目（与 `fftp_ipc::protocol::LogEntry` 字段一一对应）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// RFC3339 时间戳
    pub timestamp: String,
    /// `TRACE`/`DEBUG`/`INFO`/`WARN`/`ERROR`
    pub level: String,
    /// 日志来源（tracing target）
    pub source: String,
    pub message: String,
    #[serde(default)]
    pub client_ip: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub action: String,
}

/// 文件操作审计条目（与 `fftp_ipc::protocol::FileOpLogEntry` 字段一一对应）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOpLogEntry {
    /// RFC3339 时间戳
    pub timestamp: String,
    pub username: String,
    pub client_ip: String,
    /// 操作（`UPLOAD`/`DOWNLOAD`/`DELETE`/`RENAME`/`MKDIR`/`RMDIR`/...）
    pub operation: String,
    pub file_path: String,
    pub file_size: u64,
    /// `FTP` / `SFTP` / `GUI`
    pub protocol: String,
    pub success: bool,
    #[serde(default)]
    pub message: String,
}

/// 日志文件信息（与 `fftp_ipc::protocol::LogFileInfo` 字段一一对应）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFileInfo {
    /// 文件名（不含扩展名），如 `fftpd.2026-10-21`
    pub name: String,
    /// 完整路径
    pub path: String,
}

// ---------------------------------------------------------------------------
// 内存环形缓冲
// ---------------------------------------------------------------------------

struct RingBufferInner<T> {
    entries: StdMutex<VecDeque<T>>,
    capacity: usize,
    tx: tokio::sync::broadcast::Sender<T>,
}

/// 内存日志环形缓冲：`push` 追加并广播给 `subscribe` 的订阅者，`recent` 供 IPC 拉取。
///
/// [`LogBuffer`]（= `RingBuffer<LogEntry>`）同时作为 tracing `Layer` 挂载到全局
/// subscriber，自动捕获程序日志事件。
pub struct RingBuffer<T> {
    inner: Arc<RingBufferInner<T>>,
}

/// 程序日志环形缓冲
pub type LogBuffer = RingBuffer<LogEntry>;
/// 文件操作审计环形缓冲
pub type FileOpBuffer = RingBuffer<FileOpLogEntry>;

impl<T> Clone for RingBuffer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: Clone> RingBuffer<T> {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(capacity.max(16));
        Self {
            inner: Arc::new(RingBufferInner {
                entries: StdMutex::new(VecDeque::with_capacity(capacity.min(1024))),
                capacity,
                tx,
            }),
        }
    }

    /// 追加一条记录到环形缓冲（满时淘汰最旧一条），并广播给订阅者
    ///
    /// # Panics
    /// 内部互斥锁中毒时自动恢复（见 [`crate::sync`]）
    pub fn push(&self, entry: T) {
        {
            let mut entries = self.inner.entries.lock_recover();
            if entries.len() >= self.inner.capacity {
                entries.pop_front();
            }
            entries.push_back(entry.clone());
        }
        // 无订阅者时 send 返回 Err，忽略即可
        let _ = self.inner.tx.send(entry);
    }

    /// 最近 `count` 条记录，按时间正序返回（最旧→最新）
    ///
    /// # Panics
    /// 内部互斥锁中毒时自动恢复（见 [`crate::sync`]）
    #[must_use]
    pub fn recent(&self, count: usize) -> Vec<T> {
        let entries = self.inner.entries.lock_recover();
        let skip = entries.len().saturating_sub(count);
        entries.iter().skip(skip).cloned().collect()
    }

    /// 订阅实时日志推送（供 IPC `subscribe_logs`）
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<T> {
        self.inner.tx.subscribe()
    }

    /// 当前缓冲中的条目数
    ///
    /// # Panics
    /// 内部互斥锁中毒时自动恢复（见 [`crate::sync`]）
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.entries.lock_recover().len()
    }

    /// 缓冲是否为空
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 从 tracing 事件字段中提取 message / `client_ip` / username / action
#[derive(Default)]
struct LogFieldCollector {
    message: String,
    client_ip: Option<String>,
    username: Option<String>,
    action: Option<String>,
}

impl Visit for LogFieldCollector {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "client_ip" => self.client_ip = Some(format!("{value:?}")),
            "username" => self.username = Some(format!("{value:?}")),
            "action" => self.action = Some(format!("{value:?}")),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "message" => self.message = value.to_string(),
            "client_ip" => self.client_ip = Some(value.to_string()),
            "username" => self.username = Some(value.to_string()),
            "action" => self.action = Some(value.to_string()),
            _ => {}
        }
    }
}

/// 实时日志内存层：`enable_gui_logging` 开启时把非审计事件写入环形缓冲
///
/// 常驻挂载（而非按初始配置条件挂载）：关闭时条目不进缓冲，运行期切换
/// `enable_gui_logging` 无需重启进程即可生效（修正日志通道热开关）。
struct MemoryLogLayer {
    buffer: LogBuffer,
    live_config: Arc<StdMutex<LoggingConfig>>,
}

impl<S: Subscriber> Layer<S> for MemoryLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        if !self.live_config.lock_recover().enable_gui_logging {
            return;
        }
        let metadata = event.metadata();
        if metadata.target().starts_with(AUDIT_TARGET) {
            return;
        }

        let mut collector = LogFieldCollector::default();
        event.record(&mut collector);

        self.buffer.push(LogEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            level: metadata.level().to_string(),
            source: metadata.target().to_string(),
            message: collector.message,
            client_ip: collector.client_ip.unwrap_or_default(),
            username: collector.username.unwrap_or_default(),
            action: collector.action.unwrap_or_default(),
        });
    }
}

// ---------------------------------------------------------------------------
// 日志设施
// ---------------------------------------------------------------------------

static RELOAD_HANDLE: OnceLock<Handle<Targets, Registry>> = OnceLock::new();

/// 日志设施：内存环形缓冲 + 配置（文件管理按 [`LoggingConfig`] 生效）
pub struct Logging {
    config: LoggingConfig,
    /// 运行期可热更新的参数副本（IPC `SaveLogConfig` 后经 [`Logging::update_config`] 替换）；
    /// Arc 共享给 [`MemoryLogLayer`]，使 `enable_gui_logging` 运行期切换即时生效；
    /// 文件管理与审计写入按此副本生效，初始值与 [`Self::config`] 相同
    live_config: Arc<StdMutex<LoggingConfig>>,
    log_buffer: LogBuffer,
    file_op_buffer: FileOpBuffer,
}

impl Logging {
    /// 创建日志设施（仅内存缓冲），不安装全局 tracing subscriber。
    ///
    /// 供测试或无需 tracing 输出的工具使用；正常服务端入口用 [`Logging::init`]。
    #[must_use]
    pub fn new(config: &LoggingConfig) -> Self {
        Self {
            config: config.clone(),
            live_config: Arc::new(StdMutex::new(config.clone())),
            log_buffer: LogBuffer::new(2000),
            file_op_buffer: FileOpBuffer::new(2000),
        }
    }

    /// 创建日志设施并安装全局 tracing subscriber：
    /// 控制台 + 程序日志文件 + file-ops 审计文件 + 内存缓冲层。
    ///
    /// 内存缓冲层常驻，逐条按 `enable_gui_logging` 判断（运行期切换即时生效）。
    ///
    /// # Errors
    /// 日志目录创建失败、滚动 appender 构建失败，或全局 subscriber 已被初始化时返回错误
    pub fn init(config: &LoggingConfig) -> Result<Self> {
        let logging = Self::new(config);
        install_subscriber(
            config,
            &logging.log_buffer,
            Arc::clone(&logging.live_config),
        )?;
        Ok(logging)
    }

    #[must_use]
    pub fn config(&self) -> &LoggingConfig {
        &self.config
    }

    /// 当前生效的日志参数（初始化参数经 [`Self::update_config`] 热更新后的值）
    #[must_use]
    pub fn live_config(&self) -> LoggingConfig {
        self.live_config.lock_recover().clone()
    }

    /// 热更新日志参数（新增钩子，供守护进程 `SaveLogConfig` 后调用）
    ///
    /// 只影响运行期可变的部分：文件管理/审计写入按新参数执行，
    /// `enable_gui_logging` 由内存层逐条判断、即时生效，
    /// 日志级别另经 [`set_log_level`] 动态调整；
    /// 文件 appender 的目录/格式在 `init` 时确定，变更需重启进程完整生效。
    pub fn update_config(&self, config: LoggingConfig) {
        *self.live_config.lock_recover() = config;
    }

    /// 程序日志环形缓冲
    #[must_use]
    pub fn log_buffer(&self) -> &LogBuffer {
        &self.log_buffer
    }

    /// 文件操作审计环形缓冲
    #[must_use]
    pub fn file_op_buffer(&self) -> &FileOpBuffer {
        &self.file_op_buffer
    }

    /// 写入一条文件操作审计记录：`enable_gui_logging` 开启时进内存缓冲，
    /// 同时经 tracing `file_ops` target 写入审计日志文件。
    pub fn write_file_op(&self, entry: &FileOpLogEntry) {
        if self.live_config().enable_gui_logging {
            self.file_op_buffer.push(entry.clone());
        }

        tracing::info!(
            target: AUDIT_TARGET,
            username = entry.username.as_str(),
            client_ip = entry.client_ip.as_str(),
            operation = entry.operation.as_str(),
            file_path = entry.file_path.as_str(),
            file_size = entry.file_size,
            protocol = entry.protocol.as_str(),
            success = entry.success,
            message = entry.message.as_str(),
            "file-op"
        );
    }

    /// 审计写入口（对应 IPC `WriteAuditLog`）。
    ///
    /// 字段映射：`user`→`username`、`action`→`operation`、`target`→`file_path`、
    /// `details`→`message`；`protocol` 记为 `GUI`，`file_size` 为 0。
    pub fn write_audit(&self, user: &str, action: &str, target: &str, details: &str) {
        self.write_file_op(&FileOpLogEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            username: user.to_string(),
            client_ip: String::new(),
            operation: action.to_string(),
            file_path: target.to_string(),
            file_size: 0,
            protocol: "GUI".to_string(),
            success: true,
            message: details.to_string(),
        });
    }

    /// 列出程序日志文件（新→旧），最多 [`LoggingConfig::max_log_files`] 份
    #[must_use]
    pub fn list_log_files(&self) -> Vec<LogFileInfo> {
        let config = self.live_config();
        list_log_files_in(
            &config.resolved_log_dir(),
            PROGRAM_LOG_PREFIX,
            config.max_log_files,
        )
    }

    /// 列出 file-ops 审计日志文件（新→旧），最多 [`LoggingConfig::max_log_files`] 份
    #[must_use]
    pub fn list_file_op_log_files(&self) -> Vec<LogFileInfo> {
        let config = self.live_config();
        list_log_files_in(
            &config.resolved_log_dir(),
            FILE_OP_LOG_PREFIX,
            config.max_log_files,
        )
    }

    /// 读取程序日志文件最后 `count` 条（JSON 与文本格式均可解析）
    ///
    /// # Errors
    /// `path` 不在日志目录内（防越权读取）或无法读取时返回错误
    pub fn read_log_file(&self, path: &Path, count: usize) -> Result<Vec<LogEntry>> {
        let config = self.live_config();
        ensure_path_in_dir(path, &config.resolved_log_dir())?;
        Ok(tail_lines(path, count, config.max_log_size)
            .iter()
            .filter_map(|line| parse_program_line(line))
            .collect())
    }

    /// 读取 file-ops 审计日志文件最后 `count` 条（JSON 行）
    ///
    /// # Errors
    /// `path` 不在日志目录内（防越权读取）或无法读取时返回错误
    pub fn read_file_op_log(&self, path: &Path, count: usize) -> Result<Vec<FileOpLogEntry>> {
        let config = self.live_config();
        ensure_path_in_dir(path, &config.resolved_log_dir())?;
        Ok(tail_lines(path, count, config.max_log_size)
            .iter()
            .filter_map(|line| parse_file_op_line(line))
            .collect())
    }
}

/// 按「日期 + 单文件大小」轮转的日志文件写入器
///
/// `tracing_appender` 的 rolling appender 只支持时间轮转；`max_log_size`
/// 需要额外的体积上限，故由本类型实现：
/// - 文件名 `<prefix>.<YYYY-MM-DD>.<NNNN>.log`（序号零填充，保证字典序即时间序）；
/// - 单文件达到 `max_log_size` 后切到同日后继序号；跨天自动切新日期；
/// - 只保留最新 `max_log_files` 份（与列表/读取接口的截断口径一致）。
struct SizeRotatingFile {
    dir: PathBuf,
    prefix: String,
    max_size: u64,
    max_files: usize,
    date: String,
    seq: u32,
    size: u64,
    file: File,
}

impl SizeRotatingFile {
    fn new(dir: &Path, prefix: &str, max_size: u64, max_files: usize) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let dir = dir.to_path_buf();
        let prefix = prefix.to_string();
        let date = Local::now().format("%Y-%m-%d").to_string();

        // 续写当日最新的未满文件；否则创建下一个序号
        let (seq, path) = Self::next_slot(&dir, &prefix, &date, max_size)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();

        let writer = Self {
            dir,
            prefix,
            max_size,
            max_files: max_files.max(1),
            date,
            seq,
            size,
            file,
        };
        writer.prune();
        Ok(writer)
    }

    /// 选择写入文件：优先当日最新且未超限的文件，否则下一个序号
    fn next_slot(
        dir: &Path,
        prefix: &str,
        date: &str,
        max_size: u64,
    ) -> io::Result<(u32, PathBuf)> {
        let mut latest: Option<(u32, PathBuf, u64)> = None;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let Some(rest) = name
                    .strip_prefix(&format!("{prefix}.{date}."))
                    .and_then(|r| r.strip_suffix(".log"))
                else {
                    continue;
                };
                let Ok(seq) = rest.parse::<u32>() else {
                    continue;
                };
                let size = entry.metadata().map_or(0, |m| m.len());
                if latest.as_ref().is_none_or(|(s, _, _)| seq >= *s) {
                    latest = Some((seq, path, size));
                }
            }
        }

        match latest {
            Some((seq, path, size)) if max_size == 0 || size < max_size => Ok((seq, path)),
            Some((seq, _, _)) => {
                let next = seq
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("日志文件序号耗尽"))?;
                Ok((next, dir.join(format!("{prefix}.{date}.{next:04}.log"))))
            }
            None => Ok((0, dir.join(format!("{prefix}.{date}.0000.log")))),
        }
    }

    fn rotate(&mut self) -> io::Result<()> {
        let today = Local::now().format("%Y-%m-%d").to_string();
        let next_date = if today == self.date {
            self.date.clone()
        } else {
            self.date.clone_from(&today);
            today
        };

        let next = self
            .seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("日志文件序号耗尽"))?;
        let path = self
            .dir
            .join(format!("{}.{}.{:04}.log", self.prefix, next_date, next));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.file = file;
        self.size = 0;
        self.seq = next;
        self.date = next_date;
        self.prune();
        Ok(())
    }

    /// 删除超出 `max_files` 的最旧文件（按文件名时间序）
    fn prune(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("log"))
                    && path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(&self.prefix))
            })
            .collect();
        files.sort();
        let excess = files.len().saturating_sub(self.max_files);
        for path in files.into_iter().take(excess) {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!("清理旧日志文件失败 {}: {e}", path.display());
            }
        }
    }
}

impl Write for SizeRotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.max_size > 0 && self.size > 0 && self.size + buf.len() as u64 > self.max_size {
            self.rotate()?;
        }
        let written = self.file.write(buf)?;
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn install_subscriber(
    config: &LoggingConfig,
    log_buffer: &LogBuffer,
    live_config: Arc<StdMutex<LoggingConfig>>,
) -> Result<()> {
    let log_dir = config.resolved_log_dir();
    std::fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

    let filter = parse_log_level(&config.log_level);

    let program_appender = SizeRotatingFile::new(
        &log_dir,
        PROGRAM_LOG_PREFIX,
        config.max_log_size,
        config.max_log_files,
    )
    .context("创建程序日志文件失败")?;
    let (non_blocking_program, guard_program) = non_blocking(program_appender);

    let audit_appender = SizeRotatingFile::new(
        &log_dir,
        FILE_OP_LOG_PREFIX,
        config.max_log_size,
        config.max_log_files,
    )
    .context("创建审计日志文件失败")?;
    let (non_blocking_audit, guard_audit) = non_blocking(audit_appender);

    let (reload_filter, reload_handle) = reload::Layer::new(filter.clone());

    let program_layer = if config.enable_json {
        fmt::layer()
            .with_writer(non_blocking_program)
            .with_ansi(false)
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_line_number(true)
            .with_timer(ChronoLocal::rfc_3339())
            .json()
            .boxed()
    } else {
        fmt::layer()
            .with_writer(non_blocking_program)
            .with_ansi(false)
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_line_number(true)
            .with_timer(ChronoLocal::rfc_3339())
            .boxed()
    };
    let program_layer =
        program_layer.with_filter(filter.clone().with_target(AUDIT_TARGET, LevelFilter::OFF));

    // 审计日志恒为 JSON 行（[`parse_file_op_line`] 仅按 JSON 解析）
    let audit_layer = fmt::layer()
        .with_writer(non_blocking_audit)
        .with_ansi(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_line_number(false)
        .with_timer(ChronoLocal::rfc_3339())
        .json()
        .with_filter(Targets::new().with_target(AUDIT_TARGET, LevelFilter::INFO));

    let console_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_line_number(false)
        .with_timer(ChronoLocal::rfc_3339())
        .with_filter(filter.clone().with_target(AUDIT_TARGET, LevelFilter::OFF));

    // 内存缓冲层常驻：enable_gui_logging 的开关在层内逐条判断（运行期热生效）
    let subscriber = Registry::default()
        .with(reload_filter)
        .with(console_layer)
        .with(program_layer)
        .with(audit_layer)
        .with(
            MemoryLogLayer {
                buffer: log_buffer.clone(),
                live_config,
            }
            .with_filter(filter.with_target(FILE_OP_LOG_PREFIX, LevelFilter::OFF)),
        );
    let subscriber = Box::new(subscriber) as Box<dyn Subscriber + Send + Sync>;

    tracing::subscriber::set_global_default(subscriber)?;
    let _ = RELOAD_HANDLE.set(reload_handle);

    // 非阻塞写入线程需存活到进程结束
    std::mem::forget(guard_program);
    std::mem::forget(guard_audit);

    Ok(())
}

/// 动态调整全局日志级别（对应 IPC `save_log_config` 的日志级别变更）
///
/// # Errors
/// 过滤器替换失败时返回错误
pub fn set_log_level(level: &str) -> Result<()> {
    let filter = parse_log_level(level);

    if let Some(handle) = RELOAD_HANDLE.get() {
        handle.modify(|old_filter| {
            *old_filter = filter;
        })?;
    }

    Ok(())
}

/// 简易初始化：仅控制台输出，INFO 起始级别
///
/// # Errors
/// 全局 subscriber 已被初始化时返回错误
pub fn init_simple() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_line_number(false)
        .init();
    Ok(())
}

fn level_to_filter(level: &str) -> LevelFilter {
    match level.to_lowercase().as_str() {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "warn" | "warning" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        "off" => LevelFilter::OFF,
        // "info" 与未知级别均落到 INFO
        _ => LevelFilter::INFO,
    }
}

fn parse_log_level(level: &str) -> Targets {
    Targets::new()
        .with_default(level_to_filter(level))
        .with_target("russh", LevelFilter::INFO)
        .with_target("russh-keys", LevelFilter::WARN)
        .with_target("tokio", LevelFilter::WARN)
}

// ---------------------------------------------------------------------------
// 日志文件管理
// ---------------------------------------------------------------------------

/// 列出目录下带指定前缀的日志文件（新→旧），如 `fftpd` 匹配 `fftpd.2026-10-21.log`
///
/// 扩展名比较大小写不敏感；前缀大小写敏感（由本程序生成，恒定小写）。
/// 结果按 `max_files` 截断（对应 [`LoggingConfig::max_log_files`]）。
fn list_log_files_in(log_dir: &Path, prefix: &str, max_files: usize) -> Vec<LogFileInfo> {
    let Ok(entries) = std::fs::read_dir(log_dir) else {
        return Vec::new();
    };

    let mut files: Vec<LogFileInfo> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    n.starts_with(prefix)
                        && p.extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("log"))
                })
        })
        .map(|p| LogFileInfo {
            name: p
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string(),
            path: p.to_string_lossy().into_owned(),
        })
        .collect();

    files.sort_by(|a, b| b.name.cmp(&a.name));
    files.truncate(max_files);
    files
}

/// 读取文件最后 `count` 行；最多从文件末尾扫描 `max_bytes` 字节
/// （对应 [`LoggingConfig::max_log_size`]，防止读取超大文件）
fn tail_lines(path: &Path, count: usize, max_bytes: u64) -> Vec<String> {
    use std::io::{BufRead, Seek, SeekFrom};

    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };

    let file_len = file.metadata().map_or(0, |m| m.len());
    if max_bytes > 0 && file_len > max_bytes {
        let start = file_len - max_bytes;
        let _ = file.seek(SeekFrom::Start(start));
    }

    let mut reader = std::io::BufReader::new(file);
    let mut lines = Vec::new();
    let mut first = String::new();
    // 从文件中段开始时首行可能不完整，丢弃
    let truncated = max_bytes > 0 && file_len > max_bytes;
    if truncated {
        let _ = reader.read_line(&mut first);
    }

    for line in reader.lines().map_while(std::io::Result::ok) {
        lines.push(line);
        if lines.len() > count * 2 {
            let drain_to = lines.len() - count;
            lines.drain(..drain_to);
        }
    }

    if lines.len() > count {
        lines.split_off(lines.len() - count)
    } else {
        lines
    }
}

fn opt_to_string(v: serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// 解析一行程序日志（JSON 或文本格式），尽力而为：失败返回 `None`
fn parse_program_line(line: &str) -> Option<LogEntry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
        && v.is_object()
    {
        return Some(LogEntry {
            timestamp: opt_to_string(v.get("timestamp").cloned().unwrap_or_default())
                .unwrap_or_default(),
            level: opt_to_string(v.get("level").cloned().unwrap_or_default())
                .unwrap_or_else(|| "INFO".into()),
            source: opt_to_string(v.get("target").cloned().unwrap_or_default()).unwrap_or_default(),
            message: v
                .get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or_default()
                .to_string(),
            client_ip: field_str(&v, "client_ip"),
            username: field_str(&v, "username"),
            action: field_str(&v, "action"),
        });
    }

    // 文本格式：`<rfc3339时间> <LEVEL> <target>: <message>`
    let (timestamp, remainder) = line.split_once(' ')?;
    let remainder = remainder.trim_start();
    let (level, rest) = remainder.split_once(' ')?;
    let rest = rest.trim_start();
    let (source, message) = match rest.split_once(": ") {
        Some((s, m)) => (s.to_string(), m.to_string()),
        None => (String::new(), rest.to_string()),
    };

    Some(LogEntry {
        timestamp: timestamp.to_string(),
        level: level.to_string(),
        source,
        message,
        client_ip: String::new(),
        username: String::new(),
        action: String::new(),
    })
}

/// 解析一行 file-ops 审计日志（JSON 格式），失败返回 `None`
fn parse_file_op_line(line: &str) -> Option<FileOpLogEntry> {
    let v = serde_json::from_str::<serde_json::Value>(line.trim()).ok()?;

    Some(FileOpLogEntry {
        timestamp: v
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or_default()
            .to_string(),
        username: field_str(&v, "username"),
        client_ip: field_str(&v, "client_ip"),
        operation: field_str(&v, "operation"),
        file_path: field_str(&v, "file_path"),
        file_size: v
            .get("fields")
            .and_then(|f| f.get("file_size"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
        protocol: field_str(&v, "protocol"),
        success: v
            .get("fields")
            .and_then(|f| f.get("success"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or_default(),
        message: field_str(&v, "message"),
    })
}

fn field_str(v: &serde_json::Value, name: &str) -> String {
    v.get("fields")
        .and_then(|f| f.get(name))
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string()
}

/// 校验日志文件路径位于指定目录内，防止越权读取任意文件
///
/// # Errors
/// 路径无法解析或位于目录之外时返回错误
pub fn ensure_path_in_dir(path: &Path, dir: &Path) -> Result<()> {
    let canonical = std::fs::canonicalize(path)?;
    let log_dir = std::fs::canonicalize(dir)?;
    if !canonical.starts_with(&log_dir) {
        bail!("path {} is outside log directory", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_logging(gui: bool, json: bool) -> (tempfile::TempDir, Logging) {
        let dir = tempfile::tempdir().unwrap();
        let config = LoggingConfig {
            log_dir: dir.path().to_string_lossy().into_owned(),
            log_level: "info".to_string(),
            max_log_files: 10,
            max_log_size: 10 * 1024 * 1024,
            enable_json: json,
            enable_gui_logging: gui,
        };
        (dir, Logging::new(&config))
    }

    // ---- 日志级别 ----

    #[test]
    fn parse_log_level_mapping() {
        assert_eq!(level_to_filter("debug"), LevelFilter::DEBUG);
        assert_eq!(level_to_filter("info"), LevelFilter::INFO);
        assert_eq!(level_to_filter("warn"), LevelFilter::WARN);
        assert_eq!(level_to_filter("warning"), LevelFilter::WARN);
        assert_eq!(level_to_filter("error"), LevelFilter::ERROR);
        assert_eq!(level_to_filter("off"), LevelFilter::OFF);
        // 未知级别落到 INFO
        assert_eq!(level_to_filter("invalid"), LevelFilter::INFO);
    }

    // ---- 环形缓冲 ----

    #[test]
    fn ring_buffer_evicts_oldest() {
        let buffer = LogBuffer::new(4);
        for i in 0..6 {
            buffer.push(LogEntry {
                timestamp: format!("t{i}"),
                level: "INFO".into(),
                source: "test".into(),
                message: format!("m{i}"),
                client_ip: String::new(),
                username: String::new(),
                action: String::new(),
            });
        }
        let recent = buffer.recent(10);
        assert_eq!(recent.len(), 4);
        assert_eq!(recent[0].timestamp, "t2", "最旧的应被淘汰");
        assert_eq!(recent[3].timestamp, "t5");
    }

    #[test]
    fn ring_buffer_recent_limits_count_in_order() {
        let buffer = LogBuffer::new(10);
        for i in 0..5 {
            buffer.push(LogEntry {
                timestamp: format!("t{i}"),
                level: "INFO".into(),
                source: "test".into(),
                message: format!("m{i}"),
                client_ip: String::new(),
                username: String::new(),
                action: String::new(),
            });
        }
        let recent = buffer.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].message, "m2");
        assert_eq!(recent[2].message, "m4");
        assert!(buffer.subscribe().try_recv().is_err(), "订阅前无历史推送");
    }

    // ---- 审计写入 ----

    #[test]
    fn write_audit_lands_in_file_op_buffer() {
        let (_dir, logging) = temp_logging(true, false);
        logging.write_audit("admin", "save_config", "config.toml", "修改端口");

        let recent = logging.file_op_buffer().recent(10);
        assert_eq!(recent.len(), 1);
        let entry = &recent[0];
        assert_eq!(entry.username, "admin");
        assert_eq!(entry.operation, "save_config");
        assert_eq!(entry.file_path, "config.toml");
        assert_eq!(entry.message, "修改端口");
        assert_eq!(entry.protocol, "GUI");
        assert!(entry.success);
        assert_eq!(entry.file_size, 0);
        assert!(entry.timestamp.contains('T'), "时间戳应为 RFC3339");
    }

    #[test]
    fn gui_logging_disabled_skips_buffer() {
        let (_dir, logging) = temp_logging(false, false);
        logging.write_audit("admin", "action", "target", "details");
        logging.write_file_op(&FileOpLogEntry {
            timestamp: "t".into(),
            username: "u".into(),
            client_ip: "ip".into(),
            operation: "UPLOAD".into(),
            file_path: "/a".into(),
            file_size: 1,
            protocol: "FTP".into(),
            success: true,
            message: "ok".into(),
        });
        assert!(
            logging.file_op_buffer().is_empty(),
            "关闭 GUI 日志时只记文件不进缓冲"
        );
    }

    // ---- 行解析 ----

    #[test]
    fn parse_text_program_line() {
        let entry =
            parse_program_line("2026-09-05T10:00:00+08:00  INFO fftpd_ftp::server: FTP 服务已启动")
                .expect("parse ok");
        assert_eq!(entry.level, "INFO");
        assert_eq!(entry.source, "fftpd_ftp::server");
        assert_eq!(entry.message, "FTP 服务已启动");
    }

    #[test]
    fn parse_json_program_line() {
        let line = r#"{"timestamp":"2026-09-05T10:00:00+08:00","level":"INFO","target":"fftpd","fields":{"message":"hello","client_ip":"1.2.3.4"}}"#;
        let entry = parse_program_line(line).expect("parse ok");
        assert_eq!(entry.source, "fftpd");
        assert_eq!(entry.message, "hello");
        assert_eq!(entry.client_ip, "1.2.3.4");
    }

    #[test]
    fn parse_file_op_json_line() {
        let line = r#"{"timestamp":"2026-09-05T10:00:00+08:00","fields":{"username":"u","client_ip":"1.2.3.4","operation":"UPLOAD","file_path":"/a","file_size":10,"protocol":"FTP","success":true,"message":"文件上传成功"}}"#;
        let entry = parse_file_op_line(line).expect("parse ok");
        assert_eq!(entry.operation, "UPLOAD");
        assert_eq!(entry.file_size, 10);
        assert!(entry.success);
        assert_eq!(entry.message, "文件上传成功");
    }

    // ---- 文件管理 ----

    #[test]
    fn list_files_filters_prefix_and_sorts_desc() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "fftpd.2026-09-01.log",
            "fftpd.2026-09-05.log",
            "fftpd.2026-09-03.log",
            "file-ops.2026-09-05.log", // 不同前缀，应被过滤
            "fftpd.2026-09-02.txt",    // 非日志扩展名，应被过滤
        ] {
            std::fs::write(dir.path().join(name), "x").unwrap();
        }

        let files = list_log_files_in(dir.path(), PROGRAM_LOG_PREFIX, 10);
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["fftpd.2026-09-05", "fftpd.2026-09-03", "fftpd.2026-09-01"]
        );
        assert!(files[0].path.ends_with("fftpd.2026-09-05.log"));
    }

    #[test]
    fn list_files_caps_at_max_files() {
        let dir = tempfile::tempdir().unwrap();
        for day in 1..=5 {
            std::fs::write(dir.path().join(format!("fftpd.2026-09-0{day}.log")), "x").unwrap();
        }
        let files = list_log_files_in(dir.path(), PROGRAM_LOG_PREFIX, 2);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "fftpd.2026-09-05");
        assert_eq!(files[1].name, "fftpd.2026-09-04");
    }

    #[test]
    fn list_files_missing_dir_returns_empty() {
        let files = list_log_files_in(Path::new("/nonexistent/fftpd/logs"), "fftpd", 10);
        assert_eq!(files, Vec::new(), "不存在的目录应返回空列表");
    }

    #[test]
    fn tail_lines_returns_last_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fftpd.2026-09-08.log");
        let mut content = String::new();
        for i in 0..5 {
            use std::fmt::Write as _;
            let _ = writeln!(content, "2026-09-08T10:0{i}:00+08:00  INFO fftpd: line-{i}");
        }
        std::fs::write(&path, content).unwrap();

        let lines = tail_lines(&path, 3, u64::MAX);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].ends_with("line-2"), "最早的一条应为 line-2");
        assert!(lines[2].ends_with("line-4"));

        // count 超过文件行数时返回全部
        assert_eq!(tail_lines(&path, 100, u64::MAX).len(), 5);
    }

    #[test]
    fn tail_lines_byte_budget_skips_incomplete_head() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fftpd.log");
        let mut content = String::new();
        for i in 0..10 {
            use std::fmt::Write as _;
            let _ = writeln!(content, "2026-09-08T10:00:0{i}+08:00  INFO fftpd: line-{i}");
        }
        std::fs::write(&path, content).unwrap();

        // 只允许扫描 100 字节：首行从文件中段开始，应被丢弃
        let lines = tail_lines(&path, 100, 100);
        assert_ne!(lines, Vec::<String>::new());
        assert!(
            lines[0].starts_with("2026-09-08T"),
            "中段截断的半行应被丢弃: {}",
            lines[0]
        );
    }

    #[test]
    fn read_log_file_roundtrip_via_logging() {
        let (dir, logging) = temp_logging(true, false);
        logging.write_audit("u", "UPLOAD", "/a", "ok");
        logging.write_audit("u", "DELETE", "/b", "nope");

        // 审计内容经 tracing 写入文件需要全局 subscriber；此处直接构造文件验证读取路径
        let file_op = dir.path().join("file-ops.2026-10-21.log");
        std::fs::write(
            &file_op,
            concat!(
                r#"{"timestamp":"t1","fields":{"username":"u1","client_ip":"ip","operation":"UPLOAD","file_path":"/a","file_size":1,"protocol":"FTP","success":true,"message":"ok"}}"#,
                "\n",
                "not-json-line\n",
            ),
        )
        .unwrap();

        let entries = logging
            .read_file_op_log(&file_op, 10)
            .expect("log dir 内的文件可读");
        assert_eq!(entries.len(), 1, "无法解析的行应被跳过");
        assert_eq!(entries[0].operation, "UPLOAD");

        let program = dir.path().join("fftpd.2026-10-21.log");
        std::fs::write(&program, "2026-10-21T10:00:00+08:00  INFO fftpd: started\n").unwrap();
        let parsed = logging.read_log_file(&program, 10).expect("可读");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].message, "started");
    }

    #[test]
    fn read_rejects_path_outside_log_dir() {
        let (_dir, logging) = temp_logging(true, false);
        let outside = std::env::temp_dir().join("fftpd-outside-test.log");
        std::fs::write(&outside, "x").unwrap();

        assert!(
            logging.read_log_file(&outside, 10).is_err(),
            "目录之外的路径应被拒绝"
        );
        assert!(logging.read_file_op_log(&outside, 10).is_err());
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn ensure_path_in_dir_accepts_inside() {
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("app.log");
        std::fs::write(&inside, "x").unwrap();
        assert!(ensure_path_in_dir(&inside, dir.path()).is_ok());
    }

    #[test]
    fn list_log_files_uses_config_dir_and_prefix() {
        let (dir, logging) = temp_logging(true, false);
        std::fs::write(dir.path().join("fftpd.2026-10-21.log"), "x").unwrap();
        std::fs::write(dir.path().join("file-ops.2026-10-21.log"), "x").unwrap();

        let program = logging.list_log_files();
        assert_eq!(program.len(), 1);
        assert_eq!(program[0].name, "fftpd.2026-10-21");

        let audit = logging.list_file_op_log_files();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].name, "file-ops.2026-10-21");
    }

    // ---- IPC 线格式形状 ----

    #[test]
    fn entries_serde_shape_matches_ipc_wire() {
        let entry = LogEntry {
            timestamp: "t".into(),
            level: "INFO".into(),
            source: "s".into(),
            message: "m".into(),
            client_ip: "ip".into(),
            username: "u".into(),
            action: "a".into(),
        };
        let v = serde_json::to_value(&entry).unwrap();
        for key in [
            "timestamp",
            "level",
            "source",
            "message",
            "client_ip",
            "username",
            "action",
        ] {
            assert!(v.get(key).is_some(), "缺少 IPC 字段 {key}");
        }

        let op = FileOpLogEntry {
            timestamp: "t".into(),
            username: "u".into(),
            client_ip: "ip".into(),
            operation: "UPLOAD".into(),
            file_path: "/a".into(),
            file_size: 7,
            protocol: "FTP".into(),
            success: true,
            message: "ok".into(),
        };
        let v = serde_json::to_value(&op).unwrap();
        for key in [
            "timestamp",
            "username",
            "client_ip",
            "operation",
            "file_path",
            "file_size",
            "protocol",
            "success",
            "message",
        ] {
            assert!(v.get(key).is_some(), "缺少 IPC 字段 {key}");
        }
    }
}

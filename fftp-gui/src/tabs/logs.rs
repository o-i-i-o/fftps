//! 日志页：实时订阅 + 文本搜索 + 文件历史
//!
//! 进入本页时由应用壳的订阅桥（`iced::stream::channel`）连上
//! `broadcast::Receiver`，先接收服务端补推的历史（`tail_count` 条），
//! 随后持续接收实时推送；级别着色展示，支持级别过滤、文本搜索、
//! 自动滚动、复制/导出；文件历史经 `GetLogFiles` + `GetLogFileContent` 切换。

use std::collections::VecDeque;

use fftp_ipc::protocol::{Command, LogEntry};
use iced::widget::{button, checkbox, column, pick_list, row, scrollable, text, text_input};
use iced::{Color, Element, Length, Task};

use crate::app::Message;
use crate::ipc_service::{self, IpcError, IpcService, LogEntries, LogFiles};
use crate::tabs::{
    error_line, file_options, info_line, relay_error, FileOption, ACCENT_COLOR, INFO_COLOR,
    MUTED_COLOR, WARN_COLOR,
};

/// 内存中保留的最大实时日志条数
const MAX_ENTRIES: usize = 5000;

/// 文件历史一次加载的条数
const FILE_LOAD_COUNT: u32 = 500;

/// 日志滚动区标识（自动滚动用）
const LOG_SCROLL_ID: &str = "logs-scroll";

/// 日志级别过滤
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LevelFilter {
    /// 不过滤
    #[default]
    All,
    /// `ERROR`
    Error,
    /// `WARN`
    Warn,
    /// `INFO`
    Info,
    /// `DEBUG`
    Debug,
    /// `TRACE`
    Trace,
}

impl LevelFilter {
    /// 下拉可选项
    pub const ALL: [Self; 6] = [
        Self::All,
        Self::Error,
        Self::Warn,
        Self::Info,
        Self::Debug,
        Self::Trace,
    ];

    /// 展示名
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            LevelFilter::All => "全部",
            LevelFilter::Error => "ERROR",
            LevelFilter::Warn => "WARN",
            LevelFilter::Info => "INFO",
            LevelFilter::Debug => "DEBUG",
            LevelFilter::Trace => "TRACE",
        }
    }

    /// 是否放行该级别（大小写不敏感）
    #[must_use]
    pub fn allows(self, level: &str) -> bool {
        match self {
            LevelFilter::All => true,
            filter => level.eq_ignore_ascii_case(filter.label()),
        }
    }
}

impl std::fmt::Display for LevelFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// 视图来源
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Viewing {
    /// 实时订阅
    #[default]
    Live,
    /// 历史文件
    File,
}

/// 日志页消息
#[derive(Debug, Clone)]
pub enum Msg {
    /// 实时日志条目
    Entry(LogEntry),
    /// 订阅期间因落后丢弃的条数
    Lagged(u64),
    /// `SubscribeLogs` 失败
    SubscribeFailed(IpcError),
    /// 变更级别过滤
    Filter(LevelFilter),
    /// 文本搜索
    Search(String),
    /// 自动滚动开关
    ToggleAutoScroll(bool),
    /// 清空实时日志
    Clear,
    /// 复制当前显示内容到剪贴板
    Copy,
    /// 导出当前显示内容到文件
    Export,
    /// 导出完成（附文件路径）
    Exported(Result<String, String>),
    /// 刷新文件历史列表（进入页面时触发）
    RefreshFiles,
    /// `GetLogFiles` 响应
    Files(Result<Vec<FileOption>, IpcError>),
    /// 选择历史文件
    SelectFile(FileOption),
    /// 加载历史文件内容
    LoadFile,
    /// `GetLogFileContent` 响应
    FileEntries(Result<Vec<LogEntry>, IpcError>),
    /// 返回实时视图
    BackToLive,
}

/// 日志页状态
#[derive(Debug, Default)]
pub struct LogsTab {
    /// 实时日志（环形缓冲）
    live: VecDeque<LogEntry>,
    /// 历史文件条目
    file_entries: Vec<LogEntry>,
    /// 日志文件列表
    files: Vec<FileOption>,
    /// 当前选中文件
    selected: Option<FileOption>,
    /// 视图来源
    viewing: Viewing,
    /// 级别过滤
    filter: LevelFilter,
    /// 文本搜索
    search: String,
    /// 自动滚动到底部
    auto_scroll: bool,
    error: Option<String>,
    info: Option<String>,
}

impl LogsTab {
    /// 更新页面状态；`ipc` 用于文件历史请求
    pub fn update(&mut self, msg: Msg, ipc: &IpcService) -> Task<Message> {
        match msg {
            Msg::Entry(entry) => {
                self.push(entry);
                self.auto_scroll_task()
            }
            Msg::Lagged(count) => {
                self.push(LogEntry {
                    timestamp: String::new(),
                    level: "WARN".to_owned(),
                    source: "gui".to_owned(),
                    message: format!("日志订阅落后，丢弃 {count} 条"),
                    client_ip: String::new(),
                    username: String::new(),
                    action: String::new(),
                });
                self.auto_scroll_task()
            }
            Msg::SubscribeFailed(e) => {
                self.error = Some(e.message().to_owned());
                relay_error(&e)
            }
            Msg::Filter(filter) => {
                self.filter = filter;
                Task::none()
            }
            Msg::Search(query) => {
                self.search = query;
                Task::none()
            }
            Msg::ToggleAutoScroll(on) => {
                self.auto_scroll = on;
                self.auto_scroll_task()
            }
            Msg::Clear => {
                self.live.clear();
                Task::none()
            }
            Msg::Copy => self.copy(),
            Msg::Export => self.export(),
            Msg::Exported(result) => self.on_exported(result),
            Msg::RefreshFiles => Self::refresh_files(ipc),
            Msg::Files(result) => self.on_files(result),
            Msg::SelectFile(option) => {
                self.selected = Some(option);
                self.load_file(ipc)
            }
            Msg::LoadFile => self.load_file(ipc),
            Msg::FileEntries(result) => self.on_file_entries(result),
            Msg::BackToLive => {
                self.viewing = Viewing::Live;
                Task::none()
            }
        }
    }

    /// 复制当前显示内容到剪贴板
    fn copy(&mut self) -> Task<Message> {
        let content = self.export_text();
        if content.is_empty() {
            self.info = Some("没有可复制的日志".to_owned());
            return Task::none();
        }
        let count = self.displayed().len();
        self.info = Some(format!("已复制 {count} 条日志到剪贴板"));
        iced::clipboard::write(content)
    }

    /// 导出当前显示内容到文件
    fn export(&mut self) -> Task<Message> {
        let content = self.export_text();
        if content.is_empty() {
            self.info = Some("没有可导出的日志".to_owned());
            return Task::none();
        }
        self.info = Some("正在导出…".to_owned());
        Task::perform(export_entries(content), |r| Message::Logs(Msg::Exported(r)))
    }

    /// 导出完成
    fn on_exported(&mut self, result: Result<String, String>) -> Task<Message> {
        match result {
            Ok(path) => self.info = Some(format!("日志已导出到：{path}")),
            Err(e) => self.error = Some(e),
        }
        Task::none()
    }

    /// `GetLogFiles` 响应：更新文件下拉
    fn on_files(&mut self, result: Result<Vec<FileOption>, IpcError>) -> Task<Message> {
        match result {
            Ok(files) => {
                if self.selected.is_none() {
                    self.selected = files.first().cloned();
                }
                self.files = files;
                self.error = None;
            }
            Err(e) => {
                self.error = Some(e.message().to_owned());
                return relay_error(&e);
            }
        }
        Task::none()
    }

    /// `GetLogFileContent` 响应：切换到历史视图
    fn on_file_entries(&mut self, result: Result<Vec<LogEntry>, IpcError>) -> Task<Message> {
        match result {
            Ok(entries) => {
                self.file_entries = entries;
                self.viewing = Viewing::File;
                self.error = None;
                self.info = None;
            }
            Err(e) => {
                self.error = Some(e.message().to_owned());
                return relay_error(&e);
            }
        }
        Task::none()
    }

    fn push(&mut self, entry: LogEntry) {
        self.live.push_back(entry);
        while self.live.len() > MAX_ENTRIES {
            self.live.pop_front();
        }
    }

    /// 自动滚动到底部（仅实时视图且开启时）
    fn auto_scroll_task(&self) -> Task<Message> {
        if self.auto_scroll && self.viewing == Viewing::Live {
            scrollable::snap_to(
                scrollable::Id::new(LOG_SCROLL_ID),
                scrollable::RelativeOffset { x: 0.0, y: 1.0 },
            )
        } else {
            Task::none()
        }
    }

    /// 拉取日志文件列表（进入页面时刷新下拉）
    fn refresh_files(ipc: &IpcService) -> Task<Message> {
        let Some(conn) = ipc.conn().cloned() else {
            return Task::done(Message::Logs(Msg::Files(Err(IpcError::Disconnected(
                "未连接 fftpd，无法读取日志文件列表".to_owned(),
            )))));
        };
        Task::perform(
            async move {
                ipc_service::request::<LogFiles>(conn, Command::GetLogFiles)
                    .await
                    .map(|r| file_options(&r.files))
            },
            |r| Message::Logs(Msg::Files(r)),
        )
    }

    /// 加载历史文件
    fn load_file(&self, ipc: &IpcService) -> Task<Message> {
        let Some(option) = self.selected.clone() else {
            return Task::none();
        };
        let Some(conn) = ipc.conn().cloned() else {
            return Task::done(Message::Logs(Msg::FileEntries(Err(IpcError::Disconnected(
                "未连接 fftpd，无法加载日志文件".to_owned(),
            )))));
        };
        Task::perform(
            async move {
                ipc_service::request::<LogEntries>(
                    conn,
                    Command::GetLogFileContent {
                        path: option.path,
                        count: FILE_LOAD_COUNT,
                    },
                )
                .await
                .map(|r| r.entries)
            },
            |r| Message::Logs(Msg::FileEntries(r)),
        )
    }

    /// 当前显示的条目（视图 + 过滤）
    fn displayed(&self) -> Vec<&LogEntry> {
        let entries: Vec<&LogEntry> = match self.viewing {
            Viewing::Live => self.live.iter().collect(),
            Viewing::File => self.file_entries.iter().collect(),
        };
        entries
            .into_iter()
            .filter(|entry| self.matches(entry))
            .collect()
    }

    /// 级别 + 文本搜索过滤
    fn matches(&self, entry: &LogEntry) -> bool {
        if !self.filter.allows(&entry.level) {
            return false;
        }
        let query = self.search.trim().to_lowercase();
        if query.is_empty() {
            return true;
        }
        entry.message.to_lowercase().contains(&query)
            || entry.source.to_lowercase().contains(&query)
            || entry.username.to_lowercase().contains(&query)
            || entry.action.to_lowercase().contains(&query)
            || entry.client_ip.contains(&query)
    }

    /// 当前显示内容的文本形式（复制/导出用）
    fn export_text(&self) -> String {
        self.displayed()
            .iter()
            .map(|entry| {
                format!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    entry.timestamp,
                    entry.level,
                    entry.source,
                    entry.username,
                    entry.client_ip,
                    entry.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 渲染页面
    #[must_use]
    pub fn view(&self) -> Element<'_, Message> {
        let toolbar = row![
            text("级别：").size(14),
            pick_list(LevelFilter::ALL, Some(self.filter), |filter| {
                Message::Logs(Msg::Filter(filter))
            })
            .placeholder("全部"),
            text_input("搜索消息/来源/用户/IP", &self.search)
                .on_input(|v| Message::Logs(Msg::Search(v)))
                .width(Length::Fixed(240.0)),
            checkbox("自动滚动", self.auto_scroll)
                .on_toggle(|v| Message::Logs(Msg::ToggleAutoScroll(v))),
            button(text("清空")).on_press(Message::Logs(Msg::Clear)),
            button(text("复制")).on_press(Message::Logs(Msg::Copy)),
            button(text("导出")).on_press(Message::Logs(Msg::Export)),
            text(format!("显示 {} 条", self.displayed().len())).size(13),
        ]
        .spacing(10);

        let file_bar = row![
            text("文件历史：").size(14),
            pick_list(
                self.files.as_slice(),
                self.selected.clone(),
                |option| Message::Logs(Msg::SelectFile(option)),
            )
            .placeholder("（无日志文件）"),
            button(text("加载")).on_press(Message::Logs(Msg::LoadFile)),
            button(text("返回实时")).on_press_maybe(
                (self.viewing == Viewing::File).then_some(Message::Logs(Msg::BackToLive))
            ),
            text(if self.viewing == Viewing::Live {
                "当前：实时订阅"
            } else {
                "当前：历史文件"
            })
            .size(13)
            .color(ACCENT_COLOR),
        ]
        .spacing(10);

        let mut page = column![text("日志").size(22), toolbar, file_bar]
            .spacing(10)
            .width(Length::Fill)
            .height(Length::Fill);
        if let Some(error) = &self.error {
            page = page.push(error_line(error));
        }
        if let Some(info) = &self.info {
            page = page.push(info_line(info));
        }

        let rows = column(self.displayed().into_iter().map(entry_row)).spacing(2);
        page = page.push(
            scrollable(rows)
                .id(scrollable::Id::new(LOG_SCROLL_ID))
                .height(Length::Fill),
        );
        page.into()
    }
}

/// 单条日志行：时间 / 级别（着色）/ 来源 / 用户@IP / 消息
fn entry_row(entry: &LogEntry) -> Element<'_, Message> {
    let mut line = row![
        text(entry.timestamp.clone())
            .size(12)
            .color(MUTED_COLOR)
            .width(Length::Fixed(170.0)),
        text(entry.level.clone())
            .size(12)
            .color(level_color(&entry.level))
            .width(Length::Fixed(60.0)),
        text(entry.source.clone())
            .size(12)
            .color(ACCENT_COLOR)
            .width(Length::Fixed(110.0)),
    ]
    .spacing(10);
    if !entry.username.is_empty() || !entry.client_ip.is_empty() {
        line = line.push(
            text(format!("{}@{}", entry.username, entry.client_ip))
                .size(12)
                .color(WARN_COLOR)
                .width(Length::Fixed(160.0)),
        );
    }
    line = line.push(text(entry.message.clone()).size(12));
    line.into()
}

/// 级别着色
fn level_color(level: &str) -> Color {
    if level.eq_ignore_ascii_case("error") {
        crate::tabs::ERROR_COLOR
    } else if level.eq_ignore_ascii_case("warn") {
        WARN_COLOR
    } else if level.eq_ignore_ascii_case("info") {
        INFO_COLOR
    } else {
        MUTED_COLOR
    }
}

/// 导出日志到临时目录文件
async fn export_entries(content: String) -> Result<String, String> {
    let name = format!(
        "fftp-gui-logs-{}.txt",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );
    let path = std::env::temp_dir().join(name);
    tokio::fs::write(&path, content)
        .await
        .map_err(|e| format!("导出失败：{e}"))?;
    Ok(path.display().to_string())
}

//! 文件日志页：文件操作审计日志浏览
//!
//! 经 `GetFileOpLogFiles` 列出审计日志文件、`GetFileOpLogContent` 加载内容，
//! 表格展示 时间/用户/IP/操作/文件/大小/协议/结果，支持按用户与操作过滤。

use fftp_ipc::protocol::{Command, FileOpLogEntry};
use iced::widget::{
    button, column, container, pick_list, row, scrollable, text, text_input, Widget,
};
use iced::{Element, Length, Task};

use crate::app::Message;
use crate::ipc_service::{self, FileOpEntries, IpcError, IpcService, LogFiles};
use crate::tabs::{error_line, relay_error, FileOption, ERROR_COLOR, INFO_COLOR, MUTED_COLOR};

/// 文件历史一次加载的条数
const FILE_LOAD_COUNT: u32 = 500;

/// 文件日志页消息
#[derive(Debug, Clone)]
pub enum Msg {
    /// 刷新文件列表（进入页面/点击刷新）
    Refresh,
    /// `GetFileOpLogFiles` 响应
    Files(Result<Vec<FileOption>, IpcError>),
    /// 选择文件
    SelectFile(FileOption),
    /// 加载选中文件
    Load,
    /// `GetFileOpLogContent` 响应
    Entries(Result<Vec<FileOpLogEntry>, IpcError>),
    /// 用户过滤
    UserFilter(String),
    /// 操作过滤
    OpFilter(String),
}

/// 文件日志页状态
#[derive(Debug, Default)]
pub struct FileLogsTab {
    /// 日志文件列表
    files: Vec<FileOption>,
    /// 当前选中文件
    selected: Option<FileOption>,
    /// 当前条目
    entries: Vec<FileOpLogEntry>,
    /// 用户过滤
    user_filter: String,
    /// 操作过滤
    op_filter: String,
    /// 加载进行中
    loading: bool,
    error: Option<String>,
}

impl FileLogsTab {
    /// 更新页面状态；`ipc` 用于发起请求
    pub fn update(&mut self, msg: Msg, ipc: &IpcService) -> Task<Message> {
        match msg {
            Msg::Refresh => self.refresh(ipc),
            Msg::Files(result) => {
                self.loading = false;
                match result {
                    Ok(files) => {
                        let selected = self
                            .selected
                            .clone()
                            .filter(|current| files.iter().any(|file| file.path == current.path))
                            .or_else(|| files.first().cloned());
                        let need_load = selected != self.selected;
                        self.selected = selected;
                        self.files = files;
                        self.error = None;
                        if need_load {
                            return self.load(ipc);
                        }
                        Task::none()
                    }
                    Err(e) => {
                        self.error = Some(e.message().to_owned());
                        relay_error(&e)
                    }
                }
            }
            Msg::SelectFile(option) => {
                self.selected = Some(option);
                self.load(ipc)
            }
            Msg::Load => self.load(ipc),
            Msg::Entries(result) => {
                self.loading = false;
                match result {
                    Ok(entries) => {
                        self.entries = entries;
                        self.error = None;
                    }
                    Err(e) => {
                        self.error = Some(e.message().to_owned());
                        return relay_error(&e);
                    }
                }
                Task::none()
            }
            Msg::UserFilter(v) => {
                self.user_filter = v;
                Task::none()
            }
            Msg::OpFilter(v) => {
                self.op_filter = v;
                Task::none()
            }
        }
    }

    /// 拉取文件列表并加载当前文件
    fn refresh(&mut self, ipc: &IpcService) -> Task<Message> {
        let Some(conn) = ipc.conn().cloned() else {
            self.error = Some("未连接 fftpd，无法读取文件日志".to_owned());
            return Task::none();
        };
        self.loading = true;
        Task::perform(
            async move {
                ipc_service::request::<LogFiles>(conn, Command::GetFileOpLogFiles)
                    .await
                    .map(|r| {
                        r.files
                            .iter()
                            .map(|info| FileOption {
                                name: info.name.clone(),
                                path: info.path.clone(),
                            })
                            .collect::<Vec<_>>()
                    })
            },
            |r| Message::FileLogs(Msg::Files(r)),
        )
    }

    /// 加载选中文件内容
    fn load(&mut self, ipc: &IpcService) -> Task<Message> {
        let Some(option) = self.selected.clone() else {
            return Task::none();
        };
        let Some(conn) = ipc.conn().cloned() else {
            self.error = Some("未连接 fftpd，无法读取文件日志".to_owned());
            return Task::none();
        };
        self.loading = true;
        Task::perform(
            async move {
                ipc_service::request::<FileOpEntries>(
                    conn,
                    Command::GetFileOpLogContent {
                        path: option.path,
                        count: FILE_LOAD_COUNT,
                    },
                )
                .await
                .map(|r| r.entries)
            },
            |r| Message::FileLogs(Msg::Entries(r)),
        )
    }

    /// 过滤后的条目
    fn displayed(&self) -> impl Iterator<Item = &FileOpLogEntry> {
        let user = self.user_filter.trim().to_lowercase();
        let op = self.op_filter.trim().to_lowercase();
        self.entries.iter().filter(move |entry| {
            let user_ok = user.is_empty() || entry.username.to_lowercase().contains(&user);
            let op_ok = op.is_empty() || entry.operation.to_lowercase().contains(&op);
            user_ok && op_ok
        })
    }

    /// 渲染页面
    #[must_use]
    pub fn view(&self, connected: bool) -> Element<'_, Message> {
        let toolbar = row![
            text("文件日志").size(22),
            pick_list(
                self.selected.clone(),
                self.files.as_slice(),
                ToString::to_string,
            )
            .on_select(|option| Message::FileLogs(Msg::SelectFile(option)))
            .placeholder("（无审计日志文件）")
            .width(Length::Fixed(220.0)),
            button(text("刷新")).on_press_maybe(
                (connected && !self.loading).then_some(Message::FileLogs(Msg::Refresh))
            ),
            button(text("加载")).on_press_maybe(
                (connected && !self.loading).then_some(Message::FileLogs(Msg::Load))
            ),
            text_input("按用户过滤", &self.user_filter)
                .on_input(|v| Message::FileLogs(Msg::UserFilter(v)))
                .width(Length::Fixed(150.0)),
            text_input("按操作过滤", &self.op_filter)
                .on_input(|v| Message::FileLogs(Msg::OpFilter(v)))
                .width(Length::Fixed(150.0)),
            text(format!("共 {} 条", self.displayed().count())).size(13),
        ]
        .spacing(10);

        let mut page = column![toolbar].spacing(10).width(Length::Fill).height(Length::Fill);
        if let Some(error) = &self.error {
            page = page.push(error_line(error));
        }
        page = page.push(self.table());
        page.boxed()
    }

    /// 表格（表头 + 行）
    fn table(&self) -> Element<'_, Message> {
        let header = row![
            text("时间").size(13).width(Length::Fixed(160.0)),
            text("用户").size(13).width(Length::Fixed(90.0)),
            text("IP").size(13).width(Length::Fixed(120.0)),
            text("操作").size(13).width(Length::Fixed(80.0)),
            text("文件").size(13).width(Length::Fill),
            text("大小").size(13).width(Length::Fixed(90.0)),
            text("协议").size(13).width(Length::Fixed(60.0)),
            text("结果").size(13).width(Length::Fixed(60.0)),
        ]
        .spacing(10);

        let rows = column(self.displayed().map(entry_row)).spacing(2);
        container(
            column![
                header,
                scrollable(rows).height(Length::Fill),
            ]
            .spacing(6),
        )
        .padding(12)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(container::rounded_box)
        .boxed()
    }
}

/// 单条审计日志行
fn entry_row(entry: &FileOpLogEntry) -> Element<'_, Message> {
    row![
        text(entry.timestamp.clone())
            .size(12)
            .color(MUTED_COLOR)
            .width(Length::Fixed(160.0)),
        text(entry.username.clone()).size(12).width(Length::Fixed(90.0)),
        text(entry.client_ip.clone()).size(12).width(Length::Fixed(120.0)),
        text(entry.operation.clone()).size(12).width(Length::Fixed(80.0)),
        text(entry.file_path.clone()).size(12).width(Length::Fill),
        text(format_size(entry.file_size))
            .size(12)
            .width(Length::Fixed(90.0)),
        text(entry.protocol.clone()).size(12).width(Length::Fixed(60.0)),
        text(if entry.success { "成功" } else { "失败" })
            .size(12)
            .color(if entry.success {
                INFO_COLOR
            } else {
                ERROR_COLOR
            })
            .width(Length::Fixed(60.0)),
    ]
    .spacing(10)
    .boxed()
}

/// 字节数的可读展示（整数运算，避免浮点精度告警）
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{}.{:02} GB", bytes / GB, (bytes % GB) * 100 / GB)
    } else if bytes >= MB {
        format!("{}.{:02} MB", bytes / MB, (bytes % MB) * 100 / MB)
    } else if bytes >= KB {
        format!("{}.{:02} KB", bytes / KB, (bytes % KB) * 100 / KB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_scales_units() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2.00 KB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.00 MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.00 GB");
    }
}

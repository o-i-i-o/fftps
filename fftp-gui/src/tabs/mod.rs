//! 各功能页
//!
//! 每个页面持有自己的状态与消息枚举，`update` 返回应用层 [`Task`]，
//! 与连接管理相关的副作用（断线上报等）统一经 [`relay_error`] 处理；
//! 提示行、表单行等共用排版辅助集中在本模块。

pub mod about;
pub mod file_logs;
pub mod logs;
pub mod security;
pub mod server;
pub mod service;
pub mod users;

use iced::widget::{row, text};
use iced::{Color, Element, Length, Task};

use crate::app::Message;
use crate::ipc_service::IpcError;

/// 错误提示色（`Color::from_rgb8` 非 const，直接构造）
pub const ERROR_COLOR: Color = Color {
    r: 248.0 / 255.0,
    g: 81.0 / 255.0,
    b: 73.0 / 255.0,
    a: 1.0,
};
/// 成功提示色
pub const INFO_COLOR: Color = Color {
    r: 46.0 / 255.0,
    g: 160.0 / 255.0,
    b: 67.0 / 255.0,
    a: 1.0,
};
/// 辅助文字色
pub const MUTED_COLOR: Color = Color {
    r: 140.0 / 255.0,
    g: 140.0 / 255.0,
    b: 140.0 / 255.0,
    a: 1.0,
};
/// 强调（链接/来源）色
pub const ACCENT_COLOR: Color = Color {
    r: 90.0 / 255.0,
    g: 140.0 / 255.0,
    b: 200.0 / 255.0,
    a: 1.0,
};
/// 警告色
pub const WARN_COLOR: Color = Color {
    r: 210.0 / 255.0,
    g: 153.0 / 255.0,
    b: 34.0 / 255.0,
    a: 1.0,
};

/// 日志文件下拉选项（[`fftp_ipc::protocol::LogFileInfo`] 未实现 `PartialEq`/`Display`，
/// 用本地展示类型）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOption {
    /// 文件名
    pub name: String,
    /// 完整路径
    pub path: String,
}

impl FileOption {
    /// 从协议文件信息转换
    #[must_use]
    pub fn from_info(info: &fftp_ipc::protocol::LogFileInfo) -> Self {
        Self {
            name: info.name.clone(),
            path: info.path.clone(),
        }
    }
}

impl std::fmt::Display for FileOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// 把协议文件列表转换为下拉选项
#[must_use]
pub fn file_options(files: &[fftp_ipc::protocol::LogFileInfo]) -> Vec<FileOption> {
    files.iter().map(FileOption::from_info).collect()
}

/// 请求失败时的共用处理：断线则上报应用层触发重连
pub fn relay_error(err: &IpcError) -> Task<Message> {
    if err.is_disconnected() {
        Task::done(Message::ConnectionLost(err.message().to_owned()))
    } else {
        Task::none()
    }
}

/// 错误提示行
pub fn error_line<'a>(msg: &str) -> Element<'a, Message> {
    text(msg.to_owned()).size(13).color(ERROR_COLOR).into()
}

/// 成功提示行
pub fn info_line<'a>(msg: &str) -> Element<'a, Message> {
    text(msg.to_owned()).size(13).color(INFO_COLOR).into()
}

/// “标签：控件”表单行
pub fn form_row<'a>(
    label: &'a str,
    control: impl Into<Element<'a, Message>>,
) -> iced::widget::Row<'a, Message> {
    row![text(label).size(13).width(Length::Fixed(150.0)), control.into()].spacing(8)
}

//! 关于页：项目、版本、通信端点与数据路径
//!
//! 服务端信息以 `GetStatus` 响应为准；未连接时回退到本地可推导的信息
//! （IPC 端点、本机配置/用户库路径）。

use iced::widget::{column, container, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::ipc_service::ServerStatus;
use crate::tabs::{form_row, MUTED_COLOR};

/// 渲染关于页
#[must_use]
pub fn view<'a>(status: Option<&ServerStatus>) -> Element<'a, Message> {
    let gui_version = env!("CARGO_PKG_VERSION").to_owned();
    let (daemon_version, endpoint, config_path, users_path) = match status {
        Some(status) => (
            status.version.clone(),
            status.endpoint.clone(),
            status.config_path.clone(),
            status.users_path.clone(),
        ),
        None => (
            "未知（未连接 fftpd）".to_owned(),
            fftp_ipc::transport::endpoint_display(),
            fftp_common::paths::config_path().display().to_string(),
            fftp_common::paths::users_path().display().to_string(),
        ),
    };

    let identity = container(
        column![
            text("fftps（f-ftp suite）").size(26),
            text("跨平台 FTP(FTPS)/SFTP 服务端套件").size(15),
        ]
        .spacing(6),
    )
    .padding(16)
    .width(Length::Fill)
    .style(container::rounded_box);

    let detail = container(
        column![
            text("版本与运行信息").size(16),
            form_row("管理程序（ftp-gui）", text(gui_version).size(13)),
            form_row("服务端（fftpd）", text(daemon_version).size(13)),
            form_row("IPC 端点", text(endpoint).size(13)),
            form_row("配置文件", text(config_path).size(13)),
            form_row("用户库", text(users_path).size(13)),
        ]
        .spacing(8),
    )
    .padding(16)
    .width(Length::Fill)
    .style(container::rounded_box);

    let note = text(
        "前后端经 fftp-ipc（JSON 帧协议）本地通信：Linux 为 Unix socket（0600），\
         Windows 为命名管道（本地会话 ACL）；fftpd 是配置与用户数据的唯一写入者，\
         管理程序经 IPC 读写。",
    )
    .size(12)
    .color(MUTED_COLOR);

    container(
        column![identity, detail, note]
            .spacing(12)
            .width(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

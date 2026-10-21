//! ftp-gui：fftps 前端管理程序（iced 跨平台 GUI）
//!
//! 与 fftpd 经 fftp-ipc 本地通信，提供服务器/用户/安全/日志/文件日志/
//! 服务/关于等管理页面；断线自动重连，写操作在断线时禁用。

mod app;
mod ipc_service;
mod tabs;

use iced::Size;

fn main() -> iced::Result {
    iced::application("fftps 管理程序（f-ftp suite）", app::update, app::view)
        .subscription(app::subscription)
        .window_size(Size::new(1100.0, 760.0))
        .run_with(app::App::init)
}

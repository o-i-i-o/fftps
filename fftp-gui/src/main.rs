//! fftp-gui：fftps 前端管理程序（iced 跨平台 GUI）
//!
//! 与 fftpd 经 fftp-ipc 本地通信，提供服务器/用户/安全/日志/文件日志/
//! 服务/关于等管理页面；断线自动重连，写操作在断线时禁用。

mod app;
mod ipc_service;
mod tabs;

use iced::{Font, Size};

/// 内嵌中文字体（文泉驿微米黑）：避免系统缺字导致中文显示为方框
pub const CJK_FONT_BYTES: &[u8] = include_bytes!("../../fonts/WenQuanYiMicroHei.ttf");

/// 内嵌字体的 family 名（须与 TTF name 表一致，否则字体匹配不到）
pub const CJK_FONT_NAME: &str = "WenQuanYi Micro Hei";

fn main() -> iced::Result {
    // 0.14 起 `application` 首参为 boot 函数（产生初始状态），标题/全局字体改经
    // `.title()`/`.font()` 设置；0.15 起 `Font::new` 取代 `Font::with_name`
    iced::application(app::App::init, app::update, app::view)
        .title("fftps 管理程序（f-ftp suite）")
        .subscription(app::subscription)
        .font(Font::new(CJK_FONT_NAME))
        .window_size(Size::new(1100.0, 760.0))
        .run()
}

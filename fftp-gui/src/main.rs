//! fftp-gui：fftps 前端管理程序（Slint 跨平台 GUI）
//!
//! 与 fftpd 经 fftp-ipc 本地通信，提供服务器/用户/安全/日志/文件日志/
//! 服务/关于等管理页面；断线自动重连，写操作在断线时禁用。
//! UI 为 ui/*.slint 声明式描述（编译期生成绑定），Rust 侧负责
//! IPC 请求、连接监督与各页面状态同步。
//!
//! 默认使用 winit + femtovg 后端（零系统 GUI 依赖）；面向
//! UOS/Deepin/麒麟等 Qt5 桌面可用 `--features qt` 启用 Qt 后端，
//! 运行时以 `SLINT_BACKEND=qt` 选择。

mod app;
mod ipc_service;
mod tabs;

use slint::ComponentHandle;

slint::include_modules!();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 中文渲染依赖系统 CJK 字体（UOS/Deepin/麒麟/Windows 均自带）
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let core = std::sync::Arc::new(std::sync::Mutex::new(app::Core::new(rt.handle().clone())));

    let ui = AppWindow::new()?;
    app::wire(&ui, &core);
    app::start_connect(&ui.as_weak(), &core);
    ui.run()?;

    rt.shutdown_timeout(std::time::Duration::from_millis(200));
    Ok(())
}

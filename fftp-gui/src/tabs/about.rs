//! 关于页：项目、版本、通信端点与数据路径
//!
//! 服务端信息以 `GetStatus` 响应为准（应用壳在连接成功与轮询时刷新）；
//! 未连接时回退到本地可推导的信息（IPC 端点、本机配置/用户库路径）。

use slint::ComponentHandle;

use crate::ipc_service::ServerStatus;
use crate::{AboutState, AppWindow};

/// 以 `GetStatus` 响应刷新服务端信息
pub fn set_from_status(ui: &AppWindow, status: &ServerStatus) {
    let state = ui.global::<AboutState>();
    state.set_daemon_version(status.version.clone().into());
    state.set_endpoint(status.endpoint.clone().into());
    state.set_config_path(status.config_path.clone().into());
    state.set_users_path(status.users_path.clone().into());
}

/// 未连接时的本地回退信息（GUI 版本、IPC 端点与数据路径）
pub fn set_fallback(ui: &AppWindow) {
    let state = ui.global::<AboutState>();
    state.set_gui_version(env!("CARGO_PKG_VERSION").into());
    state.set_daemon_version("未知（未连接 fftpd）".into());
    state.set_endpoint(fftp_ipc::transport::endpoint_display().into());
    state.set_config_path(fftp_common::paths::config_path().display().to_string().into());
    state.set_users_path(fftp_common::paths::users_path().display().to_string().into());
}

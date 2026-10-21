//! Windows 服务入口（windows-service 0.8，移植 wftpd-windows 的 service_main.rs）
//!
//! 主入口切换：`--service` 参数或 SCM 自动检测到服务方式启动时进入服务调度器，
//! 否则返回 `false` 由调用方回退前台运行（前台行为与 Linux 完全一致）。
//! 服务控制处理：`SERVICE_CONTROL_STOP`/`SHUTDOWN` 触发守护逻辑的优雅关停，
//! `Pause`/`Continue`/`Interrogate` 应答无错，其余控制码返回未实现。

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

/// Windows 服务名（`sc create/delete`、服务管理器与服务调度器共用）
pub const SERVICE_NAME: &str = "fftpd";

define_windows_service!(ffi_service_main, service_main);

/// 服务主函数（由服务调度器拉起）
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("fftpd 服务运行失败: {e:#}");
    }
}

/// 尝试以 Windows 服务方式运行（主入口切换）
///
/// - 由 SCM 启动（或显式 `--service`）时进入服务调度器，服务停止后返回 `true`；
/// - 普通前台启动（未由 SCM 调度）返回 `false`，调用方回退前台运行。
///
/// # Errors
/// 显式 `--service` 但服务调度器启动失败时返回错误
pub fn try_run_as_service() -> Result<bool> {
    let explicit = std::env::args().any(|arg| arg == "--service");
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(true),
        // 未由 SCM 调度（前台启动）：回退前台运行
        Err(e) if !explicit => {
            eprintln!("服务调度器未接管（回退前台运行）: {e:?}");
            Ok(false)
        }
        Err(e) => Err(anyhow::anyhow!("启动 Windows 服务调度器失败: {e:?}")),
    }
}

/// 服务生命周期：注册控制处理器 → 上报运行中 → 运行守护逻辑 → 上报已停止
fn run_service() -> Result<()> {
    // SCM 停止信号 → 守护逻辑的关停观察通道
    let (stop_tx, stop_rx) = watch::channel(false);
    let stop_tx = Arc::new(stop_tx);

    let handler_tx = Arc::clone(&stop_tx);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                tracing::info!("收到服务停止信号，正在优雅关停...");
                let _ = handler_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Pause | ServiceControl::Continue | ServiceControl::Interrogate => {
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status_handle.set_service_status(service_status(ServiceState::Running))?;

    // 服务主逻辑与前台入口共用（阻塞至收到停止信号）
    let result = crate::run_daemon_blocking(Some(stop_rx));

    status_handle.set_service_status(service_status(ServiceState::Stopped))?;
    result
}

/// 构造服务状态上报（OWN_PROCESS；运行中接受 STOP/SHUTDOWN 控制）
fn service_status(state: ServiceState) -> ServiceStatus {
    let controls_accepted = if state == ServiceState::Running {
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
    } else {
        ServiceControlAccept::empty()
    };
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

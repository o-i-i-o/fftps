//! 服务页：FTP/SFTP 生命周期管理 + 系统服务安装/自启 + 日志设置
//!
//! 启停/重启经 `StartService`/`StopService`/`RestartService`（目标：全部/FTP/SFTP），
//! 状态显示复用 `GetStatus`（应用壳 5 秒轮询 + 操作后立即刷新）；
//! 系统服务管理（安装/卸载/开机自启）走平台分支进程调用
//! （Linux `systemctl --user`，Windows `sc.exe`），在 `spawn_blocking`
//! 中执行并把 stderr 显示在页面；日志设置经 `SaveLogConfig` 提交
//! （`log_dir`/`log_level`/`max_log_size`/`max_log_files`/`enable_gui_logging`）。

use fftp_common::config::{Config, LoggingConfig};
use fftp_ipc::protocol::{Command, ServiceTarget};
use slint::ComponentHandle;

use crate::app::{dispatch, relay, request_status, wire0, wire1, wire2, SharedCore, UiWeak};
use crate::ipc_service::{self, IpcConn, IpcError, ServerStatus};
use crate::tabs::{parse_num, row_index, ui_index};
use crate::{AppWindow, ServiceState};

/// 系统服务管理动作（安装/卸载/开机自启，平台分支实现）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysAction {
    /// 安装服务（注册 + 启动 + 开机自启）
    Install,
    /// 卸载服务（停止 + 删除/禁用）
    Uninstall,
    /// 开机自启：开
    AutostartOn,
    /// 开机自启：关
    AutostartOff,
}

impl SysAction {
    /// 成功提示
    #[must_use]
    pub fn ok_text(self) -> &'static str {
        match self {
            SysAction::Install => "服务已安装并启动",
            SysAction::Uninstall => "服务已卸载",
            SysAction::AutostartOn => "已开启开机自启",
            SysAction::AutostartOff => "已关闭开机自启",
        }
    }
}

/// 日志级别下拉选项
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogLevel {
    /// `error`
    Error,
    /// `warn`
    Warn,
    /// `info`
    #[default]
    Info,
    /// `debug`
    Debug,
    /// `trace`
    Trace,
}

impl LogLevel {
    /// 下拉可选项（与 `ui/service.slint` 的 `ComboBox` 顺序一致）
    pub const ALL: [Self; 5] = [
        Self::Error,
        Self::Warn,
        Self::Info,
        Self::Debug,
        Self::Trace,
    ];

    /// 配置字符串
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }

    /// 从配置字符串解析（未知值回退 `info`）
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "error" => LogLevel::Error,
            "warn" | "warning" => LogLevel::Warn,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => LogLevel::Info,
        }
    }
}

/// 平台分支提示文案（系统服务卡片）
#[must_use]
pub fn platform_hint() -> &'static str {
    if cfg!(windows) {
        "Windows：sc.exe 管理 fftpd 服务（安装 = 注册 + 启动 + 开机自启；需要管理员权限）"
    } else {
        "Linux：systemctl --user 管理 fftpd 用户服务（安装 = enable --now，自启 = enable/disable）"
    }
}

/// 回调接线
pub fn wire(weak: &UiWeak, core: &SharedCore) {
    let ui = weak.upgrade().unwrap();
    let state = ui.global::<ServiceState>();
    state.on_op(wire2(weak, core, on_op));
    state.on_sys_op(wire1(weak, core, on_sys_op));
    state.on_refresh_status(wire0(weak, core, request_status));
    state.on_reload_log(wire0(weak, core, reload_log));
    state.on_save_log(wire0(weak, core, save_log));
}

/// `GetStatus` 响应：刷新运行状态卡
pub fn set_status(ui: &AppWindow, status: &ServerStatus) {
    let state = ui.global::<ServiceState>();
    state.set_have_status(true);
    state.set_ftp_running(status.ftp_running);
    state.set_sftp_running(status.sftp_running);
    state.set_version(status.version.clone().into());
}

/// 下拉索引 → 服务目标（与 ui/service.slint 的按钮顺序一致）
fn target_from_idx(idx: i32) -> ServiceTarget {
    match idx {
        1 => ServiceTarget::Ftp,
        2 => ServiceTarget::Sftp,
        _ => ServiceTarget::All,
    }
}

/// 下拉索引 → 系统服务动作（0 安装 / 1 卸载 / 2 自启开 / 3 自启关）
fn sys_action_from_idx(idx: i32) -> SysAction {
    match idx {
        1 => SysAction::Uninstall,
        2 => SysAction::AutostartOn,
        3 => SysAction::AutostartOff,
        _ => SysAction::Install,
    }
}

/// 下拉索引 → 日志级别
fn level_from_idx(idx: i32) -> LogLevel {
    LogLevel::ALL.get(row_index(idx)).copied().unwrap_or_default()
}

/// 日志级别 → 下拉索引
fn level_idx(level: LogLevel) -> i32 {
    // `parse` 只返回 `ALL` 成员，2（Info）仅为兜底
    LogLevel::ALL
        .iter()
        .position(|&l| l == level)
        .map_or(2, ui_index)
}

/// 启动/停止/重启服务（which：0 全部 / 1 FTP / 2 SFTP；action：0 启动 / 1 停止 / 2 重启）
fn on_op(ui: &AppWindow, core: &SharedCore, which: i32, action: i32) {
    let state = ui.global::<ServiceState>();
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        state.set_error("未连接 fftpd，无法操作服务".into());
        return;
    };
    let target = target_from_idx(which);
    let cmd = match action {
        0 => Command::StartService { which: target },
        1 => Command::StopService { which: target },
        _ => Command::RestartService { which: target },
    };
    let ok_text = match action {
        0 => "服务已启动",
        1 => "服务已停止",
        _ => "服务已重启",
    };
    state.set_busy(true);
    state.set_error("".into());
    state.set_info("".into());
    dispatch(
        ui.as_weak(),
        core,
        async move { ipc_service::request_ok(conn, cmd).await },
        move |ui, core, result| {
            let state = ui.global::<ServiceState>();
            state.set_busy(false);
            match result {
                Ok(()) => {
                    state.set_error("".into());
                    state.set_info(ok_text.into());
                    request_status(ui, core);
                }
                Err(e) => {
                    state.set_error(e.message().into());
                    relay(ui, core, &e);
                }
            }
        },
    );
}

/// 系统服务管理（安装/卸载/开机自启；不依赖 IPC 连接，busy 属性做并发守卫）
fn on_sys_op(ui: &AppWindow, core: &SharedCore, action: i32) {
    let state = ui.global::<ServiceState>();
    if state.get_sys_busy() {
        return;
    }
    let action = sys_action_from_idx(action);
    let ok_text = action.ok_text();
    state.set_sys_busy(true);
    state.set_error("".into());
    state.set_info("".into());
    dispatch(ui.as_weak(), core, run_sys_action(action), move |ui, _core, result| {
        let state = ui.global::<ServiceState>();
        state.set_sys_busy(false);
        match result {
            Ok(out) => {
                state.set_error("".into());
                state.set_info(if out.is_empty() {
                    ok_text.into()
                } else {
                    format!("{ok_text}：{out}").into()
                });
            }
            Err(e) => state.set_error(e.into()),
        }
    });
}

/// 重新载入日志设置（`GetConfig` → `[logging]` 段）
pub fn reload_log(ui: &AppWindow, core: &SharedCore) {
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        ui.global::<ServiceState>()
            .set_error("未连接 fftpd，无法载入日志设置".into());
        return;
    };
    ui.global::<ServiceState>().set_log_saving(true);
    dispatch(ui.as_weak(), core, load_logging(conn), on_log_loaded);
}

/// 载入日志设置（`GetConfig` → `[logging]` 段）
async fn load_logging(conn: IpcConn) -> Result<LoggingConfig, IpcError> {
    let content = ipc_service::request::<crate::ipc_service::TextContent>(conn, Command::GetConfig).await?;
    toml::from_str::<Config>(&content.content)
        .map(|config| config.logging)
        .map_err(|e| IpcError::BadResponse(format!("配置解析失败：{e}")))
}

/// `GetConfig` 响应：写入页面表单
fn on_log_loaded(ui: &AppWindow, core: &SharedCore, result: Result<LoggingConfig, IpcError>) {
    let state = ui.global::<ServiceState>();
    state.set_log_saving(false);
    match result {
        Ok(cfg) => {
            state.set_log_dir(cfg.log_dir.into());
            state.set_log_level_idx(level_idx(LogLevel::parse(&cfg.log_level)));
            state.set_max_size(cfg.max_log_size.to_string().into());
            state.set_max_files(cfg.max_log_files.to_string().into());
            state.set_gui_logging(cfg.enable_gui_logging);
            state.set_error("".into());
        }
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 保存日志设置（解析数值后走 `SaveLogConfig`）
fn save_log(ui: &AppWindow, core: &SharedCore) {
    let state = ui.global::<ServiceState>();
    let max_log_size = match parse_num::<u64>(&state.get_max_size(), "单文件大小上限") {
        Ok(value) => value,
        Err(message) => {
            state.set_error(message.into());
            return;
        }
    };
    let max_log_files = match parse_num::<u32>(&state.get_max_files(), "轮转保留文件数") {
        Ok(value) => value,
        Err(message) => {
            state.set_error(message.into());
            return;
        }
    };
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        state.set_error("未连接 fftpd，无法保存".into());
        return;
    };
    let log_dir = state.get_log_dir().trim().to_owned();
    let log_level = level_from_idx(state.get_log_level_idx()).as_str().to_owned();
    let enable_gui_logging = state.get_gui_logging();
    state.set_log_saving(true);
    state.set_error("".into());
    state.set_info("".into());
    dispatch(
        ui.as_weak(),
        core,
        async move {
            ipc_service::request_ok(
                conn,
                Command::SaveLogConfig {
                    log_dir,
                    log_level,
                    max_log_size,
                    max_log_files,
                    enable_gui_logging,
                },
            )
            .await
        },
        on_log_saved,
    );
}

/// `SaveLogConfig` 响应
fn on_log_saved(ui: &AppWindow, core: &SharedCore, result: Result<(), IpcError>) {
    let state = ui.global::<ServiceState>();
    state.set_log_saving(false);
    match result {
        Ok(()) => {
            state.set_error("".into());
            state.set_info("日志设置已保存".into());
        }
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 执行系统服务管理命令（阻塞进程调用经 `spawn_blocking` 挪出 UI 线程）
async fn run_sys_action(action: SysAction) -> Result<String, String> {
    tokio::task::spawn_blocking(move || sys_command(action))
        .await
        .map_err(|e| format!("任务执行失败：{e}"))?
}

/// 平台分支：Linux 用 `systemctl --user` 管理 fftpd 用户服务
#[cfg(not(windows))]
fn sys_command(action: SysAction) -> Result<String, String> {
    let args: &[&str] = match action {
        SysAction::Install => &["--user", "enable", "--now", "fftpd"],
        SysAction::Uninstall => &["--user", "disable", "--now", "fftpd"],
        SysAction::AutostartOn => &["--user", "enable", "fftpd"],
        SysAction::AutostartOff => &["--user", "disable", "fftpd"],
    };
    run_command("systemctl", args)
}

/// 平台分支：Windows 用 `sc.exe` 管理 fftpd 服务
#[cfg(windows)]
fn sys_command(action: SysAction) -> Result<String, String> {
    let bin_path = format!("\"{}\" --service", fftpd_exe_path()?.display());
    match action {
        SysAction::Install => {
            // 注册（start= auto 开机自启）后启动；失败信息（stderr）原样带回页面
            run_command(
                "sc.exe",
                &["create", "fftpd", "binPath=", &bin_path, "DisplayName=", "fftps FTP/SFTP Server", "start=", "auto"],
            )?;
            run_command("sc.exe", &["start", "fftpd"])
        }
        SysAction::Uninstall => {
            let _ = run_command("sc.exe", &["stop", "fftpd"]); // 未运行时忽略
            run_command("sc.exe", &["delete", "fftpd"])
        }
        SysAction::AutostartOn => run_command("sc.exe", &["config", "fftpd", "start=", "auto"]),
        SysAction::AutostartOff => run_command("sc.exe", &["config", "fftpd", "start=", "demand"]),
    }
}

/// 服务端二进制位置：与 fftp-gui 同目录的 fftpd.exe
#[cfg(windows)]
fn fftpd_exe_path() -> Result<std::path::PathBuf, String> {
    let dir = std::env::current_exe()
        .map_err(|e| format!("无法定位程序目录：{e}"))?
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "无法定位程序目录".to_owned())?;
    Ok(dir.join("fftpd.exe"))
}

/// 执行命令并收集输出；失败时把 stderr（无则 stdout/退出码）带回页面展示
fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("无法执行 {program}：{e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim().to_owned()
        } else {
            stderr.trim().to_owned()
        };
        Err(if detail.is_empty() {
            format!("{program} 执行失败（退出码 {:?}）", output.status.code())
        } else {
            format!("{program} 执行失败：{detail}")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_roundtrips_and_falls_back() {
        for level in LogLevel::ALL {
            assert_eq!(LogLevel::parse(level.as_str()), level);
        }
        assert_eq!(LogLevel::parse("WARNING"), LogLevel::Warn);
        assert_eq!(LogLevel::parse("nonsense"), LogLevel::Info);
    }
}

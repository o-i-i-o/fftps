//! 服务页：FTP/SFTP 生命周期管理 + 系统服务安装/自启 + 日志设置
//!
//! 启停/重启经 `StartService`/`StopService`/`RestartService`（目标：全部/FTP/SFTP），
//! 状态显示复用 `GetStatus`（应用壳 5 秒轮询 + 操作后立即刷新）；
//! 系统服务管理（安装/卸载/开机自启）走平台分支进程调用
//! （Linux `systemctl --user`，Windows `sc.exe`），失败把 stderr 显示在页面；
//! 日志设置经 `SaveLogConfig` 提交（`log_dir`/`log_level`/`max_log_size`/
//! `max_log_files`/`enable_gui_logging`）。

use fftp_common::config::{Config, LoggingConfig};
use fftp_ipc::protocol::{Command, ServiceTarget};
use iced::widget::{button, checkbox, column, container, pick_list, row, text, text_input};
use iced::{Element, Length, Task};

use crate::app::Message;
use crate::ipc_service::{self, IpcConn, IpcError, IpcService, ServerStatus, TextContent};
use crate::tabs::server;
use crate::tabs::{error_line, form_row, info_line, relay_error, ERROR_COLOR, INFO_COLOR};

/// 服务动作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 启动
    Start,
    /// 停止
    Stop,
    /// 重启
    Restart,
}

impl Action {
    /// 全部动作
    const ALL: [Self; 3] = [Action::Start, Action::Stop, Action::Restart];

    /// 按钮文案
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Action::Start => "启动",
            Action::Stop => "停止",
            Action::Restart => "重启",
        }
    }

    /// 成功提示
    #[must_use]
    pub fn ok_text(self) -> &'static str {
        match self {
            Action::Start => "服务已启动",
            Action::Stop => "服务已停止",
            Action::Restart => "服务已重启",
        }
    }
}

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
    /// 全部动作
    const ALL: [Self; 4] = [
        SysAction::Install,
        SysAction::Uninstall,
        SysAction::AutostartOn,
        SysAction::AutostartOff,
    ];

    /// 按钮文案
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SysAction::Install => "安装服务",
            SysAction::Uninstall => "卸载服务",
            SysAction::AutostartOn => "开机自启：开",
            SysAction::AutostartOff => "开机自启：关",
        }
    }

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
    /// 下拉可选项
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

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 日志设置表单（数值以文本缓冲编辑）
#[derive(Debug, Clone, Default)]
pub struct LogForm {
    /// 日志目录（空 = 默认目录）
    pub log_dir: String,
    /// 日志级别
    pub log_level: LogLevel,
    /// 单文件大小上限（字节）
    pub max_log_size: String,
    /// 轮转保留文件数
    pub max_log_files: String,
    /// 允许日志推送给前端
    pub enable_gui_logging: bool,
}

impl LogForm {
    /// 从 `[logging]` 段填充
    #[must_use]
    pub fn from_logging(cfg: &LoggingConfig) -> Self {
        Self {
            log_dir: cfg.log_dir.clone(),
            log_level: LogLevel::parse(&cfg.log_level),
            max_log_size: cfg.max_log_size.to_string(),
            max_log_files: cfg.max_log_files.to_string(),
            enable_gui_logging: cfg.enable_gui_logging,
        }
    }
}

/// 日志设置字段变更
#[derive(Debug, Clone)]
pub enum LogField {
    /// 日志目录
    Dir(String),
    /// 日志级别
    Level(LogLevel),
    /// 单文件大小上限（字节）
    MaxSize(String),
    /// 轮转保留文件数
    MaxFiles(String),
    /// 允许日志推送
    GuiLogging(bool),
}

/// 服务页消息
#[derive(Debug, Clone)]
pub enum Msg {
    /// 服务操作
    Op(Action, ServiceTarget),
    /// 操作完成（附成功提示）
    OpDone(Result<(), IpcError>, &'static str),
    /// 系统服务管理（安装/卸载/开机自启）
    SysOp(SysAction),
    /// 系统服务管理命令完成（命令输出或 stderr 错误）
    SysDone(Result<String, String>, &'static str),
    /// 刷新运行状态（`GetStatus`）
    RefreshStatus,
    /// 重新载入日志设置
    Reload,
    /// `GetConfig` 响应（解析后的日志设置）
    LogLoaded(Result<LoggingConfig, IpcError>),
    /// 日志设置字段
    LogField(LogField),
    /// 保存日志设置
    SaveLog,
    /// `SaveLogConfig` 响应
    LogSaved(Result<(), IpcError>),
}

/// 服务页状态
#[derive(Debug, Default)]
pub struct ServiceTab {
    /// 日志设置表单
    log: LogForm,
    /// 服务操作进行中
    busy: bool,
    /// 系统服务管理命令进行中
    sys_busy: bool,
    /// 日志设置保存进行中
    log_saving: bool,
    error: Option<String>,
    info: Option<String>,
}

impl ServiceTab {
    /// 更新页面状态；`ipc` 用于发起请求
    pub fn update(&mut self, msg: Msg, ipc: &IpcService) -> Task<Message> {
        match msg {
            Msg::Op(action, which) => {
                let Some(conn) = ipc.conn().cloned() else {
                    self.error = Some("未连接 fftpd，无法操作服务".to_owned());
                    return Task::none();
                };
                self.busy = true;
                self.error = None;
                self.info = None;
                let cmd = match action {
                    Action::Start => Command::StartService { which },
                    Action::Stop => Command::StopService { which },
                    Action::Restart => Command::RestartService { which },
                };
                let ok_text = action.ok_text();
                Task::perform(
                    async move { ipc_service::request_ok(conn, cmd).await },
                    move |r| Message::Service(Msg::OpDone(r, ok_text)),
                )
            }
            Msg::OpDone(result, ok_text) => {
                self.busy = false;
                match result {
                    Ok(()) => {
                        self.error = None;
                        self.info = Some(ok_text.to_owned());
                        refresh_status(ipc)
                    }
                    Err(e) => {
                        self.error = Some(e.message().to_owned());
                        relay_error(&e)
                    }
                }
            }
            Msg::SysOp(action) => self.sys_op(action),
            Msg::SysDone(result, ok_text) => {
                self.sys_done(result, ok_text);
                Task::none()
            }
            Msg::RefreshStatus => refresh_status(ipc),
            Msg::Reload => {
                let Some(conn) = ipc.conn().cloned() else {
                    self.error = Some("未连接 fftpd，无法载入日志设置".to_owned());
                    return Task::none();
                };
                self.log_saving = true;
                Task::perform(load_logging(conn), |r| Message::Service(Msg::LogLoaded(r)))
            }
            Msg::LogLoaded(result) => {
                self.log_saving = false;
                match result {
                    Ok(cfg) => {
                        self.log = LogForm::from_logging(&cfg);
                        self.error = None;
                        Task::none()
                    }
                    Err(e) => {
                        self.error = Some(e.message().to_owned());
                        relay_error(&e)
                    }
                }
            }
            Msg::LogField(field) => {
                match field {
                    LogField::Dir(v) => self.log.log_dir = v,
                    LogField::Level(v) => self.log.log_level = v,
                    LogField::MaxSize(v) => self.log.max_log_size = v,
                    LogField::MaxFiles(v) => self.log.max_log_files = v,
                    LogField::GuiLogging(v) => self.log.enable_gui_logging = v,
                }
                self.info = None;
                Task::none()
            }
            Msg::SaveLog => self.save_log(ipc),
            Msg::LogSaved(result) => {
                self.log_saving = false;
                match result {
                    Ok(()) => {
                        self.error = None;
                        self.info = Some("日志设置已保存".to_owned());
                        Task::none()
                    }
                    Err(e) => {
                        self.error = Some(e.message().to_owned());
                        relay_error(&e)
                    }
                }
            }
        }
    }

    /// 发起系统服务管理命令（平台分支，阻塞进程调用挪出 UI 线程）
    fn sys_op(&mut self, action: SysAction) -> Task<Message> {
        if self.sys_busy {
            return Task::none();
        }
        self.sys_busy = true;
        self.error = None;
        self.info = None;
        let ok_text = action.ok_text();
        Task::perform(run_sys_action(action), move |r| {
            Message::Service(Msg::SysDone(r, ok_text))
        })
    }

    /// 系统服务管理命令完成：成功附带命令输出，失败把 stderr 显示在页面
    fn sys_done(&mut self, result: Result<String, String>, ok_text: &'static str) {
        self.sys_busy = false;
        match result {
            Ok(out) => {
                self.error = None;
                self.info = Some(if out.is_empty() {
                    ok_text.to_owned()
                } else {
                    format!("{ok_text}：{out}")
                });
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// 保存日志设置（解析数值后走 `SaveLogConfig`）
    fn save_log(&mut self, ipc: &IpcService) -> Task<Message> {
        let Ok(max_log_size) = self.log.max_log_size.trim().parse::<u64>() else {
            self.error = Some(format!(
                "单文件大小上限不是合法数字：{}",
                self.log.max_log_size
            ));
            return Task::none();
        };
        let Ok(max_log_files) = self.log.max_log_files.trim().parse::<u32>() else {
            self.error = Some(format!(
                "轮转保留文件数不是合法数字：{}",
                self.log.max_log_files
            ));
            return Task::none();
        };
        let Some(conn) = ipc.conn().cloned() else {
            self.error = Some("未连接 fftpd，无法保存".to_owned());
            return Task::none();
        };
        self.log_saving = true;
        self.error = None;
        self.info = None;
        let (log_dir, log_level) = (
            self.log.log_dir.trim().to_owned(),
            self.log.log_level.as_str().to_owned(),
        );
        let enable_gui_logging = self.log.enable_gui_logging;
        Task::perform(
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
            |r| Message::Service(Msg::LogSaved(r)),
        )
    }

    /// 渲染页面
    #[must_use]
    pub fn view<'a>(
        &'a self,
        connected: bool,
        status: Option<&'a ServerStatus>,
    ) -> Element<'a, Message> {
        let mut toolbar = row![
            text("服务").size(22),
            button(text("刷新状态")).on_press_maybe(
                (connected && !self.busy).then_some(Message::Service(Msg::RefreshStatus))
            ),
        ]
        .spacing(10);
        if let Some(info) = &self.info {
            toolbar = toolbar.push(info_line(info));
        }

        let mut page = column![
            toolbar,
            container(
                column![text("运行状态").size(16), status_rows(status)].spacing(10),
            )
            .padding(16)
            .width(Length::Fill)
            .style(container::rounded_box),
            self.control_card(connected),
            self.sys_card(),
            self.log_card(connected),
        ]
        .spacing(12)
        .width(Length::Fill)
        .height(Length::Fill);
        if let Some(error) = &self.error {
            page = page.push(error_line(error));
        }
        page.into()
    }

    /// 启停控制卡片
    fn control_card(&self, connected: bool) -> Element<'_, Message> {
        let targets: [(ServiceTarget, &str); 3] = [
            (ServiceTarget::All, "全部服务"),
            (ServiceTarget::Ftp, "FTP 服务"),
            (ServiceTarget::Sftp, "SFTP 服务"),
        ];
        let rows = column(targets.map(|(which, label)| {
            Element::from(row![
                text(label).size(14).width(Length::Fixed(120.0)),
                row(Action::ALL.map(|action| {
                    Element::from(button(text(action.label())).on_press_maybe(
                        (connected && !self.busy)
                            .then_some(Message::Service(Msg::Op(action, which))),
                    ))
                }))
                .spacing(8),
            ])
        }))
        .spacing(10);

        container(column![text("生命周期管理").size(16), rows].spacing(10))
            .padding(16)
            .width(Length::Fill)
            .style(container::rounded_box)
            .into()
    }

    /// 系统服务卡片：安装/卸载服务 + 开机自启开关（平台分支，不依赖 IPC 连接）
    fn sys_card(&self) -> Element<'_, Message> {
        let hint = if cfg!(windows) {
            "Windows：sc.exe 管理 fftpd 服务（安装 = 注册 + 启动 + 开机自启；需要管理员权限）"
        } else {
            "Linux：systemctl --user 管理 fftpd 用户服务（安装 = enable --now，自启 = enable/disable）"
        };
        let rows = row(SysAction::ALL.map(|action| {
            Element::from(button(text(action.label())).on_press_maybe(
                (!self.sys_busy).then_some(Message::Service(Msg::SysOp(action))),
            ))
        }))
        .spacing(8);

        container(
            column![
                text("系统服务（开机自启）").size(16),
                text(hint).size(12),
                rows,
            ]
            .spacing(10),
        )
        .padding(16)
        .width(Length::Fill)
        .style(container::rounded_box)
        .into()
    }

    /// 日志设置卡片
    fn log_card(&self, connected: bool) -> Element<'_, Message> {
        let mut fields = column![
            form_row(
                "日志目录 log_dir",
                text_input("（空 = 默认目录）", &self.log.log_dir)
                    .on_input(|v| Message::Service(Msg::LogField(LogField::Dir(v))))
                    .width(Length::Fixed(360.0)),
            ),
            form_row(
                "日志级别",
                pick_list(
                    LogLevel::ALL,
                    Some(self.log.log_level),
                    |level| Message::Service(Msg::LogField(LogField::Level(level))),
                )
                .width(Length::Fixed(160.0)),
            ),
            form_row(
                "单文件大小上限（字节）",
                text_input("10485760", &self.log.max_log_size)
                    .on_input(|v| Message::Service(Msg::LogField(LogField::MaxSize(v))))
                    .width(Length::Fixed(160.0)),
            ),
            form_row(
                "轮转保留文件数",
                text_input("10", &self.log.max_log_files)
                    .on_input(|v| Message::Service(Msg::LogField(LogField::MaxFiles(v))))
                    .width(Length::Fixed(160.0)),
            ),
            checkbox("允许日志实时推送给前端（enable_gui_logging）", self.log.enable_gui_logging)
                .on_toggle(|v| Message::Service(Msg::LogField(LogField::GuiLogging(v)))),
            row![
                button(text(if self.log_saving { "保存中…" } else { "保存日志设置" }))
                    .on_press_maybe(
                        (connected && !self.log_saving)
                            .then_some(Message::Service(Msg::SaveLog))
                    ),
                button(text("重新载入")).on_press_maybe(
                    (connected && !self.log_saving)
                        .then_some(Message::Service(Msg::Reload))
                ),
            ]
            .spacing(8),
        ]
        .spacing(8);

        // 空表单时提示默认值来源
        if self.log.max_log_size.is_empty() {
            fields = fields.push(
                text("尚未载入日志设置（默认：10 MiB / 保留 10 个文件）。")
                    .size(12),
            );
        }

        container(column![text("日志设置").size(16), fields].spacing(10))
            .padding(16)
            .width(Length::Fill)
            .style(container::rounded_box)
            .into()
    }
}

/// 运行状态行
fn status_rows(status: Option<&ServerStatus>) -> Element<'_, Message> {
    let Some(status) = status else {
        return text("尚未获取到状态（未连接 fftpd）").size(13).into();
    };
    column![
        kv("FTP 服务：", running(status.ftp_running)),
        kv("SFTP 服务：", running(status.sftp_running)),
        kv("fftpd 版本：", text(status.version.clone()).size(13)),
    ]
    .spacing(6)
    .into()
}

/// “标签：值”行
fn kv<'a>(
    label: &'a str,
    value: impl Into<Element<'a, Message>>,
) -> iced::widget::Row<'a, Message> {
    row![text(label).size(13), value.into()].spacing(8)
}

/// 服务运行状态着色文本
fn running<'a>(running: bool) -> Element<'a, Message> {
    text(if running { "运行中" } else { "未运行" })
        .size(13)
        .color(if running { INFO_COLOR } else { ERROR_COLOR })
        .into()
}

/// 刷新运行状态（`GetStatus` → 服务器页状态）
fn refresh_status(ipc: &IpcService) -> Task<Message> {
    let Some(conn) = ipc.conn().cloned() else {
        return Task::none();
    };
    Task::perform(
        ipc_service::request::<ServerStatus>(conn, Command::GetStatus),
        |r| Message::Server(server::Msg::Status(r)),
    )
}

/// 载入日志设置（`GetConfig` → `[logging]` 段）
async fn load_logging(conn: IpcConn) -> Result<LoggingConfig, IpcError> {
    let content = ipc_service::request::<TextContent>(conn, Command::GetConfig).await?;
    toml::from_str::<Config>(&content.content)
        .map(|config| config.logging)
        .map_err(|e| IpcError::BadResponse(format!("配置解析失败：{e}")))
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
    fn log_level_parses_and_roundtrips() {
        for level in LogLevel::ALL {
            assert_eq!(LogLevel::parse(level.as_str()), level);
        }
        assert_eq!(LogLevel::parse("WARNING"), LogLevel::Warn);
        assert_eq!(LogLevel::parse("nonsense"), LogLevel::Info);
    }

    #[test]
    fn log_form_from_logging_maps_fields() {
        let cfg = LoggingConfig {
            log_dir: "/var/log/fftpd".to_owned(),
            log_level: "debug".to_owned(),
            max_log_size: 4096,
            max_log_files: 3,
            enable_gui_logging: false,
            ..LoggingConfig::default()
        };

        let form = LogForm::from_logging(&cfg);
        assert_eq!(form.log_dir, "/var/log/fftpd");
        assert_eq!(form.log_level, LogLevel::Debug);
        assert_eq!(form.max_log_size, "4096");
        assert_eq!(form.max_log_files, "3");
        assert!(!form.enable_gui_logging);
    }
}

//! 服务器页：FTP/SFTP 结构化配置表单 + `config.toml` 原文编辑
//!
//! 表单字段映射 [`fftp_common::config::Config`] 的 `ftp`/`sftp` 段：
//! 加载时解析 `config.toml` 填表，保存时以“读-改-写”取回服务端最新配置、
//! 仅覆盖本页负责的段落（`security` 由安全页、`logging` 由服务页维护），
//! 经共享类型校验后序列化为 TOML 走 `SaveConfig`；
//! “高级”切换保留 `config.toml` 原文编辑能力。

use fftp_common::config::{Config, ConnectionMode, FtpConfig, SftpConfig};
use fftp_ipc::protocol::Command;
use iced::widget::{
    button, checkbox, column, container, pick_list, row, text, text_editor, text_input, Widget,
};
use iced::{Element, Font, Length, Task};

use crate::app::Message;
use crate::ipc_service::{self, IpcConn, IpcError, IpcService, ServerStatus, TextContent};
use crate::tabs::{error_line, form_row, info_line, relay_error};

/// 连接模式下拉选项（[`ConnectionMode`] 未实现 `Display`，用本地展示类型）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ModeOption {
    /// 仅被动
    #[default]
    PassiveOnly,
    /// 仅主动
    ActiveOnly,
    /// 主动 + 被动
    Both,
}

impl ModeOption {
    /// 下拉可选项
    pub const ALL: [Self; 3] = [Self::PassiveOnly, Self::ActiveOnly, Self::Both];

    /// 转换为配置枚举
    #[must_use]
    pub fn to_mode(self) -> ConnectionMode {
        match self {
            ModeOption::PassiveOnly => ConnectionMode::PassiveOnly,
            ModeOption::ActiveOnly => ConnectionMode::ActiveOnly,
            ModeOption::Both => ConnectionMode::ActiveAndPassive,
        }
    }

    /// 从配置枚举转换
    #[must_use]
    pub fn from_mode(mode: ConnectionMode) -> Self {
        match mode {
            ConnectionMode::PassiveOnly => ModeOption::PassiveOnly,
            ConnectionMode::ActiveOnly => ModeOption::ActiveOnly,
            ConnectionMode::ActiveAndPassive => ModeOption::Both,
        }
    }
}

impl std::fmt::Display for ModeOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ModeOption::PassiveOnly => "仅被动 passive_only",
            ModeOption::ActiveOnly => "仅主动 active_only",
            ModeOption::Both => "主动 + 被动 active_and_passive",
        })
    }
}

/// FTPS 表单（`[ftp.ftps]`）
#[derive(Debug, Clone, Default)]
pub struct FtpsForm {
    /// 启用 FTPS（显式 TLS）
    pub enabled: bool,
    /// 强制 TLS（拒绝未升级的客户端）
    pub require_ssl: bool,
    /// 证书路径（空 = 自动生成）
    pub cert_path: String,
    /// 私钥路径（空 = 自动生成）
    pub key_path: String,
}

impl FtpsForm {
    /// 从配置填充表单
    #[must_use]
    pub fn from_config(cfg: &fftp_common::config::FtpsConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            require_ssl: cfg.require_ssl,
            cert_path: cfg.cert_path.clone(),
            key_path: cfg.key_path.clone(),
        }
    }

    /// 写回配置
    pub fn apply_to(&self, cfg: &mut fftp_common::config::FtpsConfig) {
        cfg.enabled = self.enabled;
        cfg.require_ssl = self.require_ssl;
        cfg.cert_path.clone_from(&self.cert_path);
        cfg.key_path.clone_from(&self.key_path);
    }
}

/// FTP 表单：数值字段以文本缓冲编辑，保存时解析回 [`FtpConfig`]
#[derive(Debug, Clone, Default)]
pub struct FtpForm {
    /// 启用 FTP 服务
    pub enabled: bool,
    /// 监听地址
    pub bind_ip: String,
    /// 监听端口
    pub port: String,
    /// 欢迎消息
    pub welcome_message: String,
    /// 允许匿名登录
    pub allow_anonymous: bool,
    /// 匿名主目录（空 = 未设置）
    pub anonymous_home: String,
    /// 连接模式
    pub connection_mode: ModeOption,
    /// 被动端口区间起
    pub passive_start: String,
    /// 被动端口区间止
    pub passive_end: String,
    /// FTPS 子表单
    pub ftps: FtpsForm,
}

impl FtpForm {
    /// 从配置填充表单
    #[must_use]
    pub fn from_config(cfg: &FtpConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            bind_ip: cfg.bind_ip.clone(),
            port: cfg.port.to_string(),
            welcome_message: cfg.welcome_message.clone(),
            allow_anonymous: cfg.allow_anonymous,
            anonymous_home: cfg.anonymous_home.clone(),
            connection_mode: ModeOption::from_mode(cfg.connection_mode),
            passive_start: cfg.passive_ports.0.to_string(),
            passive_end: cfg.passive_ports.1.to_string(),
            ftps: FtpsForm::from_config(&cfg.ftps),
        }
    }

    /// 表单消息应用到本地缓冲
    pub fn apply(&mut self, msg: FtpMsg) {
        match msg {
            FtpMsg::Enabled(v) => self.enabled = v,
            FtpMsg::BindIp(v) => self.bind_ip = v,
            FtpMsg::Port(v) => self.port = v,
            FtpMsg::Welcome(v) => self.welcome_message = v,
            FtpMsg::AllowAnonymous(v) => self.allow_anonymous = v,
            FtpMsg::AnonymousHome(v) => self.anonymous_home = v,
            FtpMsg::ConnectionMode(v) => self.connection_mode = v,
            FtpMsg::PassiveStart(v) => self.passive_start = v,
            FtpMsg::PassiveEnd(v) => self.passive_end = v,
            FtpMsg::FtpsEnabled(v) => self.ftps.enabled = v,
            FtpMsg::FtpsRequireSsl(v) => self.ftps.require_ssl = v,
            FtpMsg::FtpsCertPath(v) => self.ftps.cert_path = v,
            FtpMsg::FtpsKeyPath(v) => self.ftps.key_path = v,
        }
    }

    /// 解析表单数值并写回配置
    ///
    /// # Errors
    /// 端口为 0、被动端口区间非法（起 > 止）或数值无法解析时返回错误
    pub fn apply_to(&self, cfg: &mut FtpConfig) -> Result<(), String> {
        cfg.enabled = self.enabled;
        cfg.bind_ip.clone_from(&self.bind_ip);
        cfg.port = parse_num(&self.port, "FTP 监听端口")?;
        if cfg.port == 0 {
            return Err("FTP 监听端口不能为 0".to_owned());
        }
        cfg.welcome_message.clone_from(&self.welcome_message);
        cfg.allow_anonymous = self.allow_anonymous;
        cfg.anonymous_home.clone_from(&self.anonymous_home);
        cfg.connection_mode = self.connection_mode.to_mode();
        let start: u16 = parse_num(&self.passive_start, "被动端口起始")?;
        let end: u16 = parse_num(&self.passive_end, "被动端口结束")?;
        if start == 0 || start > end {
            return Err(format!("被动端口区间非法：{start}-{end}"));
        }
        cfg.passive_ports = (start, end);
        self.ftps.apply_to(&mut cfg.ftps);
        Ok(())
    }
}

/// SFTP 表单：数值字段以文本缓冲编辑，保存时解析回 [`SftpConfig`]
#[derive(Debug, Clone, Default)]
pub struct SftpForm {
    /// 启用 SFTP 服务
    pub enabled: bool,
    /// 监听地址
    pub bind_ip: String,
    /// 监听端口
    pub port: String,
    /// 主机密钥路径（空 = 默认路径）
    pub host_key_path: String,
    /// 最大认证尝试次数
    pub max_auth_attempts: String,
    /// 认证超时（秒）
    pub auth_timeout: String,
}

impl SftpForm {
    /// 从配置填充表单
    #[must_use]
    pub fn from_config(cfg: &SftpConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            bind_ip: cfg.bind_ip.clone(),
            port: cfg.port.to_string(),
            host_key_path: cfg.host_key_path.clone(),
            max_auth_attempts: cfg.max_auth_attempts.to_string(),
            auth_timeout: cfg.auth_timeout.to_string(),
        }
    }

    /// 表单消息应用到本地缓冲
    pub fn apply(&mut self, msg: SftpMsg) {
        match msg {
            SftpMsg::Enabled(v) => self.enabled = v,
            SftpMsg::BindIp(v) => self.bind_ip = v,
            SftpMsg::Port(v) => self.port = v,
            SftpMsg::HostKeyPath(v) => self.host_key_path = v,
            SftpMsg::MaxAuthAttempts(v) => self.max_auth_attempts = v,
            SftpMsg::AuthTimeout(v) => self.auth_timeout = v,
        }
    }

    /// 解析表单数值并写回配置
    ///
    /// # Errors
    /// 端口为 0、认证尝试次数为 0 或数值无法解析时返回错误
    pub fn apply_to(&self, cfg: &mut SftpConfig) -> Result<(), String> {
        cfg.enabled = self.enabled;
        cfg.bind_ip.clone_from(&self.bind_ip);
        cfg.port = parse_num(&self.port, "SFTP 监听端口")?;
        if cfg.port == 0 {
            return Err("SFTP 监听端口不能为 0".to_owned());
        }
        cfg.host_key_path.clone_from(&self.host_key_path);
        cfg.max_auth_attempts = parse_num(&self.max_auth_attempts, "最大认证尝试次数")?;
        if cfg.max_auth_attempts == 0 {
            return Err("最大认证尝试次数不能为 0".to_owned());
        }
        cfg.auth_timeout = parse_num(&self.auth_timeout, "认证超时")?;
        Ok(())
    }
}

/// FTP 表单字段变更
#[derive(Debug, Clone)]
pub enum FtpMsg {
    /// 启用 FTP
    Enabled(bool),
    /// 监听地址
    BindIp(String),
    /// 监听端口
    Port(String),
    /// 欢迎消息
    Welcome(String),
    /// 允许匿名
    AllowAnonymous(bool),
    /// 匿名主目录
    AnonymousHome(String),
    /// 连接模式
    ConnectionMode(ModeOption),
    /// 被动端口起
    PassiveStart(String),
    /// 被动端口止
    PassiveEnd(String),
    /// 启用 FTPS
    FtpsEnabled(bool),
    /// 强制 TLS
    FtpsRequireSsl(bool),
    /// 证书路径
    FtpsCertPath(String),
    /// 私钥路径
    FtpsKeyPath(String),
}

/// SFTP 表单字段变更
#[derive(Debug, Clone)]
pub enum SftpMsg {
    /// 启用 SFTP
    Enabled(bool),
    /// 监听地址
    BindIp(String),
    /// 监听端口
    Port(String),
    /// 主机密钥路径
    HostKeyPath(String),
    /// 最大认证尝试次数
    MaxAuthAttempts(String),
    /// 认证超时
    AuthTimeout(String),
}

/// 服务器页消息
#[derive(Debug, Clone)]
pub enum Msg {
    /// `GetStatus` 响应
    Status(Result<ServerStatus, IpcError>),
    /// 载入 `config.toml` 原文
    Content(String),
    /// FTP 表单字段
    Ftp(FtpMsg),
    /// SFTP 表单字段
    Sftp(SftpMsg),
    /// 高级模式编辑器动作
    Edit(text_editor::Action),
    /// 表单 ⇄ 高级原文切换
    ToggleAdvanced,
    /// 保存配置
    Save,
    /// `SaveConfig` 响应（服务端规范化后的内容）
    Saved(Result<String, IpcError>),
}

/// 服务器页状态
#[derive(Debug, Default)]
pub struct ServerTab {
    status: Option<ServerStatus>,
    /// FTP 表单
    ftp: FtpForm,
    /// SFTP 表单
    sftp: SftpForm,
    /// 高级（原文编辑）模式
    advanced: bool,
    /// `config.toml` 原文编辑器
    editor: text_editor::Content,
    /// 保存进行中
    saving: bool,
    error: Option<String>,
    info: Option<String>,
}

impl ServerTab {
    /// 更新页面状态；`ipc` 用于发起保存请求
    pub fn update(&mut self, msg: Msg, ipc: &IpcService) -> Task<Message> {
        match msg {
            Msg::Status(result) => match result {
                Ok(status) => {
                    self.status = Some(status);
                    Task::none()
                }
                Err(e) => {
                    self.error = Some(e.message().to_owned());
                    relay_error(&e)
                }
            },
            Msg::Content(content) => {
                self.load(&content);
                Task::none()
            }
            Msg::Ftp(m) => {
                self.ftp.apply(m);
                self.info = None;
                Task::none()
            }
            Msg::Sftp(m) => {
                self.sftp.apply(m);
                self.info = None;
                Task::none()
            }
            Msg::Edit(action) => {
                self.editor.perform(action);
                self.info = None;
                Task::none()
            }
            Msg::ToggleAdvanced => {
                self.toggle_advanced();
                Task::none()
            }
            Msg::Save => self.save(ipc),
            Msg::Saved(result) => {
                self.saving = false;
                match result {
                    Ok(content) => {
                        self.load(&content);
                        self.info = Some("配置已保存".to_owned());
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

    /// 服务端运行状态（关于页/服务页展示用）
    #[must_use]
    pub fn status(&self) -> Option<&ServerStatus> {
        self.status.as_ref()
    }

    /// 载入 `config.toml` 原文并同步表单
    fn load(&mut self, content: &str) {
        match toml::from_str::<Config>(content) {
            Ok(config) => {
                self.ftp = FtpForm::from_config(&config.ftp);
                self.sftp = SftpForm::from_config(&config.sftp);
                self.error = None;
            }
            Err(e) => self.error = Some(format!("配置 TOML 解析失败：{e}")),
        }
        self.editor = text_editor::Content::with_text(content);
        self.info = None;
    }

    /// 表单 ⇄ 高级原文切换
    fn toggle_advanced(&mut self) {
        if self.advanced {
            // 高级 → 表单：以原文为准刷新表单
            match toml::from_str::<Config>(&self.editor.text()) {
                Ok(config) => {
                    self.ftp = FtpForm::from_config(&config.ftp);
                    self.sftp = SftpForm::from_config(&config.sftp);
                    self.advanced = false;
                    self.error = None;
                }
                Err(e) => self.error = Some(format!("配置 TOML 解析失败，无法返回表单：{e}")),
            }
        } else {
            // 表单 → 高级：把当前表单值合并进原文
            match merged_toml(&self.editor.text(), &self.ftp, &self.sftp) {
                Ok(content) => {
                    self.editor = text_editor::Content::with_text(&content);
                    self.advanced = true;
                    self.error = None;
                }
                Err(e) => self.error = Some(e),
            }
        }
        self.info = None;
    }

    fn save(&mut self, ipc: &IpcService) -> Task<Message> {
        let Some(conn) = ipc.conn().cloned() else {
            self.error = Some("未连接 fftpd，无法保存".to_owned());
            return Task::none();
        };
        if self.advanced {
            // 原文模式：本地校验后原样提交
            let content = self.editor.text();
            if let Err(e) = validate(&content) {
                self.error = Some(e);
                return Task::none();
            }
            self.saving = true;
            self.error = None;
            self.info = None;
            Task::perform(save_config(conn, content), |r| Message::Server(Msg::Saved(r)))
        } else {
            self.saving = true;
            self.error = None;
            self.info = None;
            let (ftp, sftp) = (self.ftp.clone(), self.sftp.clone());
            Task::perform(save_forms(conn, ftp, sftp), |r| Message::Server(Msg::Saved(r)))
        }
    }

    /// 渲染页面
    #[must_use]
    pub fn view(&self, connected: bool) -> Element<'_, Message> {
        let status_card = container(
            column![text("运行状态").size(16), self.status_rows(),].spacing(10),
        )
        .padding(16)
        .width(Length::Fill)
        .style(container::rounded_box);

        let mode_label = if self.advanced {
            "返回表单"
        } else {
            "高级：TOML 原文编辑"
        };
        let mut toolbar = row![
            button(text(mode_label)).on_press(Message::Server(Msg::ToggleAdvanced)),
            button(text(if self.saving { "保存中…" } else { "保存" }))
                .on_press_maybe((connected && !self.saving).then_some(Message::Server(Msg::Save))),
        ]
        .spacing(8);
        if let Some(info) = &self.info {
            toolbar = toolbar.push(info_line(info));
        }

        let mut page = column![
            status_card,
            text(if self.advanced {
                "config.toml（原文编辑）"
            } else {
                "config.toml（结构化表单）"
            })
            .size(16),
            toolbar,
        ]
        .spacing(10)
        .width(Length::Fill)
        .height(Length::Fill);
        if let Some(error) = &self.error {
            page = page.push(error_line(error));
        }
        page = page.push(if self.advanced {
            text_editor(&self.editor)
                .on_action(|action| Message::Server(Msg::Edit(action)))
                .font(Font::MONOSPACE)
                .height(Length::Fill)
                .boxed()
        } else {
            self.form_body()
        });
        page.boxed()
    }

    /// 表单主体：FTP + SFTP 两个分组
    fn form_body(&self) -> Element<'_, Message> {
        column![
            section("FTP 服务", self.ftp_rows()),
            section("SFTP 服务", self.sftp_rows()),
        ]
        .spacing(12)
        .width(Length::Fill)
        .height(Length::Fill)
        .boxed()
    }

    fn ftp_rows(&self) -> Element<'_, Message> {
        let passive = row![
            text_input("50000", &self.ftp.passive_start)
                .on_input(|v| Message::Server(Msg::Ftp(FtpMsg::PassiveStart(v))))
                .width(Length::Fixed(110.0)),
            text("—").size(13),
            text_input("51000", &self.ftp.passive_end)
                .on_input(|v| Message::Server(Msg::Ftp(FtpMsg::PassiveEnd(v))))
                .width(Length::Fixed(110.0)),
        ]
        .spacing(6);
        let ftps = row![
            checkbox(self.ftp.ftps.enabled)
                .label("启用 FTPS（显式 TLS）")
                .on_toggle(|v| Message::Server(Msg::Ftp(FtpMsg::FtpsEnabled(v)))),
            checkbox(self.ftp.ftps.require_ssl)
                .label("强制 SSL（require_ssl）")
                .on_toggle(|v| Message::Server(Msg::Ftp(FtpMsg::FtpsRequireSsl(v)))),
        ]
        .spacing(16);
        column![
            checkbox(self.ftp.enabled)
                .label("启用 FTP 服务")
                .on_toggle(|v| Message::Server(Msg::Ftp(FtpMsg::Enabled(v)))),
            form_row(
                "监听地址 bind_ip",
                text_input("0.0.0.0", &self.ftp.bind_ip)
                    .on_input(|v| Message::Server(Msg::Ftp(FtpMsg::BindIp(v))))
                    .width(Length::Fixed(260.0)),
            ),
            form_row(
                "监听端口 port",
                text_input("21", &self.ftp.port)
                    .on_input(|v| Message::Server(Msg::Ftp(FtpMsg::Port(v))))
                    .width(Length::Fixed(120.0)),
            ),
            form_row(
                "欢迎消息",
                text_input("Welcome to fftpd", &self.ftp.welcome_message)
                    .on_input(|v| Message::Server(Msg::Ftp(FtpMsg::Welcome(v))))
                    .width(Length::Fixed(360.0)),
            ),
            form_row(
                "连接模式",
                pick_list(
                    Some(self.ftp.connection_mode),
                    ModeOption::ALL,
                    ToString::to_string,
                )
                .on_select(|m| Message::Server(Msg::Ftp(FtpMsg::ConnectionMode(m))))
                .width(Length::Fixed(260.0)),
            ),
            form_row("被动端口区间", passive),
            checkbox(self.ftp.allow_anonymous)
                .label("允许匿名登录")
                .on_toggle(|v| Message::Server(Msg::Ftp(FtpMsg::AllowAnonymous(v)))),
            form_row(
                "匿名主目录",
                text_input("（空 = 未设置）", &self.ftp.anonymous_home)
                    .on_input(|v| Message::Server(Msg::Ftp(FtpMsg::AnonymousHome(v))))
                    .width(Length::Fixed(360.0)),
            ),
            ftps,
            form_row(
                "FTPS 证书路径",
                text_input("（空 = 自动生成）", &self.ftp.ftps.cert_path)
                    .on_input(|v| Message::Server(Msg::Ftp(FtpMsg::FtpsCertPath(v))))
                    .width(Length::Fixed(360.0)),
            ),
            form_row(
                "FTPS 私钥路径",
                text_input("（空 = 自动生成）", &self.ftp.ftps.key_path)
                    .on_input(|v| Message::Server(Msg::Ftp(FtpMsg::FtpsKeyPath(v))))
                    .width(Length::Fixed(360.0)),
            ),
        ]
        .spacing(8)
        .boxed()
    }

    fn sftp_rows(&self) -> Element<'_, Message> {
        column![
            checkbox(self.sftp.enabled)
                .label("启用 SFTP 服务")
                .on_toggle(|v| Message::Server(Msg::Sftp(SftpMsg::Enabled(v)))),
            form_row(
                "监听地址 bind_ip",
                text_input("0.0.0.0", &self.sftp.bind_ip)
                    .on_input(|v| Message::Server(Msg::Sftp(SftpMsg::BindIp(v))))
                    .width(Length::Fixed(260.0)),
            ),
            form_row(
                "监听端口 port",
                text_input("2222", &self.sftp.port)
                    .on_input(|v| Message::Server(Msg::Sftp(SftpMsg::Port(v))))
                    .width(Length::Fixed(120.0)),
            ),
            form_row(
                "主机密钥路径",
                text_input("（空 = 默认路径）", &self.sftp.host_key_path)
                    .on_input(|v| Message::Server(Msg::Sftp(SftpMsg::HostKeyPath(v))))
                    .width(Length::Fixed(360.0)),
            ),
            form_row(
                "最大认证尝试次数",
                text_input("3", &self.sftp.max_auth_attempts)
                    .on_input(|v| Message::Server(Msg::Sftp(SftpMsg::MaxAuthAttempts(v))))
                    .width(Length::Fixed(120.0)),
            ),
            form_row(
                "认证超时（秒）",
                text_input("60", &self.sftp.auth_timeout)
                    .on_input(|v| Message::Server(Msg::Sftp(SftpMsg::AuthTimeout(v))))
                    .width(Length::Fixed(120.0)),
            ),
        ]
        .spacing(8)
        .boxed()
    }

    fn status_rows(&self) -> Element<'_, Message> {
        let Some(status) = &self.status else {
            return text("尚未获取到状态（未连接 fftpd）").size(13).boxed();
        };
        column![
            kv("FTP 服务：", running(status.ftp_running)),
            kv("SFTP 服务：", running(status.sftp_running)),
            kv("fftpd 版本：", text(status.version.clone()).size(13)),
            kv("配置文件：", text(status.config_path.clone()).size(13)),
            kv("用户库：", text(status.users_path.clone()).size(13)),
            kv("IPC 端点：", text(status.endpoint.clone()).size(13)),
        ]
        .spacing(6)
        .boxed()
    }
}

/// 分组卡片：标题 + 表单行
fn section<'a>(title: &'a str, rows: Element<'a, Message>) -> Element<'a, Message> {
    container(column![text(title).size(16), rows].spacing(10))
        .padding(16)
        .width(Length::Fill)
        .style(container::rounded_box)
        .boxed()
}

/// 状态卡片的“标签：值”行
///
/// 0.15 起 `From<W> for Element` 被移除：控件入参改用 [`Widget`] 约束。
fn kv<'a>(label: &'a str, value: impl Widget<Message> + 'a) -> Element<'a, Message> {
    row![text(label).size(13), value].spacing(8).boxed()
}

/// 服务运行状态着色文本
fn running(running: bool) -> Element<'static, Message> {
    text(if running { "运行中" } else { "未运行" })
        .size(13)
        .color(if running {
            crate::tabs::INFO_COLOR
        } else {
            crate::tabs::ERROR_COLOR
        })
        .boxed()
}

/// 解析无符号数值字段
fn parse_num<T: std::str::FromStr>(value: &str, label: &str) -> Result<T, String> {
    value
        .trim()
        .parse::<T>()
        .map_err(|_| format!("{label}不是合法数字：{value}"))
}

/// 把当前表单值合并进 `config.toml` 原文（表单 → 高级切换用）
fn merged_toml(content: &str, ftp: &FtpForm, sftp: &SftpForm) -> Result<String, String> {
    let mut config: Config =
        toml::from_str(content).map_err(|e| format!("配置 TOML 解析失败：{e}"))?;
    ftp.apply_to(&mut config.ftp)?;
    sftp.apply_to(&mut config.sftp)?;
    toml::to_string_pretty(&config).map_err(|e| format!("配置序列化失败：{e}"))
}

/// 用共享类型校验 `config.toml` 原文
fn validate(content: &str) -> Result<(), String> {
    let parsed: Config =
        toml::from_str(content).map_err(|e| format!("配置 TOML 解析失败：{e}"))?;
    parsed
        .validate()
        .map_err(|e| format!("配置校验失败：{e:#}"))?;
    Ok(())
}

/// 保存配置（成功时返回服务端规范化后的内容）
async fn save_config(conn: IpcConn, content: String) -> Result<String, IpcError> {
    ipc_service::request::<TextContent>(conn, Command::SaveConfig { content })
        .await
        .map(|c| c.content)
}

/// 表单保存：读-改-写，仅覆盖 `ftp`/`sftp` 段
async fn save_forms(conn: IpcConn, ftp: FtpForm, sftp: SftpForm) -> Result<String, IpcError> {
    let current = ipc_service::request::<TextContent>(conn.clone(), Command::GetConfig).await?;
    let mut config: Config = toml::from_str(&current.content)
        .map_err(|e| IpcError::Request(format!("配置解析失败：{e}")))?;
    ftp.apply_to(&mut config.ftp).map_err(IpcError::Request)?;
    sftp.apply_to(&mut config.sftp).map_err(IpcError::Request)?;
    config
        .validate()
        .map_err(|e| IpcError::Request(format!("配置校验失败：{e:#}")))?;
    let content = toml::to_string_pretty(&config)
        .map_err(|e| IpcError::Request(format!("配置序列化失败：{e}")))?;
    ipc_service::request::<TextContent>(conn, Command::SaveConfig { content })
        .await
        .map(|c| c.content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_config_roundtrip() {
        let mut config = Config::default();
        config.ftp.port = 2121;
        config.ftp.connection_mode = ConnectionMode::ActiveAndPassive;
        config.ftp.passive_ports = (40000, 40100);
        config.ftp.allow_anonymous = true;
        config.ftp.anonymous_home = "/srv/anon".to_owned();
        config.ftp.ftps.enabled = true;
        config.ftp.ftps.require_ssl = true;
        config.sftp.port = 2200;
        config.sftp.max_auth_attempts = 5;
        config.sftp.auth_timeout = 30;

        let ftp = FtpForm::from_config(&config.ftp);
        let sftp = SftpForm::from_config(&config.sftp);
        let mut restored = Config::default();
        ftp.apply_to(&mut restored.ftp).unwrap();
        sftp.apply_to(&mut restored.sftp).unwrap();

        assert_eq!(restored.ftp.port, 2121);
        assert_eq!(restored.ftp.connection_mode, ConnectionMode::ActiveAndPassive);
        assert_eq!(restored.ftp.passive_ports, (40000, 40100));
        assert!(restored.ftp.allow_anonymous);
        assert_eq!(restored.ftp.anonymous_home, "/srv/anon");
        assert!(restored.ftp.ftps.enabled);
        assert!(restored.ftp.ftps.require_ssl);
        assert_eq!(restored.sftp.port, 2200);
        assert_eq!(restored.sftp.max_auth_attempts, 5);
        assert_eq!(restored.sftp.auth_timeout, 30);
    }

    #[test]
    fn apply_to_rejects_bad_numbers() {
        let mut config = Config::default();
        let mut ftp = FtpForm::from_config(&config.ftp);
        ftp.port = "abc".to_owned();
        assert!(ftp.apply_to(&mut config.ftp).is_err());

        let mut ftp = FtpForm::from_config(&config.ftp);
        ftp.port = "0".to_owned();
        assert!(ftp.apply_to(&mut config.ftp).is_err());

        let mut ftp = FtpForm::from_config(&config.ftp);
        ftp.passive_start = "51000".to_owned();
        ftp.passive_end = "50000".to_owned();
        assert!(ftp.apply_to(&mut config.ftp).is_err());

        let mut sftp = SftpForm::from_config(&config.sftp);
        sftp.max_auth_attempts = "0".to_owned();
        assert!(sftp.apply_to(&mut config.sftp).is_err());
    }

    #[test]
    fn merged_toml_overwrites_only_forms() {
        let mut config = Config::default();
        config.security.max_login_attempts = 9;
        let content = toml::to_string_pretty(&config).unwrap();

        let mut ftp = FtpForm::from_config(&config.ftp);
        ftp.port = "2121".to_owned();
        let sftp = SftpForm::from_config(&config.sftp);
        let merged = merged_toml(&content, &ftp, &sftp).unwrap();
        let parsed: Config = toml::from_str(&merged).unwrap();
        assert_eq!(parsed.ftp.port, 2121);
        assert_eq!(parsed.security.max_login_attempts, 9);
    }

    #[test]
    fn mode_option_converts_both_ways() {
        for mode in [
            ConnectionMode::PassiveOnly,
            ConnectionMode::ActiveOnly,
            ConnectionMode::ActiveAndPassive,
        ] {
            assert_eq!(ModeOption::from_mode(mode).to_mode(), mode);
        }
    }
}

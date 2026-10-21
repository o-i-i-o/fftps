//! 安全页：`[security]` 段结构化编辑
//!
//! 字段映射 [`fftp_common::config::SecurityConfig`]：IP 允许/拒绝名单（CIDR）
//! 列表编辑、fail2ban、连接数与登录防护。保存时以“读-改-写”取回服务端最新
//! `config.toml`、仅覆盖 `security` 段（`ftp`/`sftp` 由服务器页、`logging`
//! 由服务页维护），校验后走 `SaveConfig`；另附 `WriteAuditLog` 示例按钮
//! 记录管理操作审计。

use fftp_common::config::{Config, SecurityConfig};
use fftp_ipc::protocol::Command;
use iced::widget::{button, checkbox, column, container, row, text, text_input};
use iced::{Element, Length, Task};

use crate::app::Message;
use crate::ipc_service::{self, IpcConn, IpcError, IpcService, TextContent};
use crate::tabs::{error_line, form_row, info_line, relay_error};

/// 安全配置字段变更
#[derive(Debug, Clone)]
pub enum Field {
    /// 全局最大并发连接数
    MaxConnections(String),
    /// 单 IP 最大并发连接数
    MaxConnectionsPerIp(String),
    /// 启用 fail2ban
    Fail2banEnabled(bool),
    /// fail2ban 触发阈值
    Fail2banThreshold(String),
    /// fail2ban 封禁时长（秒）
    Fail2banBanTime(String),
    /// 允许符号链接
    AllowSymlinks(bool),
    /// 最大登录尝试次数
    MaxLoginAttempts(String),
}

/// 安全页消息
#[derive(Debug, Clone)]
pub enum Msg {
    /// 重新载入最新安全配置
    Reload,
    /// `GetConfig` 响应（解析后的安全配置）
    Loaded(Result<SecurityConfig, IpcError>),
    /// 字段变更
    Field(Field),
    /// 允许名单输入框
    AllowedInput(String),
    /// 拒绝名单输入框
    DeniedInput(String),
    /// 添加允许名单项
    AddAllowed,
    /// 添加拒绝名单项
    AddDenied,
    /// 删除允许名单项
    RemoveAllowed(usize),
    /// 删除拒绝名单项
    RemoveDenied(usize),
    /// 保存
    Save,
    /// `SaveConfig` 响应
    Saved(Result<String, IpcError>),
    /// 记录审计日志（示例）
    Audit,
    /// `WriteAuditLog` 响应
    Audited(Result<(), IpcError>),
}

/// 安全页状态
#[derive(Debug, Default)]
pub struct SecurityTab {
    /// 开关与名单直接落在 [`SecurityConfig`] 上
    cfg: SecurityConfig,
    /// 数值文本缓冲（保存时解析）
    max_connections: String,
    /// 单 IP 最大并发连接数缓冲
    max_connections_per_ip: String,
    /// fail2ban 阈值缓冲
    fail2ban_threshold: String,
    /// fail2ban 封禁时长缓冲
    fail2ban_ban_time: String,
    /// 最大登录尝试次数缓冲
    max_login_attempts: String,
    /// 允许名单输入框
    allowed_input: String,
    /// 拒绝名单输入框
    denied_input: String,
    /// 载入/保存进行中
    busy: bool,
    error: Option<String>,
    info: Option<String>,
}

impl SecurityTab {
    /// 更新页面状态；`ipc` 用于发起请求
    pub fn update(&mut self, msg: Msg, ipc: &IpcService) -> Task<Message> {
        match msg {
            Msg::Reload => {
                let Some(conn) = ipc.conn().cloned() else {
                    self.error = Some("未连接 fftpd，无法载入安全配置".to_owned());
                    return Task::none();
                };
                self.busy = true;
                Task::perform(load_security(conn), |r| Message::Security(Msg::Loaded(r)))
            }
            Msg::Loaded(result) => self.on_loaded(result),
            Msg::Field(field) => {
                self.apply(field);
                self.info = None;
                Task::none()
            }
            Msg::AllowedInput(v) => {
                self.allowed_input = v;
                Task::none()
            }
            Msg::DeniedInput(v) => {
                self.denied_input = v;
                Task::none()
            }
            Msg::AddAllowed => {
                let entry = self.allowed_input.trim().to_owned();
                if !entry.is_empty() {
                    self.cfg.allowed_ips.push(entry);
                    self.allowed_input = String::new();
                    self.info = None;
                }
                Task::none()
            }
            Msg::AddDenied => {
                let entry = self.denied_input.trim().to_owned();
                if !entry.is_empty() {
                    self.cfg.denied_ips.push(entry);
                    self.denied_input = String::new();
                    self.info = None;
                }
                Task::none()
            }
            Msg::RemoveAllowed(index) => {
                if index < self.cfg.allowed_ips.len() {
                    self.cfg.allowed_ips.remove(index);
                    self.info = None;
                }
                Task::none()
            }
            Msg::RemoveDenied(index) => {
                if index < self.cfg.denied_ips.len() {
                    self.cfg.denied_ips.remove(index);
                    self.info = None;
                }
                Task::none()
            }
            Msg::Save => self.save(ipc),
            Msg::Saved(result) => self.on_saved(result),
            Msg::Audit => self.audit(ipc),
            Msg::Audited(result) => self.on_audited(result),
        }
    }

    /// `GetConfig` 响应：载入安全配置
    fn on_loaded(&mut self, result: Result<SecurityConfig, IpcError>) -> Task<Message> {
        self.busy = false;
        match result {
            Ok(cfg) => {
                self.load(cfg);
                self.error = None;
                Task::none()
            }
            Err(e) => {
                self.error = Some(e.message().to_owned());
                relay_error(&e)
            }
        }
    }

    /// `SaveConfig` 响应：以服务端规范化后的内容刷新表单
    fn on_saved(&mut self, result: Result<String, IpcError>) -> Task<Message> {
        self.busy = false;
        match result {
            Ok(content) => match toml::from_str::<Config>(&content) {
                Ok(config) => {
                    self.load(config.security);
                    self.error = None;
                    self.info = Some("安全配置已保存".to_owned());
                }
                Err(e) => self.error = Some(format!("配置解析失败：{e}")),
            },
            Err(e) => {
                self.error = Some(e.message().to_owned());
                return relay_error(&e);
            }
        }
        Task::none()
    }

    /// 记录审计日志（示例操作）
    fn audit(&mut self, ipc: &IpcService) -> Task<Message> {
        let Some(conn) = ipc.conn().cloned() else {
            self.error = Some("未连接 fftpd，无法记录审计日志".to_owned());
            return Task::none();
        };
        self.busy = true;
        let details = format!(
            "允许名单 {} 项 / 拒绝名单 {} 项，fail2ban={}，最大连接数={}",
            self.cfg.allowed_ips.len(),
            self.cfg.denied_ips.len(),
            self.cfg.fail2ban_enabled,
            self.max_connections
        );
        Task::perform(write_audit(conn, details), |r| {
            Message::Security(Msg::Audited(r))
        })
    }

    /// `WriteAuditLog` 响应
    fn on_audited(&mut self, result: Result<(), IpcError>) -> Task<Message> {
        self.busy = false;
        match result {
            Ok(()) => {
                self.error = None;
                self.info = Some("审计日志已记录".to_owned());
                Task::none()
            }
            Err(e) => {
                self.error = Some(e.message().to_owned());
                relay_error(&e)
            }
        }
    }

    /// 载入安全配置并同步文本缓冲
    fn load(&mut self, cfg: SecurityConfig) {
        self.max_connections = cfg.max_connections.to_string();
        self.max_connections_per_ip = cfg.max_connections_per_ip.to_string();
        self.fail2ban_threshold = cfg.fail2ban_threshold.to_string();
        self.fail2ban_ban_time = cfg.fail2ban_ban_time.to_string();
        self.max_login_attempts = cfg.max_login_attempts.to_string();
        self.cfg = cfg;
    }

    /// 字段变更应用
    fn apply(&mut self, field: Field) {
        match field {
            Field::MaxConnections(v) => self.max_connections = v,
            Field::MaxConnectionsPerIp(v) => self.max_connections_per_ip = v,
            Field::Fail2banEnabled(v) => self.cfg.fail2ban_enabled = v,
            Field::Fail2banThreshold(v) => self.fail2ban_threshold = v,
            Field::Fail2banBanTime(v) => self.fail2ban_ban_time = v,
            Field::AllowSymlinks(v) => self.cfg.allow_symlinks = v,
            Field::MaxLoginAttempts(v) => self.max_login_attempts = v,
        }
    }

    /// 解析数值缓冲并组装 [`SecurityConfig`]
    fn to_config(&self) -> Result<SecurityConfig, String> {
        let mut cfg = self.cfg.clone();
        cfg.max_connections = parse_num(&self.max_connections, "最大连接数")?;
        cfg.max_connections_per_ip = parse_num(&self.max_connections_per_ip, "单 IP 最大连接数")?;
        cfg.fail2ban_threshold = parse_num(&self.fail2ban_threshold, "fail2ban 阈值")?;
        cfg.fail2ban_ban_time = parse_num(&self.fail2ban_ban_time, "fail2ban 封禁时长")?;
        cfg.max_login_attempts = parse_num(&self.max_login_attempts, "最大登录尝试次数")?;
        Ok(cfg)
    }

    fn save(&mut self, ipc: &IpcService) -> Task<Message> {
        let cfg = match self.to_config() {
            Ok(cfg) => cfg,
            Err(e) => {
                self.error = Some(e);
                return Task::none();
            }
        };
        let Some(conn) = ipc.conn().cloned() else {
            self.error = Some("未连接 fftpd，无法保存".to_owned());
            return Task::none();
        };
        self.busy = true;
        self.error = None;
        self.info = None;
        Task::perform(save_security(conn, cfg), |r| Message::Security(Msg::Saved(r)))
    }

    /// 渲染页面
    #[must_use]
    pub fn view(&self, connected: bool) -> Element<'_, Message> {
        let mut toolbar = row![
            text("安全").size(22),
            button(text("刷新")).on_press_maybe(
                (connected && !self.busy).then_some(Message::Security(Msg::Reload))
            ),
            button(text("保存")).on_press_maybe(
                (connected && !self.busy).then_some(Message::Security(Msg::Save))
            ),
            button(text("记录审计日志")).on_press_maybe(
                (connected && !self.busy).then_some(Message::Security(Msg::Audit))
            ),
        ]
        .spacing(10);
        if let Some(info) = &self.info {
            toolbar = toolbar.push(info_line(info));
        }

        let mut page = column![
            toolbar,
            text("config.toml 的 [security] 段：IP 名单、fail2ban、连接数与登录防护。")
                .size(13),
        ]
        .spacing(10)
        .width(Length::Fill)
        .height(Length::Fill);
        if let Some(error) = &self.error {
            page = page.push(error_line(error));
        }
        page = page.push(row![
            column![
                section("IP 名单（CIDR）", self.ip_list_rows()),
                section("连接数", self.conn_rows()),
            ]
            .spacing(12)
            .width(Length::Fill),
            column![
                section("登录防护 / fail2ban", self.guard_rows()),
                section("其他", self.misc_rows()),
            ]
            .spacing(12)
            .width(Length::Fill),
        ]
        .spacing(12));
        page.into()
    }

    /// IP 名单编辑区
    fn ip_list_rows(&self) -> Element<'_, Message> {
        let allowed = column![
            row![
                text("允许名单（空 = 全部放行）").size(13),
                text_input("192.168.1.0/24", &self.allowed_input)
                    .on_input(|v| Message::Security(Msg::AllowedInput(v)))
                    .on_submit(Message::Security(Msg::AddAllowed))
                    .width(Length::Fixed(180.0)),
                button(text("添加")).on_press(Message::Security(Msg::AddAllowed)),
            ]
            .spacing(8),
            ip_list(&self.cfg.allowed_ips, Msg::RemoveAllowed),
        ]
        .spacing(6);
        let denied = column![
            row![
                text("拒绝名单（优先于允许）").size(13),
                text_input("10.0.0.1", &self.denied_input)
                    .on_input(|v| Message::Security(Msg::DeniedInput(v)))
                    .on_submit(Message::Security(Msg::AddDenied))
                    .width(Length::Fixed(180.0)),
                button(text("添加")).on_press(Message::Security(Msg::AddDenied)),
            ]
            .spacing(8),
            ip_list(&self.cfg.denied_ips, Msg::RemoveDenied),
        ]
        .spacing(6);
        column![allowed, denied].spacing(12).into()
    }

    /// 连接数设置
    fn conn_rows(&self) -> Element<'_, Message> {
        column![
            form_row(
                "全局最大连接数",
                text_input("100", &self.max_connections)
                    .on_input(|v| Message::Security(Msg::Field(Field::MaxConnections(v))))
                    .width(Length::Fixed(120.0)),
            ),
            form_row(
                "单 IP 最大连接数",
                text_input("10", &self.max_connections_per_ip)
                    .on_input(|v| Message::Security(Msg::Field(Field::MaxConnectionsPerIp(v))))
                    .width(Length::Fixed(120.0)),
            ),
        ]
        .spacing(8)
        .into()
    }

    /// 登录防护与 fail2ban
    fn guard_rows(&self) -> Element<'_, Message> {
        column![
            checkbox("启用 fail2ban", self.cfg.fail2ban_enabled)
                .on_toggle(|v| Message::Security(Msg::Field(Field::Fail2banEnabled(v)))),
            form_row(
                "触发封禁的失败次数",
                text_input("5", &self.fail2ban_threshold)
                    .on_input(|v| Message::Security(Msg::Field(Field::Fail2banThreshold(v))))
                    .width(Length::Fixed(120.0)),
            ),
            form_row(
                "封禁时长（秒）",
                text_input("3600", &self.fail2ban_ban_time)
                    .on_input(|v| Message::Security(Msg::Field(Field::Fail2banBanTime(v))))
                    .width(Length::Fixed(120.0)),
            ),
            form_row(
                "最大登录尝试次数",
                text_input("5", &self.max_login_attempts)
                    .on_input(|v| Message::Security(Msg::Field(Field::MaxLoginAttempts(v))))
                    .width(Length::Fixed(120.0)),
            ),
        ]
        .spacing(8)
        .into()
    }

    /// 其他开关
    fn misc_rows(&self) -> Element<'_, Message> {
        column![
            checkbox("允许跟随符号链接（allow_symlinks）", self.cfg.allow_symlinks)
                .on_toggle(|v| Message::Security(Msg::Field(Field::AllowSymlinks(v)))),
            text("说明：名单为空表示全部放行；拒绝名单优先于允许名单。")
                .size(12),
        ]
        .spacing(8)
        .into()
    }
}

/// 名单编辑列表
fn ip_list(entries: &[String], on_remove: fn(usize) -> Msg) -> Element<'_, Message> {
    if entries.is_empty() {
        return text("（空）").size(12).into();
    }
    column(entries.iter().enumerate().map(|(index, entry)| {
        row![
            text(entry.clone()).size(13),
            button(text("删除"))
                .on_press(Message::Security(on_remove(index)))
                .style(iced::widget::button::danger),
        ]
        .spacing(8)
        .into()
    }))
    .spacing(4)
    .into()
}

/// 分组卡片
fn section<'a>(title: &'a str, rows: Element<'a, Message>) -> Element<'a, Message> {
    container(column![text(title).size(16), rows].spacing(10))
        .padding(16)
        .width(Length::Fill)
        .style(container::rounded_box)
        .into()
}

/// 解析无符号数值
fn parse_num<T: std::str::FromStr>(value: &str, label: &str) -> Result<T, String> {
    value
        .trim()
        .parse::<T>()
        .map_err(|_| format!("{label}不是合法数字：{value}"))
}

/// 载入最新安全配置（`GetConfig`）
async fn load_security(conn: IpcConn) -> Result<SecurityConfig, IpcError> {
    let content = ipc_service::request::<TextContent>(conn, Command::GetConfig).await?;
    toml::from_str::<Config>(&content.content)
        .map(|config| config.security)
        .map_err(|e| IpcError::BadResponse(format!("配置解析失败：{e}")))
}

/// 保存安全配置：读-改-写，仅覆盖 `security` 段
async fn save_security(conn: IpcConn, security: SecurityConfig) -> Result<String, IpcError> {
    let current = ipc_service::request::<TextContent>(conn.clone(), Command::GetConfig).await?;
    let mut config: Config = toml::from_str(&current.content)
        .map_err(|e| IpcError::Request(format!("配置解析失败：{e}")))?;
    config.security = security;
    config
        .validate()
        .map_err(|e| IpcError::Request(format!("配置校验失败：{e:#}")))?;
    let content = toml::to_string_pretty(&config)
        .map_err(|e| IpcError::Request(format!("配置序列化失败：{e}")))?;
    ipc_service::request::<TextContent>(conn, Command::SaveConfig { content })
        .await
        .map(|c| c.content)
}

/// 记录管理操作审计（`WriteAuditLog`）
async fn write_audit(conn: IpcConn, details: String) -> Result<(), IpcError> {
    ipc_service::request_ok(
        conn,
        Command::WriteAuditLog {
            user: "gui".to_owned(),
            action: "save_security_config".to_owned(),
            target: "config.toml#security".to_owned(),
            details,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_config_parses_numerics() {
        let mut tab = SecurityTab::default();
        tab.load(SecurityConfig::default());
        tab.max_connections = "200".to_owned();
        tab.cfg.fail2ban_enabled = true;
        let cfg = tab.to_config().unwrap();
        assert_eq!(cfg.max_connections, 200);
        assert!(cfg.fail2ban_enabled);

        tab.max_connections = "abc".to_owned();
        assert!(tab.to_config().is_err());
    }

    #[test]
    fn save_merges_only_security_section() {
        // 纯函数路径：合并逻辑与服务器页一致（读-改-写），此处校验段落覆盖语义
        let mut config = Config::default();
        config.ftp.port = 2121;
        config.security = SecurityConfig {
            max_login_attempts: 9,
            ..SecurityConfig::default()
        };

        let content = toml::to_string_pretty(&config).unwrap();
        let mut restored: Config = toml::from_str(&content).unwrap();
        restored.security.max_login_attempts = 3;
        let merged = toml::to_string_pretty(&restored).unwrap();
        let parsed: Config = toml::from_str(&merged).unwrap();
        assert_eq!(parsed.ftp.port, 2121);
        assert_eq!(parsed.security.max_login_attempts, 3);
    }
}

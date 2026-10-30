//! 服务器页：FTP/SFTP 结构化配置表单 + `config.toml` 原文编辑
//!
//! 表单字段映射 [`fftp_common::config::Config`] 的 `ftp`/`sftp` 段：
//! 表单状态即 `ServerState` 的 in-out 属性，加载时解析 `config.toml`
//! 填表，保存时以“读-改-写”取回服务端最新配置、仅覆盖本页负责的段落
//! （`security` 由安全页、`logging` 由服务页维护），经共享类型校验后
//! 序列化为 TOML 走 `SaveConfig`；“高级”切换保留 `config.toml` 原文编辑。

use fftp_common::config::{Config, ConnectionMode, FtpConfig, SftpConfig};
use fftp_ipc::protocol::Command;
use slint::ComponentHandle;

use crate::app::{dispatch, relay, wire0, SharedCore, UiWeak};
use crate::ipc_service::{self, IpcConn, IpcError, ServerStatus, TextContent};
use crate::tabs::parse_num;
use crate::{AppWindow, ServerState};

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
    /// 下拉索引（与 `ui/server.slint` 的 `ComboBox` 顺序一致）
    #[must_use]
    pub fn index(self) -> i32 {
        match self {
            ModeOption::PassiveOnly => 0,
            ModeOption::ActiveOnly => 1,
            ModeOption::Both => 2,
        }
    }

    /// 从下拉索引还原（越界回退仅被动）
    #[must_use]
    pub fn from_index(idx: i32) -> Self {
        match idx {
            1 => ModeOption::ActiveOnly,
            2 => ModeOption::Both,
            _ => ModeOption::PassiveOnly,
        }
    }

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

/// 回调接线
pub fn wire(weak: &UiWeak, core: &SharedCore) {
    let ui = weak.upgrade().unwrap();
    let state = ui.global::<ServerState>();
    state.on_save(wire0(weak, core, on_save));
    state.on_toggle_advanced(wire0(weak, core, on_toggle_advanced));
}

/// 服务端运行状态写入状态卡（应用壳 `GetStatus` 响应驱动）
pub fn set_status(ui: &AppWindow, status: &ServerStatus) {
    let state = ui.global::<ServerState>();
    state.set_have_status(true);
    state.set_ftp_running(status.ftp_running);
    state.set_sftp_running(status.sftp_running);
    state.set_version(status.version.clone().into());
    state.set_config_path(status.config_path.clone().into());
    state.set_users_path(status.users_path.clone().into());
    state.set_status_endpoint(status.endpoint.clone().into());
}

/// 载入 `config.toml` 原文并同步表单（初始状态/保存响应共用）
pub fn apply_content(ui: &AppWindow, content: &str) {
    let state = ui.global::<ServerState>();
    match toml::from_str::<Config>(content) {
        Ok(config) => {
            set_forms(ui, &FtpForm::from_config(&config.ftp), &SftpForm::from_config(&config.sftp));
            state.set_error("".into());
        }
        Err(e) => state.set_error(format!("配置 TOML 解析失败：{e}").into()),
    }
    state.set_toml_text(content.into());
    state.set_info("".into());
}

/// 把表单写入 UI 属性
fn set_forms(ui: &AppWindow, ftp: &FtpForm, sftp: &SftpForm) {
    let state = ui.global::<ServerState>();
    state.set_ftp_enabled(ftp.enabled);
    state.set_ftp_bind_ip(ftp.bind_ip.clone().into());
    state.set_ftp_port(ftp.port.clone().into());
    state.set_ftp_welcome(ftp.welcome_message.clone().into());
    state.set_ftp_anon(ftp.allow_anonymous);
    state.set_ftp_anon_home(ftp.anonymous_home.clone().into());
    state.set_ftp_mode_idx(ftp.connection_mode.index());
    state.set_ftp_passive_start(ftp.passive_start.clone().into());
    state.set_ftp_passive_end(ftp.passive_end.clone().into());
    state.set_ftps_enabled(ftp.ftps.enabled);
    state.set_ftps_require_ssl(ftp.ftps.require_ssl);
    state.set_ftps_cert(ftp.ftps.cert_path.clone().into());
    state.set_ftps_key(ftp.ftps.key_path.clone().into());
    state.set_sftp_enabled(sftp.enabled);
    state.set_sftp_bind_ip(sftp.bind_ip.clone().into());
    state.set_sftp_port(sftp.port.clone().into());
    state.set_sftp_host_key(sftp.host_key_path.clone().into());
    state.set_sftp_max_auth(sftp.max_auth_attempts.clone().into());
    state.set_sftp_auth_timeout(sftp.auth_timeout.clone().into());
}

/// 从 UI 属性读回表单（文本缓冲保存原文，保存时解析）
fn forms_from_ui(ui: &AppWindow) -> (FtpForm, SftpForm) {
    let state = ui.global::<ServerState>();
    let ftp = FtpForm {
        enabled: state.get_ftp_enabled(),
        bind_ip: state.get_ftp_bind_ip().to_string(),
        port: state.get_ftp_port().to_string(),
        welcome_message: state.get_ftp_welcome().to_string(),
        allow_anonymous: state.get_ftp_anon(),
        anonymous_home: state.get_ftp_anon_home().to_string(),
        connection_mode: ModeOption::from_index(state.get_ftp_mode_idx()),
        passive_start: state.get_ftp_passive_start().to_string(),
        passive_end: state.get_ftp_passive_end().to_string(),
        ftps: FtpsForm {
            enabled: state.get_ftps_enabled(),
            require_ssl: state.get_ftps_require_ssl(),
            cert_path: state.get_ftps_cert().to_string(),
            key_path: state.get_ftps_key().to_string(),
        },
    };
    let sftp = SftpForm {
        enabled: state.get_sftp_enabled(),
        bind_ip: state.get_sftp_bind_ip().to_string(),
        port: state.get_sftp_port().to_string(),
        host_key_path: state.get_sftp_host_key().to_string(),
        max_auth_attempts: state.get_sftp_max_auth().to_string(),
        auth_timeout: state.get_sftp_auth_timeout().to_string(),
    };
    (ftp, sftp)
}

/// 保存配置：高级模式本地校验后原样提交；表单模式读-改-写
fn on_save(ui: &AppWindow, core: &SharedCore) {
    let state = ui.global::<ServerState>();
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        state.set_error("未连接 fftpd，无法保存".into());
        return;
    };
    let advanced = state.get_advanced();
    let content = state.get_toml_text().to_string();
    if advanced {
        // 原文模式：本地校验后原样提交
        if let Err(e) = validate(&content) {
            state.set_error(e.into());
            return;
        }
    }
    state.set_saving(true);
    state.set_error("".into());
    state.set_info("".into());
    if advanced {
        dispatch(ui.as_weak(), core, save_config(conn, content), on_saved);
    } else {
        let (ftp, sftp) = forms_from_ui(ui);
        dispatch(ui.as_weak(), core, save_forms(conn, ftp, sftp), on_saved);
    }
}

/// 保存响应：以服务端规范化后的内容刷新表单与原文
fn on_saved(ui: &AppWindow, core: &SharedCore, result: Result<String, IpcError>) {
    let state = ui.global::<ServerState>();
    state.set_saving(false);
    match result {
        Ok(content) => {
            apply_content(ui, &content);
            state.set_info("配置已保存".into());
        }
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 表单 ⇄ 高级原文切换
fn on_toggle_advanced(ui: &AppWindow, _core: &SharedCore) {
    let state = ui.global::<ServerState>();
    let toml_text = state.get_toml_text().to_string();
    if state.get_advanced() {
        // 高级 → 表单：以原文为准刷新表单
        match toml::from_str::<Config>(&toml_text) {
            Ok(config) => {
                set_forms(
                    ui,
                    &FtpForm::from_config(&config.ftp),
                    &SftpForm::from_config(&config.sftp),
                );
                state.set_advanced(false);
                state.set_error("".into());
            }
            Err(e) => {
                state.set_error(format!("配置 TOML 解析失败，无法返回表单：{e}").into());
            }
        }
    } else {
        // 表单 → 高级：把当前表单值合并进原文
        let (ftp, sftp) = forms_from_ui(ui);
        match merged_toml(&toml_text, &ftp, &sftp) {
            Ok(content) => {
                state.set_toml_text(content.into());
                state.set_advanced(true);
                state.set_error("".into());
            }
            Err(e) => state.set_error(e.into()),
        }
    }
    state.set_info("".into());
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

    #[test]
    fn mode_option_index_roundtrip() {
        for idx in 0..3 {
            assert_eq!(ModeOption::from_index(idx).index(), idx);
        }
        assert_eq!(ModeOption::from_index(99), ModeOption::PassiveOnly);
    }
}

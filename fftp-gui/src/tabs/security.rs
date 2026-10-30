//! 安全页：`[security]` 段结构化编辑
//!
//! 字段映射 [`fftp_common::config::SecurityConfig`]：IP 允许/拒绝名单（CIDR）
//! 列表编辑、fail2ban、连接数与登录防护。名单以 `[string]` 模型维护（Rust 增删），
//! 数值字段为文本缓冲，保存时解析校验并按“读-改-写”仅覆盖 `security` 段
//! （`ftp`/`sftp` 由服务器页、`logging` 由服务页维护）；另附 `WriteAuditLog`
//! 示例按钮记录管理操作审计。

use std::rc::Rc;

use fftp_common::config::{Config, SecurityConfig};
use fftp_ipc::protocol::Command;
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::app::{dispatch, relay, wire0, wire1, SharedCore, UiWeak};
use crate::ipc_service::{self, IpcConn, IpcError, TextContent};
use crate::tabs::{parse_num, row_index};
use crate::{AppWindow, SecurityState};

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

/// 回调接线
pub fn wire(weak: &UiWeak, core: &SharedCore) {
    let ui = weak.upgrade().unwrap();
    let state = ui.global::<SecurityState>();
    state.on_reload(wire0(weak, core, reload));
    state.on_save(wire0(weak, core, on_save));
    state.on_audit(wire0(weak, core, on_audit));
    state.on_add_allowed(wire0(weak, core, add_allowed));
    state.on_add_denied(wire0(weak, core, add_denied));
    state.on_remove_allowed(wire1(weak, core, |ui, core, i: i32| {
        remove_entry(ui, core, List::Allowed, i);
    }));
    state.on_remove_denied(wire1(weak, core, |ui, core, i: i32| {
        remove_entry(ui, core, List::Denied, i);
    }));
}

/// 重新载入最新安全配置（进入页面/点击刷新）
pub fn reload(ui: &AppWindow, core: &SharedCore) {
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        ui.global::<SecurityState>()
            .set_error("未连接 fftpd，无法载入安全配置".into());
        return;
    };
    ui.global::<SecurityState>().set_busy(true);
    dispatch(ui.as_weak(), core, load_security(conn), on_loaded);
}

/// `GetConfig` 响应：载入安全配置
fn on_loaded(ui: &AppWindow, core: &SharedCore, result: Result<SecurityConfig, IpcError>) {
    let state = ui.global::<SecurityState>();
    state.set_busy(false);
    match result {
        Ok(cfg) => {
            load_props(ui, &cfg);
            state.set_error("".into());
        }
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 配置写入页面属性（名单重建模型，缓冲同步默认值）
fn load_props(ui: &AppWindow, cfg: &SecurityConfig) {
    let state = ui.global::<SecurityState>();
    state.set_allowed(ModelRc::from(Rc::new(VecModel::from(
        cfg.allowed_ips.iter().map(|e| SharedString::from(e.as_str())).collect::<Vec<_>>(),
    ))));
    state.set_denied(ModelRc::from(Rc::new(VecModel::from(
        cfg.denied_ips.iter().map(|e| SharedString::from(e.as_str())).collect::<Vec<_>>(),
    ))));
    state.set_max_conn(cfg.max_connections.to_string().into());
    state.set_max_conn_per_ip(cfg.max_connections_per_ip.to_string().into());
    state.set_f2b_enabled(cfg.fail2ban_enabled);
    state.set_f2b_threshold(cfg.fail2ban_threshold.to_string().into());
    state.set_f2b_ban(cfg.fail2ban_ban_time.to_string().into());
    state.set_max_login(cfg.max_login_attempts.to_string().into());
    state.set_allow_symlinks(cfg.allow_symlinks);
    state.set_allowed_input("".into());
    state.set_denied_input("".into());
}

/// 名单模型 → 字符串向量
fn model_strings(model: &ModelRc<SharedString>) -> Vec<String> {
    (0..model.row_count())
        .filter_map(|i| model.row_data(i).map(|s| s.to_string()))
        .collect()
}

/// 解析数值缓冲并组装 [`SecurityConfig`]（布尔与名单取自 `base`）
fn with_parsed_buffers(
    base: &SecurityConfig,
    max_connections: &str,
    max_connections_per_ip: &str,
    fail2ban_threshold: &str,
    fail2ban_ban_time: &str,
    max_login_attempts: &str,
) -> Result<SecurityConfig, String> {
    let mut cfg = base.clone();
    cfg.max_connections = parse_num(max_connections, "最大连接数")?;
    cfg.max_connections_per_ip = parse_num(max_connections_per_ip, "单 IP 最大连接数")?;
    cfg.fail2ban_threshold = parse_num(fail2ban_threshold, "fail2ban 阈值")?;
    cfg.fail2ban_ban_time = parse_num(fail2ban_ban_time, "fail2ban 封禁时长")?;
    cfg.max_login_attempts = parse_num(max_login_attempts, "最大登录尝试次数")?;
    Ok(cfg)
}

/// 保存：读回页面属性 → 解析校验 → 读-改-写提交
fn on_save(ui: &AppWindow, core: &SharedCore) {
    let state = ui.global::<SecurityState>();
    let base = SecurityConfig {
        allowed_ips: model_strings(&state.get_allowed()),
        denied_ips: model_strings(&state.get_denied()),
        fail2ban_enabled: state.get_f2b_enabled(),
        allow_symlinks: state.get_allow_symlinks(),
        ..SecurityConfig::default()
    };
    let cfg = match with_parsed_buffers(
        &base,
        state.get_max_conn().as_ref(),
        state.get_max_conn_per_ip().as_ref(),
        state.get_f2b_threshold().as_ref(),
        state.get_f2b_ban().as_ref(),
        state.get_max_login().as_ref(),
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            state.set_error(e.into());
            return;
        }
    };
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        state.set_error("未连接 fftpd，无法保存".into());
        return;
    };
    state.set_busy(true);
    state.set_error("".into());
    state.set_info("".into());
    dispatch(ui.as_weak(), core, save_security(conn, cfg), on_saved);
}

/// `SaveConfig` 响应：以服务端规范化后的内容刷新表单
fn on_saved(ui: &AppWindow, core: &SharedCore, result: Result<String, IpcError>) {
    let state = ui.global::<SecurityState>();
    state.set_busy(false);
    match result {
        Ok(content) => match toml::from_str::<Config>(&content) {
            Ok(config) => {
                load_props(ui, &config.security);
                state.set_error("".into());
                state.set_info("安全配置已保存".into());
            }
            Err(e) => state.set_error(format!("配置解析失败：{e}").into()),
        },
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 记录审计日志（示例操作，details 拼接当前页面值）
fn on_audit(ui: &AppWindow, core: &SharedCore) {
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        ui.global::<SecurityState>()
            .set_error("未连接 fftpd，无法记录审计日志".into());
        return;
    };
    let state = ui.global::<SecurityState>();
    let details = format!(
        "允许名单 {} 项 / 拒绝名单 {} 项，fail2ban={}，最大连接数={}",
        state.get_allowed().row_count(),
        state.get_denied().row_count(),
        state.get_f2b_enabled(),
        state.get_max_conn()
    );
    state.set_busy(true);
    dispatch(ui.as_weak(), core, write_audit(conn, details), on_audited);
}

/// `WriteAuditLog` 响应
fn on_audited(ui: &AppWindow, core: &SharedCore, result: Result<(), IpcError>) {
    let state = ui.global::<SecurityState>();
    state.set_busy(false);
    match result {
        Ok(()) => {
            state.set_error("".into());
            state.set_info("审计日志已记录".into());
        }
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 名单类别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum List {
    /// 允许名单
    Allowed,
    /// 拒绝名单
    Denied,
}

/// 向名单添加输入框中的条目（回车或“添加”按钮触发）
fn add_entry(ui: &AppWindow, list: List) {
    let state = ui.global::<SecurityState>();
    let (input, model) = match list {
        List::Allowed => (state.get_allowed_input(), state.get_allowed()),
        List::Denied => (state.get_denied_input(), state.get_denied()),
    };
    let entry = input.trim().to_owned();
    if entry.is_empty() {
        return;
    }
    let Some(vec) = model.as_any().downcast_ref::<VecModel<SharedString>>() else {
        return;
    };
    vec.push(entry.into());
    match list {
        List::Allowed => state.set_allowed_input("".into()),
        List::Denied => state.set_denied_input("".into()),
    }
    state.set_info("".into());
}

fn add_allowed(ui: &AppWindow, _core: &SharedCore) {
    add_entry(ui, List::Allowed);
}

fn add_denied(ui: &AppWindow, _core: &SharedCore) {
    add_entry(ui, List::Denied);
}

/// 删除名单项（行内“删除”按钮，删除最后一条后由 UI 显示“（空）”）
fn remove_entry(ui: &AppWindow, _core: &SharedCore, list: List, index: i32) {
    let state = ui.global::<SecurityState>();
    let model = match list {
        List::Allowed => state.get_allowed(),
        List::Denied => state.get_denied(),
    };
    let Some(vec) = model.as_any().downcast_ref::<VecModel<SharedString>>() else {
        return;
    };
    let index = row_index(index);
    if index < vec.row_count() {
        vec.remove(index);
        state.set_info("".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_parsed_buffers_parses_numerics() {
        let base = SecurityConfig {
            fail2ban_enabled: true,
            ..SecurityConfig::default()
        };
        let cfg = with_parsed_buffers(&base, "200", "10", "5", "3600", "5").unwrap();
        assert_eq!(cfg.max_connections, 200);
        assert_eq!(cfg.max_connections_per_ip, 10);
        assert!(cfg.fail2ban_enabled);
        assert_eq!(cfg.fail2ban_threshold, 5);
        assert_eq!(cfg.fail2ban_ban_time, 3600);
        assert_eq!(cfg.max_login_attempts, 5);

        assert!(with_parsed_buffers(&base, "abc", "10", "5", "3600", "5").is_err());
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

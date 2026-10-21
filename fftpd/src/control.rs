//! IPC 控制面：[`ControlHandler`] + [`Handler`] 命令分发
//!
//! 覆盖 `fftp_ipc::protocol::Command` 全量命令：
//! 服务生命周期、配置/用户、目录辅助、日志与审计。
//! 命令实现按领域拆到 [`crate::dirs`] / [`crate::logs`]，
//! 服务启停与状态记账在 [`crate::state`]。

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::Value;

use fftp_common::config::Config;
use fftp_common::users::UserManager;
use fftp_ipc::protocol::{Command, ErrorCode, ServiceTarget};
use fftp_ipc::server::{Handler, HandlerError};

use crate::dirs;
use crate::logs;
use crate::state::AppState;

/// IPC 处理器：持有 [`AppState`] 的 `Arc`
#[derive(Clone)]
pub struct ControlHandler {
    state: Arc<AppState>,
}

impl ControlHandler {
    #[must_use]
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl Handler for ControlHandler {
    async fn handle(&self, cmd: Command) -> Result<Value, HandlerError> {
        match cmd {
            // ---- 服务生命周期 ----
            Command::GetStatus => self.status().await,
            Command::StartService { which } => self.start_service(which).await,
            Command::StopService { which } => self.stop_service(which).await,
            Command::RestartService { which } => self.restart_service(which).await,
            Command::Shutdown => {
                self.state.request_shutdown();
                Ok(Value::Null)
            }
            // ---- 配置与用户 ----
            Command::GetConfig => self.get_config(),
            Command::SaveConfig { content } => self.save_config(&content).await,
            Command::GetUsers => self.get_users(),
            Command::SaveUsers { content } => self.save_users(&content),
            Command::GetInitialState => self.initial_state().await,
            // ---- 目录辅助 ----
            Command::EnsureUserDirectories => dirs::ensure_user_directories(&self.state),
            Command::CreateUserDirectory { path } => dirs::create_user_directory(&path),
            Command::SetupDirectoryPermissions { path } => dirs::setup_directory_permissions(&path),
            // ---- 日志 ----
            Command::GetRecentLogs { count } => Ok(logs::recent_logs(&self.state, count)),
            Command::SubscribeLogs { .. } | Command::UnsubscribeLogs => {
                // 由 fftp_ipc::server 在连接层处理，不会派发到这里
                Err(HandlerError::internal("订阅命令应由 IPC 服务层处理"))
            }
            Command::GetLogFiles => Ok(logs::log_files(&self.state)),
            Command::GetLogFileContent { path, count } => {
                logs::log_file_content(&self.state, &path, count)
            }
            Command::GetFileOpLogFiles => Ok(logs::file_op_log_files(&self.state)),
            Command::GetFileOpLogContent { path, count } => {
                logs::file_op_log_content(&self.state, &path, count)
            }
            Command::SaveLogConfig {
                log_dir,
                log_level,
                max_log_size,
                max_log_files,
                enable_gui_logging,
            } => logs::save_log_config(
                &self.state,
                log_dir,
                log_level,
                max_log_size,
                max_log_files,
                enable_gui_logging,
            ),
            Command::WriteAuditLog {
                user,
                action,
                target,
                details,
            } => Ok(logs::write_audit_log(
                &self.state, &user, &action, &target, &details,
            )),
        }
    }
}

impl ControlHandler {
    /// 运行状态（与 fftp-gui `ServerStatus` 字段一一对应）
    async fn status(&self) -> Result<Value, HandlerError> {
        let (ftp_running, sftp_running) = self.state.service_status().await;
        Ok(serde_json::json!({
            "ftp_running": ftp_running,
            "sftp_running": sftp_running,
            "version": env!("CARGO_PKG_VERSION"),
            "config_path": fftp_common::paths::config_path().display().to_string(),
            "users_path": self.state.users_path.display().to_string(),
            "endpoint": fftp_ipc::transport::endpoint_display(),
        }))
    }

    async fn start_service(&self, which: ServiceTarget) -> Result<Value, HandlerError> {
        self.state
            .start_service(which)
            .await
            .map_err(|e| HandlerError::new(ErrorCode::Io, e))?;
        let (ftp_running, sftp_running) = self.state.service_status().await;
        Ok(serde_json::json!({ "ftp_running": ftp_running, "sftp_running": sftp_running }))
    }

    async fn stop_service(&self, which: ServiceTarget) -> Result<Value, HandlerError> {
        self.state
            .stop_service(which)
            .await
            .map_err(HandlerError::internal)?;
        let (ftp_running, sftp_running) = self.state.service_status().await;
        Ok(serde_json::json!({ "ftp_running": ftp_running, "sftp_running": sftp_running }))
    }

    async fn restart_service(&self, which: ServiceTarget) -> Result<Value, HandlerError> {
        self.state
            .restart_service(which)
            .await
            .map_err(|e| HandlerError::new(ErrorCode::Io, e))?;
        let (ftp_running, sftp_running) = self.state.service_status().await;
        Ok(serde_json::json!({ "ftp_running": ftp_running, "sftp_running": sftp_running }))
    }

    async fn initial_state(&self) -> Result<Value, HandlerError> {
        let (ftp_running, sftp_running) = self.state.service_status().await;
        let config = self.state.current_config();
        let config_toml =
            toml::to_string_pretty(&config).map_err(|e| HandlerError::internal(e.to_string()))?;
        let users = read_users_content(&self.state.users_path)?;
        Ok(serde_json::json!({
            "config": config_toml,
            "users": users,
            "ftp_running": ftp_running,
            "sftp_running": sftp_running,
        }))
    }

    fn get_config(&self) -> Result<Value, HandlerError> {
        let config = self.state.current_config();
        let content =
            toml::to_string_pretty(&config).map_err(|e| HandlerError::internal(e.to_string()))?;
        Ok(serde_json::json!({ "content": content }))
    }

    /// 保存配置：校验 → 落盘 → 应用变更（日志参数热更新 + 在跑服务重启）
    async fn save_config(&self, content: &str) -> Result<Value, HandlerError> {
        // 校验失败不落盘；成功时返回规范化后的配置内容
        let parsed: Config = toml::from_str(content)
            .map_err(|e| HandlerError::validation(format!("配置 TOML 解析失败: {e}")))?;
        parsed
            .validate()
            .map_err(|e| HandlerError::validation(e.to_string()))?;

        let path = fftp_common::paths::config_path();
        parsed
            .save(&path)
            .map_err(|e| HandlerError::internal(format!("配置落盘失败: {e:#}")))?;

        let normalized =
            toml::to_string_pretty(&parsed).map_err(|e| HandlerError::internal(e.to_string()))?;

        // 热重载：配置句柄更新（日志参数同步生效）→ 在跑协议服务 stop/start
        self.state.store_config(parsed.clone());
        if let Err(e) = logs::apply_logging_config(&self.state.logging, &parsed.logging) {
            tracing::error!("日志参数应用失败: {}", e.message);
        }
        self.state.reload_services().await;

        Ok(serde_json::json!({ "content": normalized }))
    }

    fn get_users(&self) -> Result<Value, HandlerError> {
        let content = read_users_content(&self.state.users_path)?;
        Ok(serde_json::json!({ "content": content }))
    }

    /// 保存用户库：校验 → 落盘 → 共享 [`UserManager`] 热重载
    fn save_users(&self, content: &str) -> Result<Value, HandlerError> {
        // 用共享类型解析校验，非法内容不落盘
        let manager: UserManager = serde_json::from_str(content)
            .map_err(|e| HandlerError::validation(format!("用户 JSON 解析失败: {e}")))?;
        manager
            .save(&self.state.users_path)
            .map_err(|e| HandlerError::internal(format!("用户库落盘失败: {e:#}")))?;

        // 热重载：协议服务持同一共享句柄，立即按新用户生效
        self.state
            .users
            .lock()
            .unwrap()
            .reload(&self.state.users_path)
            .map_err(|e| HandlerError::internal(format!("用户库热重载失败: {e:#}")))?;

        Ok(serde_json::json!({ "content": content }))
    }
}

/// users.json 原文；文件不存在时返回空库的序列化形态
fn read_users_content(path: &Path) -> Result<String, HandlerError> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::to_string_pretty(
            &UserManager::new(),
        )
        .map_err(|e| HandlerError::internal(e.to_string()))?),
        Err(e) => Err(HandlerError::internal(format!(
            "读取用户库失败 {}: {e}",
            path.display()
        ))),
    }
}

/// 供 main 启动时加载配置
///
/// # Errors
/// 配置读取/解析/校验失败时返回错误
pub fn load_config() -> Result<Config> {
    let path = fftp_common::paths::config_path();
    let config = Config::load(&path).with_context(|| format!("加载配置失败: {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

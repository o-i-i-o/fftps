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
use fftp_common::sync::MutexExt;
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
            Command::GetUsers => self.get_users().await,
            Command::SaveUsers { content } => self.save_users(&content).await,
            Command::GetInitialState => self.initial_state().await,
            // ---- 目录辅助（同步文件系统操作移入阻塞线程） ----
            Command::EnsureUserDirectories => {
                self.run_blocking(dirs::ensure_user_directories).await
            }
            Command::CreateUserDirectory { path } => {
                self.run_blocking(move |_| dirs::create_user_directory(&path))
                    .await
            }
            Command::SetupDirectoryPermissions { path } => {
                self.run_blocking(move |_| dirs::setup_directory_permissions(&path))
                    .await
            }
            // ---- 日志 ----
            Command::GetRecentLogs { count } => Ok(logs::recent_logs(&self.state, count)),
            Command::GetRecentFileOps { count } => Ok(logs::recent_file_ops(&self.state, count)),
            Command::SubscribeLogs { .. }
            | Command::UnsubscribeLogs
            | Command::SubscribeFileOps { .. }
            | Command::UnsubscribeFileOps => {
                // 由 fftp_ipc::server 在连接层处理，不会派发到这里
                Err(HandlerError::internal("订阅命令应由 IPC 服务层处理"))
            }
            Command::GetLogFiles => self.run_blocking(|state| Ok(logs::log_files(state))).await,
            Command::GetLogFileContent { path, count } => {
                self.run_blocking(move |state| logs::log_file_content(state, &path, count))
                    .await
            }
            Command::GetFileOpLogFiles => {
                self.run_blocking(|state| Ok(logs::file_op_log_files(state)))
                    .await
            }
            Command::GetFileOpLogContent { path, count } => {
                self.run_blocking(move |state| logs::file_op_log_content(state, &path, count))
                    .await
            }
            Command::SaveLogConfig {
                log_dir,
                log_level,
                max_log_size,
                max_log_files,
                enable_gui_logging,
            } => {
                self.run_blocking(move |state| {
                    logs::save_log_config(
                        state,
                        log_dir,
                        log_level,
                        max_log_size,
                        max_log_files,
                        enable_gui_logging,
                    )
                })
                .await
            }
            Command::WriteAuditLog {
                user,
                action,
                target,
                details,
            } => {
                self.run_blocking(move |state| {
                    Ok(logs::write_audit_log(
                        state, &user, &action, &target, &details,
                    ))
                })
                .await
            }
            Command::WriteFileOpLog {
                username,
                operation,
                file_path,
                details,
            } => {
                self.run_blocking(move |state| {
                    Ok(logs::write_file_op_log(
                        state, &username, &operation, &file_path, &details,
                    ))
                })
                .await
            }
        }
    }
}

impl ControlHandler {
    /// 在阻塞线程中执行同步文件系统操作，避免占用 tokio worker
    async fn run_blocking<T, F>(&self, f: F) -> Result<T, HandlerError>
    where
        T: Send + 'static,
        F: FnOnce(&AppState) -> Result<T, HandlerError> + Send + 'static,
    {
        let state = Arc::clone(&self.state);
        match tokio::task::spawn_blocking(move || f(&state)).await {
            Ok(result) => result,
            Err(e) => Err(HandlerError::internal(format!("阻塞任务执行失败: {e}"))),
        }
    }

    /// 运行状态（与 fftp-http `ServerStatus` 字段一一对应）
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
        let users = self
            .run_blocking(|state| read_users_content(&state.users_path))
            .await?;
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
        let previous = self.state.current_config();
        let to_save = parsed.clone();
        let (path, normalized) = self
            .run_blocking(move |_| {
                to_save
                    .save(&path)
                    .map_err(|e| HandlerError::internal(format!("配置落盘失败: {e:#}")))?;
                let normalized = toml::to_string_pretty(&to_save)
                    .map_err(|e| HandlerError::internal(e.to_string()))?;
                Ok((path, normalized))
            })
            .await?;

        // 热重载：配置句柄更新（日志参数同步生效）→ 在跑协议服务 stop/start
        self.state.store_config(parsed.clone());
        // 日志目录创建/级别切换为同步文件 IO，移入阻塞线程避免占用异步 worker
        let new_logging = parsed.logging.clone();
        match self
            .run_blocking(move |state| {
                logs::apply_logging_config(&state.logging, &new_logging)
                    .map_err(|e| HandlerError::internal(e.message))
            })
            .await
        {
            Ok(()) => {}
            Err(e) => tracing::error!("日志参数应用失败: {}", e.message),
        }
        if let Err(e) = self.state.reload_services().await {
            // 新配置无法让服务重新监听（端口占用等）：回滚配置并尽量按旧配置恢复
            tracing::error!("配置热重载失败，回滚到旧配置: {e}");
            self.state.store_config(previous.clone());
            let prev_save = previous.clone();
            let rollback_path = path.clone();
            if let Err(se) = self
                .run_blocking(move |_| {
                    prev_save
                        .save(&rollback_path)
                        .map_err(|e| HandlerError::internal(format!("{e:#}")))
                })
                .await
            {
                tracing::error!("回滚配置文件落盘失败: {}", se.message);
            }
            let prev_logging = previous.logging.clone();
            match self
                .run_blocking(move |state| {
                    logs::apply_logging_config(&state.logging, &prev_logging)
                        .map_err(|e| HandlerError::internal(e.message))
                })
                .await
            {
                Ok(()) => {}
                Err(le) => tracing::error!("回滚日志参数失败: {}", le.message),
            }
            if let Err(re) = self.state.reload_services().await {
                tracing::error!("按旧配置恢复服务失败: {re}");
            }
            return Err(HandlerError::internal(format!(
                "新配置无法使服务重新监听，已回滚: {e}"
            )));
        }

        Ok(serde_json::json!({ "content": normalized }))
    }

    async fn get_users(&self) -> Result<Value, HandlerError> {
        let content = self
            .run_blocking(|state| read_users_content(&state.users_path))
            .await?;
        Ok(serde_json::json!({ "content": content }))
    }

    /// 保存用户库：校验 → 落盘 → 共享 [`UserManager`] 热重载
    async fn save_users(&self, content: &str) -> Result<Value, HandlerError> {
        // 用共享类型解析校验，非法内容不落盘
        let manager: UserManager = serde_json::from_str(content)
            .map_err(|e| HandlerError::validation(format!("用户 JSON 解析失败: {e}")))?;
        let content_owned = content.to_string();
        self.run_blocking(move |state| {
            manager
                .save(&state.users_path)
                .map_err(|e| HandlerError::internal(format!("用户库落盘失败: {e:#}")))?;

            // 热重载：协议服务持同一共享句柄，立即按新用户生效
            state
                .users
                .lock_recover()
                .reload(&state.users_path)
                .map_err(|e| HandlerError::internal(format!("用户库热重载失败: {e:#}")))?;

            Ok(serde_json::json!({ "content": content_owned }))
        })
        .await
    }
}

/// users.json 原文；文件不存在时返回空库的序列化形态
fn read_users_content(path: &Path) -> Result<String, HandlerError> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(serde_json::to_string_pretty(&UserManager::new())
                .map_err(|e| HandlerError::internal(e.to_string()))?)
        }
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
    let config =
        Config::load(&path).with_context(|| format!("加载配置失败: {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

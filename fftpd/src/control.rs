//! IPC 控制面：[`AppState`] + [`Handler`] 实现
//!
//! 阶段 1 覆盖：状态/配置/用户/关停。目录辅助、日志、服务生命周期
//! 在阶段 2 随服务端功能迁移补齐。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::sync::{watch, RwLock};

use fftp_common::config::Config;
use fftp_ipc::protocol::Command;
use fftp_ipc::server::{Handler, HandlerError};

/// 守护进程共享状态（阶段 2 追加用户库/日志/防护等句柄）
pub struct AppState {
    pub config: RwLock<Config>,
    pub users_path: PathBuf,
    pub ftp_running: AtomicBool,
    pub sftp_running: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
}

impl AppState {
    #[must_use]
    pub fn new(config: Config, shutdown_tx: watch::Sender<bool>) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(config),
            users_path: fftp_common::paths::users_path(),
            ftp_running: AtomicBool::new(false),
            sftp_running: AtomicBool::new(false),
            shutdown_tx,
        })
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

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
    fn handle(
        &self,
        cmd: Command,
    ) -> impl std::future::Future<Output = Result<Value, HandlerError>> + Send {
        async move {
            match cmd {
                Command::GetStatus => self.status(),
                Command::GetInitialState => self.initial_state().await,
                Command::GetConfig => self.get_config().await,
                Command::SaveConfig { content } => self.save_config(&content).await,
                Command::GetUsers => self.get_users(),
                Command::SaveUsers { content } => self.save_users(&content),
                Command::Shutdown => {
                    self.state.request_shutdown();
                    Ok(Value::Null)
                }
                other => Err(HandlerError::internal(format!(
                    "命令尚未实现: {other:?}（阶段 2 随功能迁移补齐）"
                ))),
            }
        }
    }
}

impl ControlHandler {
    fn status(&self) -> Result<Value, HandlerError> {
        Ok(serde_json::json!({
            "ftp_running": self.state.ftp_running.load(Ordering::Relaxed),
            "sftp_running": self.state.sftp_running.load(Ordering::Relaxed),
            "version": env!("CARGO_PKG_VERSION"),
            "config_path": fftp_common::paths::config_path().display().to_string(),
            "users_path": self.state.users_path.display().to_string(),
            "endpoint": fftp_ipc::transport::endpoint_display(),
        }))
    }

    async fn initial_state(&self) -> Result<Value, HandlerError> {
        let config = self.state.config.read().await;
        let config_toml =
            toml::to_string_pretty(&*config).map_err(|e| HandlerError::internal(e.to_string()))?;
        let users = read_users_content(&self.state.users_path)?;
        Ok(serde_json::json!({
            "config": config_toml,
            "users": users,
            "ftp_running": self.state.ftp_running.load(Ordering::Relaxed),
            "sftp_running": self.state.sftp_running.load(Ordering::Relaxed),
        }))
    }

    async fn get_config(&self) -> Result<Value, HandlerError> {
        let config = self.state.config.read().await;
        let content =
            toml::to_string_pretty(&*config).map_err(|e| HandlerError::internal(e.to_string()))?;
        Ok(serde_json::json!({ "content": content }))
    }

    async fn save_config(&self, content: &str) -> Result<Value, HandlerError> {
        // 校验失败不落盘；成功时返回规范化后的配置内容
        let parsed: Config = toml::from_str(content).map_err(|e| {
            HandlerError::validation(format!("配置 TOML 解析失败: {e}"))
        })?;
        parsed
            .validate()
            .map_err(|e| HandlerError::validation(e.to_string()))?;

        let path = fftp_common::paths::config_path();
        parsed
            .save(&path)
            .map_err(|e| HandlerError::internal(format!("配置落盘失败: {e:#}")))?;

        let normalized =
            toml::to_string_pretty(&parsed).map_err(|e| HandlerError::internal(e.to_string()))?;
        *self.state.config.write().await = parsed;
        Ok(serde_json::json!({ "content": normalized }))
    }

    fn get_users(&self) -> Result<Value, HandlerError> {
        let content = read_users_content(&self.state.users_path)?;
        Ok(serde_json::json!({ "content": content }))
    }

    fn save_users(&self, content: &str) -> Result<Value, HandlerError> {
        // 用共享类型解析校验，非法内容不落盘
        let manager: fftp_common::users::UserManager = serde_json::from_str(content)
            .map_err(|e| HandlerError::validation(format!("用户 JSON 解析失败: {e}")))?;
        manager
            .save(&self.state.users_path)
            .map_err(|e| HandlerError::internal(format!("用户库落盘失败: {e:#}")))?;
        Ok(serde_json::json!({ "content": content }))
    }
}

/// users.json 原文；文件不存在时返回空库的序列化形态
fn read_users_content(path: &PathBuf) -> Result<String, HandlerError> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::to_string_pretty(
            &fftp_common::users::UserManager::new(),
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

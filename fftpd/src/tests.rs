//! IPC 命令分发集成测试
//!
//! 通过 [`ControlHandler::handle`] 直接驱动全量命令面，覆盖：
//! 配置/用户保存与校验、日志读取防逃逸、日志参数热更新、服务启停状态流转、
//! 日志实时推送、审计写入与目录辅助。
//!
//! 环境变量（`FFTPD_CONFIG_DIR`/`FFTPD_STATE_DIR`）为进程级共享，
//! 统一经 [`ENV_LOCK`] 串行化；日志用 `Logging::new`（不安装全局 subscriber）。

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::{broadcast, watch};

use fftp_common::config::{Config, LoggingConfig};
use fftp_common::logging::{LogEntry, Logging};
use fftp_common::users::UserManager;
use fftp_ipc::protocol::{Command, ErrorCode, Event, ServiceTarget};
use fftp_ipc::server::{Handler, HandlerError};

use crate::control::ControlHandler;
use crate::logs;
use crate::state::AppState;

/// 环境变量互斥锁：`std::env::set_var` 影响整个进程，测试须串行执行
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 测试环境：临时目录（配置/状态/日志隔离）+ 已装配的命令处理器
struct TestEnv {
    /// 临时目录存活到测试结束（并持有环境变量互斥锁）
    _guard: MutexGuard<'static, ()>,
    dir: tempfile::TempDir,
    handler: ControlHandler,
    state: Arc<AppState>,
    shutdown_rx: watch::Receiver<bool>,
}

impl TestEnv {
    /// 组装测试环境：环境变量指向临时目录，服务端口用 0（临时端口）
    fn new() -> Self {
        let guard = env_lock();
        let dir = tempfile::tempdir().expect("创建临时目录");

        // SAFETY: 持有 ENV_LOCK 期间独占写入进程环境变量，测试串行执行
        unsafe {
            std::env::set_var("FFTPD_CONFIG_DIR", dir.path());
            std::env::set_var("FFTPD_STATE_DIR", dir.path());
        }

        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("创建日志目录");

        let mut config = Config::default();
        config.ftp.bind_ip = "127.0.0.1".to_string();
        config.ftp.port = 0;
        config.ftp.pooled_listener_mode = false;
        config.sftp.bind_ip = "127.0.0.1".to_string();
        config.sftp.port = 0;
        config.logging = LoggingConfig {
            log_dir: log_dir.to_string_lossy().into_owned(),
            log_level: "info".to_string(),
            max_log_files: 5,
            max_log_size: 1024 * 1024,
            enable_json: false,
            enable_gui_logging: true,
        };
        config
            .save(&fftp_common::paths::config_path())
            .expect("落盘测试配置");

        let logging = Arc::new(Logging::new(&config.logging));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let state = AppState::new(config, UserManager::new(), logging, shutdown_tx);
        let handler = ControlHandler::new(Arc::clone(&state));

        Self {
            _guard: guard,
            dir,
            handler,
            state,
            shutdown_rx,
        }
    }

    /// 调用命令并取响应数据（失败时返回 [`HandlerError`]）
    async fn call(&self, cmd: Command) -> Result<Value, HandlerError> {
        self.handler.handle(cmd).await
    }
}

/// 构造单用户 users.json 内容（直接反序列化，绕过 Argon2 口令哈希）
fn sample_users_json(home: &Path) -> String {
    json!({
        "users": {
            "alice": {
                "username": "alice",
                "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
                "home_dir": home.display().to_string(),
                "permissions": {
                    "can_read": true,
                    "can_write": true,
                    "can_delete": true,
                    "can_list": true,
                    "can_mkdir": true,
                    "can_rmdir": true,
                    "can_rename": true,
                    "can_append": true,
                    "quota_mb": null,
                    "speed_limit_kbps": null
                },
                "created_at": "2026-10-21T00:00:00Z",
                "last_login": null,
                "enabled": true,
                "is_admin": false
            }
        }
    })
    .to_string()
}

fn sample_log_entry(message: &str) -> LogEntry {
    LogEntry {
        timestamp: "2026-10-21T10:00:00+08:00".to_string(),
        level: "INFO".to_string(),
        source: "test".to_string(),
        message: message.to_string(),
        client_ip: String::new(),
        username: String::new(),
        action: String::new(),
    }
}

// ---- 状态与初始加载 ----

#[tokio::test]
async fn get_status_and_initial_state_shapes() {
    let env = TestEnv::new();

    let data = env.call(Command::GetStatus).await.expect("GetStatus");
    for key in [
        "ftp_running",
        "sftp_running",
        "version",
        "config_path",
        "users_path",
        "endpoint",
    ] {
        assert!(data.get(key).is_some(), "GetStatus 缺少字段 {key}");
    }
    assert_eq!(data["ftp_running"], json!(false), "初始不应在运行");
    assert_eq!(data["sftp_running"], json!(false));

    let data = env
        .call(Command::GetInitialState)
        .await
        .expect("GetInitialState");
    assert!(
        data["config"].as_str().is_some_and(|s| s.contains("welcome_message")),
        "InitialState.config 应为 TOML 原文"
    );
    assert!(data["users"].as_str().is_some(), "InitialState.users 应为 JSON 原文");

    let data = env.call(Command::GetConfig).await.expect("GetConfig");
    assert!(data["content"].as_str().is_some_and(|s| s.contains("welcome_message")));
}

// ---- 配置保存与校验 ----

#[tokio::test]
async fn save_config_rejects_invalid_content_without_write() {
    let env = TestEnv::new();
    let config_path = fftp_common::paths::config_path();
    let before = std::fs::read_to_string(&config_path).expect("读取测试配置");

    // 非法 TOML：拒绝且不落盘
    let err = env
        .call(Command::SaveConfig {
            content: "not a valid toml {{{{".to_string(),
        })
        .await
        .expect_err("非法 TOML 应被拒绝");
    assert_eq!(err.code, ErrorCode::Validation);

    // 语义非法：匿名访问开启但未配置主目录
    let mut bad = env.state.current_config();
    bad.ftp.allow_anonymous = true;
    bad.ftp.anonymous_home = String::new();
    let err = env
        .call(Command::SaveConfig {
            content: toml::to_string_pretty(&bad).expect("序列化"),
        })
        .await
        .expect_err("语义非法配置应被拒绝");
    assert_eq!(err.code, ErrorCode::Validation);

    assert_eq!(
        std::fs::read_to_string(&config_path).expect("读取测试配置"),
        before,
        "校验失败不得改写配置文件"
    );
}

#[tokio::test]
async fn save_config_persists_and_applies() {
    let env = TestEnv::new();

    let mut config = env.state.current_config();
    config.ftp.port = 2121;
    config.ftp.welcome_message = "hello-fftpd".to_string();
    let data = env
        .call(Command::SaveConfig {
            content: toml::to_string_pretty(&config).expect("序列化"),
        })
        .await
        .expect("合法配置应保存成功");
    assert!(
        data["content"].as_str().is_some_and(|s| s.contains("hello-fftpd")),
        "应返回规范化后的配置内容"
    );

    // 内存配置热更新 + 落盘生效
    assert_eq!(env.state.current_config().ftp.port, 2121);
    let on_disk: Config = toml::from_str(
        &std::fs::read_to_string(fftp_common::paths::config_path()).expect("读取落盘配置"),
    )
    .expect("落盘配置可解析");
    assert_eq!(on_disk.ftp.port, 2121);
    assert_eq!(on_disk.ftp.welcome_message, "hello-fftpd");
}

// ---- 用户保存与热重载 ----

#[tokio::test]
async fn save_users_rejects_invalid_json() {
    let env = TestEnv::new();
    let users_path = fftp_common::paths::users_path();
    let before = std::fs::read_to_string(&users_path).ok();

    let err = env
        .call(Command::SaveUsers {
            content: "{ not json".to_string(),
        })
        .await
        .expect_err("非法 JSON 应被拒绝");
    assert_eq!(err.code, ErrorCode::Validation);
    assert_eq!(
        std::fs::read_to_string(&users_path).ok(),
        before,
        "校验失败不得改写用户库"
    );
}

#[tokio::test]
async fn save_users_persists_and_hot_reloads() {
    let env = TestEnv::new();
    let home = env.dir.path().join("home-alice");
    std::fs::create_dir_all(&home).expect("创建用户主目录");
    let content = sample_users_json(&home);

    let data = env
        .call(Command::SaveUsers {
            content: content.clone(),
        })
        .await
        .expect("合法用户库应保存成功");
    assert_eq!(data["content"], json!(content), "应原样回显用户库内容");

    assert!(
        fftp_common::paths::users_path().is_file(),
        "用户库应落盘"
    );
    assert!(
        env.state.users.lock().unwrap().get_user("alice").is_some(),
        "共享 UserManager 应热重载到新用户"
    );

    let data = env.call(Command::GetUsers).await.expect("GetUsers");
    assert!(data["content"].as_str().is_some_and(|s| s.contains("alice")));
}

// ---- 日志读取（防逃逸） ----

#[tokio::test]
async fn log_file_reading_blocks_path_escape() {
    let env = TestEnv::new();

    // 日志目录外的文件：拒绝（防逃逸）
    let outside = env.dir.path().join("outside.log");
    std::fs::write(&outside, "x").expect("写入目录外文件");
    let err = env
        .call(Command::GetLogFileContent {
            path: outside.display().to_string(),
            count: 10,
        })
        .await
        .expect_err("目录外路径应被拒绝");
    assert_eq!(err.code, ErrorCode::Validation);

    let err = env
        .call(Command::GetFileOpLogContent {
            path: outside.display().to_string(),
            count: 10,
        })
        .await
        .expect_err("审计日志同样防逃逸");
    assert_eq!(err.code, ErrorCode::Validation);

    // 不存在的文件：NotFound
    let missing = env.dir.path().join("logs").join("missing.log");
    let err = env
        .call(Command::GetLogFileContent {
            path: missing.display().to_string(),
            count: 10,
        })
        .await
        .expect_err("不存在的文件应报 NotFound");
    assert_eq!(err.code, ErrorCode::NotFound);

    // 日志目录内：正常读取
    let inside = env.dir.path().join("logs").join("fftpd.2026-10-21.log");
    std::fs::write(&inside, "2026-10-21T10:00:00+08:00  INFO fftpd: started\n")
        .expect("写入日志文件");
    let data = env
        .call(Command::GetLogFileContent {
            path: inside.display().to_string(),
            count: 10,
        })
        .await
        .expect("目录内文件可读");
    let entries = data["entries"].as_array().expect("entries 数组");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["message"], json!("started"));
}

#[tokio::test]
async fn log_file_lists_and_file_op_content() {
    let env = TestEnv::new();
    let log_dir = env.dir.path().join("logs");

    std::fs::write(log_dir.join("fftpd.2026-10-21.log"), "x").expect("写入程序日志");
    std::fs::write(
        log_dir.join("file-ops.2026-10-21.log"),
        concat!(
            r#"{"timestamp":"t1","fields":{"username":"u1","client_ip":"ip","operation":"UPLOAD","file_path":"/a","file_size":1,"protocol":"FTP","success":true,"message":"ok"}}"#,
            "\n",
        ),
    )
    .expect("写入审计日志");

    let data = env.call(Command::GetLogFiles).await.expect("GetLogFiles");
    let files = data["files"].as_array().expect("files 数组");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["name"], json!("fftpd.2026-10-21"));
    assert!(files[0]["path"].as_str().is_some());

    let data = env
        .call(Command::GetFileOpLogFiles)
        .await
        .expect("GetFileOpLogFiles");
    assert_eq!(data["files"].as_array().expect("files 数组").len(), 1);

    let audit_path = log_dir.join("file-ops.2026-10-21.log");
    let data = env
        .call(Command::GetFileOpLogContent {
            path: audit_path.display().to_string(),
            count: 10,
        })
        .await
        .expect("读取审计日志");
    let entries = data["entries"].as_array().expect("entries 数组");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["operation"], json!("UPLOAD"));
    assert_eq!(entries[0]["file_size"], json!(1));
}

// ---- 最近日志与日志参数热更新 ----

#[tokio::test]
async fn recent_logs_returns_entries_shape() {
    let env = TestEnv::new();
    for i in 0..3 {
        env.state
            .logging
            .log_buffer()
            .push(sample_log_entry(&format!("m{i}")));
    }

    let data = env
        .call(Command::GetRecentLogs { count: 2 })
        .await
        .expect("GetRecentLogs");
    let entries = data["entries"].as_array().expect("entries 数组");
    assert_eq!(entries.len(), 2, "count 应限制条数");
    assert_eq!(entries[1]["message"], json!("m2"), "应保留最新条目");
    for key in [
        "timestamp",
        "level",
        "source",
        "message",
        "client_ip",
        "username",
        "action",
    ] {
        assert!(entries[0].get(key).is_some(), "日志条目缺少字段 {key}");
    }

    // count = 0 → 全部
    let data = env
        .call(Command::GetRecentLogs { count: 0 })
        .await
        .expect("GetRecentLogs");
    assert_eq!(data["entries"].as_array().expect("entries 数组").len(), 3);

    // enable_gui_logging 关闭（经 apply_logging_config 生效）→ 不进缓冲语义，返回空
    let mut config = env.state.current_config();
    config.logging.enable_gui_logging = false;
    env.state.store_config(config.clone());
    logs::apply_logging_config(&env.state.logging, &config.logging).expect("应用日志参数");
    let data = env
        .call(Command::GetRecentLogs { count: 0 })
        .await
        .expect("GetRecentLogs");
    assert_eq!(
        data["entries"].as_array().expect("entries 数组").len(),
        0,
        "关闭 GUI 日志后应返回空 entries"
    );
}

#[tokio::test]
async fn save_log_config_validates_and_applies() {
    let env = TestEnv::new();
    let log_dir = env.dir.path().join("logs").to_string_lossy().into_owned();

    // 非法级别
    let err = env
        .call(Command::SaveLogConfig {
            log_dir: log_dir.clone(),
            log_level: "verbose".to_string(),
            max_log_size: 1024,
            max_log_files: 3,
            enable_gui_logging: true,
        })
        .await
        .expect_err("非法日志级别应被拒绝");
    assert_eq!(err.code, ErrorCode::Validation);

    // max_log_files 不得为 0
    let err = env
        .call(Command::SaveLogConfig {
            log_dir: log_dir.clone(),
            log_level: "info".to_string(),
            max_log_size: 1024,
            max_log_files: 0,
            enable_gui_logging: true,
        })
        .await
        .expect_err("max_log_files=0 应被拒绝");
    assert_eq!(err.code, ErrorCode::Validation);

    // 合法：目录迁移 + 级别/开关热更新
    let new_dir = env.dir.path().join("logs2");
    let data = env
        .call(Command::SaveLogConfig {
            log_dir: new_dir.display().to_string(),
            log_level: "debug".to_string(),
            max_log_size: 2048,
            max_log_files: 7,
            enable_gui_logging: false,
        })
        .await
        .expect("合法日志参数应保存成功");
    assert_eq!(data["log_level"], json!("debug"));
    assert_eq!(data["enable_gui_logging"], json!(false));
    assert!(new_dir.is_dir(), "新日志目录应被创建");

    let live = env.state.logging.live_config();
    assert_eq!(live.log_level, "debug");
    assert!(!live.enable_gui_logging);
    assert_eq!(live.resolved_log_dir(), new_dir);

    // 配置落盘生效
    let on_disk: Config = toml::from_str(
        &std::fs::read_to_string(fftp_common::paths::config_path()).expect("读取落盘配置"),
    )
    .expect("落盘配置可解析");
    assert_eq!(on_disk.logging.log_level, "debug");
    assert_eq!(on_disk.logging.max_log_files, 7);
}

// ---- 日志实时推送与审计 ----

#[tokio::test]
async fn log_forwarder_pushes_events_to_subscribers() {
    let env = TestEnv::new();
    let (events, mut rx) = broadcast::channel::<Event>(16);
    let forward = logs::spawn_log_forwarder(Arc::clone(&env.state.logging), events);

    // 等待转发器完成订阅后再推送
    tokio::time::sleep(Duration::from_millis(100)).await;
    env.state
        .logging
        .log_buffer()
        .push(sample_log_entry("hello-forward"));

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("应在超时前收到日志推送")
        .expect("广播通道未关闭");
    match event {
        Event::Log { entry } => assert_eq!(entry.message, "hello-forward"),
    }
    forward.abort();
}

#[tokio::test]
async fn write_audit_records_to_file_op_buffer() {
    let env = TestEnv::new();

    let data = env
        .call(Command::WriteAuditLog {
            user: "admin".to_string(),
            action: "save_config".to_string(),
            target: "config.toml".to_string(),
            details: "修改端口".to_string(),
        })
        .await
        .expect("WriteAuditLog");
    assert_eq!(data["recorded"], json!(true));

    let recent = env.state.logging.file_op_buffer().recent(10);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].username, "admin");
    assert_eq!(recent[0].operation, "save_config");
    assert_eq!(recent[0].file_path, "config.toml");
    assert_eq!(recent[0].protocol, "GUI");
}

// ---- 服务启停状态流转 ----

#[tokio::test]
async fn service_lifecycle_transitions_running_state() {
    let env = TestEnv::new();

    // 启动 FTP（幂等：重复启动仍成功）
    for _ in 0..2 {
        let data = env
            .call(Command::StartService {
                which: ServiceTarget::Ftp,
            })
            .await
            .expect("启动 FTP");
        assert_eq!(data["ftp_running"], json!(true));
        assert_eq!(data["sftp_running"], json!(false));
    }
    let data = env.call(Command::GetStatus).await.expect("GetStatus");
    assert_eq!(data["ftp_running"], json!(true));

    // 停止 FTP（幂等：重复停止仍成功）
    for _ in 0..2 {
        let data = env
            .call(Command::StopService {
                which: ServiceTarget::Ftp,
            })
            .await
            .expect("停止 FTP");
        assert_eq!(data["ftp_running"], json!(false));
    }

    // 重启 SFTP（未运行时等价于启动）
    let data = env
        .call(Command::RestartService {
            which: ServiceTarget::Sftp,
        })
        .await
        .expect("重启 SFTP");
    assert_eq!(data["sftp_running"], json!(true));

    // 全部启动 → 全部停止
    let data = env
        .call(Command::StartService {
            which: ServiceTarget::All,
        })
        .await
        .expect("启动全部服务");
    assert_eq!(data["ftp_running"], json!(true));
    assert_eq!(data["sftp_running"], json!(true));

    let data = env
        .call(Command::StopService {
            which: ServiceTarget::All,
        })
        .await
        .expect("停止全部服务");
    assert_eq!(data["ftp_running"], json!(false));
    assert_eq!(data["sftp_running"], json!(false));
}

#[tokio::test]
async fn shutdown_signals_process_exit() {
    let env = TestEnv::new();
    assert!(!*env.shutdown_rx.borrow(), "初始不应有退出请求");

    let data = env.call(Command::Shutdown).await.expect("Shutdown");
    assert!(data.is_null());
    assert!(*env.shutdown_rx.borrow(), "Shutdown 应触发退出信号");
}

// ---- 目录辅助 ----

#[tokio::test]
async fn ensure_user_directories_creates_missing_dirs_once() {
    let env = TestEnv::new();
    let home = env.dir.path().join("homes").join("carol");
    *env.state.users.lock().unwrap() =
        serde_json::from_str(&sample_users_json(&home)).expect("解析用户库");

    let data = env
        .call(Command::EnsureUserDirectories)
        .await
        .expect("EnsureUserDirectories");
    let created = data["created"].as_array().expect("created 数组");
    assert!(
        created
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.contains("carol"))),
        "用户主目录应被创建: {created:?}"
    );
    assert!(home.is_dir(), "用户主目录应存在");
    assert!(fftp_common::paths::keys_dir().is_dir(), "密钥目录应存在");

    // 幂等：再次调用无新建
    let data = env
        .call(Command::EnsureUserDirectories)
        .await
        .expect("EnsureUserDirectories");
    assert_eq!(
        data["created"].as_array().expect("created 数组").len(),
        0,
        "目录已存在时不应重复创建"
    );
}

#[tokio::test]
async fn directory_helpers_validate_and_set_permissions() {
    let env = TestEnv::new();

    // 空路径校验
    let err = env
        .call(Command::CreateUserDirectory {
            path: "   ".to_string(),
        })
        .await
        .expect_err("空路径应被拒绝");
    assert_eq!(err.code, ErrorCode::Validation);
    let err = env
        .call(Command::SetupDirectoryPermissions {
            path: String::new(),
        })
        .await
        .expect_err("空路径应被拒绝");
    assert_eq!(err.code, ErrorCode::Validation);

    // 创建用户目录（含父目录）
    let user_dir = env.dir.path().join("homes").join("bob");
    let data = env
        .call(Command::CreateUserDirectory {
            path: user_dir.display().to_string(),
        })
        .await
        .expect("CreateUserDirectory");
    assert_eq!(data["path"], json!(user_dir.display().to_string()));
    assert!(user_dir.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&user_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "新建目录应为 0700");
    }

    // 权限设置：不存在 → NotFound；存在 → 返回权限标识
    let err = env
        .call(Command::SetupDirectoryPermissions {
            path: env.dir.path().join("nope").display().to_string(),
        })
        .await
        .expect_err("不存在的目录应报 NotFound");
    assert_eq!(err.code, ErrorCode::NotFound);

    let data = env
        .call(Command::SetupDirectoryPermissions {
            path: user_dir.display().to_string(),
        })
        .await
        .expect("SetupDirectoryPermissions");
    #[cfg(unix)]
    assert_eq!(data["permissions"], json!("0700"));
    #[cfg(windows)]
    assert_eq!(data["permissions"], json!("default"));
}

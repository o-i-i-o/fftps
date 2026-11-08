//! 系统服务管理：fftpd 的安装/卸载/开机自启/状态
//!
//! Linux 走 `systemctl --user`（用户态服务，无需 root），Windows 走 `sc.exe`
//! （注册/删除 SCM 服务，需要管理员权限）。所有命令固定参数、不拼接用户输入，
//! 阻塞进程调用经 `spawn_blocking` 挪出异步运行时。
//!
//! 本模块只管理后端 `fftpd`；`fftp-http` 本身由桌面入口按需启动/由 SCM 托管，
//! 页面上的「关闭 Web 服务」走空闲模块的自身关停路径。

use serde::Serialize;

/// 系统服务管理动作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 安装（注册 + 启动 + 开机自启）
    Install,
    /// 卸载（停止 + 删除/禁用）
    Uninstall,
    /// 开启开机自启
    AutostartOn,
    /// 关闭开机自启
    AutostartOff,
}

impl Action {
    /// 解析 API 路径参数
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "install" => Some(Self::Install),
            "uninstall" => Some(Self::Uninstall),
            "autostart-on" => Some(Self::AutostartOn),
            "autostart-off" => Some(Self::AutostartOff),
            _ => None,
        }
    }

    /// 成功提示
    #[must_use]
    pub fn ok_text(self) -> &'static str {
        match self {
            Self::Install => "系统服务已安装并启动",
            Self::Uninstall => "系统服务已卸载",
            Self::AutostartOn => "已开启开机自启",
            Self::AutostartOff => "已关闭开机自启",
        }
    }
}

/// 服务状态快照（`GET /api/system-service/status`）
#[derive(Debug, Clone, Serialize)]
pub struct ServiceStatus {
    /// 是否已注册（Windows SCM / systemd 用户单元）
    pub installed: bool,
    /// 是否正在运行
    pub running: bool,
    /// 是否开机自启
    pub autostart: bool,
    /// 平台说明
    pub platform: &'static str,
    /// 原始状态摘要（排障用）
    pub detail: String,
}

/// 执行系统服务管理动作，返回命令输出摘要
///
/// # Errors
/// 命令无法执行或返回失败状态时返回错误（含 stderr/stdout 摘要）
pub async fn perform(action: Action) -> Result<String, String> {
    tokio::task::spawn_blocking(move || run_action(action))
        .await
        .map_err(|e| format!("任务执行失败：{e}"))?
}

/// 查询系统服务状态
///
/// # Errors
/// 状态查询命令无法执行时返回错误
pub async fn status() -> Result<ServiceStatus, String> {
    tokio::task::spawn_blocking(query_status)
        .await
        .map_err(|e| format!("任务执行失败：{e}"))?
}

// ---------- Linux（systemd --user） ----------

#[cfg(not(windows))]
fn run_action(action: Action) -> Result<String, String> {
    let args: &[&str] = match action {
        Action::Install => &["--user", "enable", "--now", "fftpd"],
        Action::Uninstall => &["--user", "disable", "--now", "fftpd"],
        Action::AutostartOn => &["--user", "enable", "fftpd"],
        Action::AutostartOff => &["--user", "disable", "fftpd"],
    };
    run_command("systemctl", args)
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)] // 与 Windows 分支保持同一签名
fn query_status() -> Result<ServiceStatus, String> {
    let enabled = run_command_line("systemctl", &["--user", "is-enabled", "fftpd"]).ok();
    let active = run_command_line("systemctl", &["--user", "is-active", "fftpd"]).ok();
    let installed = enabled
        .as_deref()
        .is_some_and(|s| s != "not-found" && !s.is_empty());
    Ok(ServiceStatus {
        installed,
        running: active.as_deref() == Some("active"),
        autostart: enabled.as_deref() == Some("enabled"),
        platform: "Linux systemd --user",
        detail: format!(
            "is-enabled={} is-active={}",
            enabled.as_deref().unwrap_or("未知"),
            active.as_deref().unwrap_or("未知")
        ),
    })
}

// ---------- Windows（sc.exe） ----------

#[cfg(windows)]
fn run_action(action: Action) -> Result<String, String> {
    let bin_path = format!("\"{}\" --service", fftpd_exe_path()?.display());
    match action {
        Action::Install => {
            // 已存在时先清理旧服务，保证 binPath 指向当前安装目录
            let _ = run_command("sc.exe", &["stop", "fftpd"]);
            let _ = run_command("sc.exe", &["delete", "fftpd"]);
            run_command(
                "sc.exe",
                &[
                    "create",
                    "fftpd",
                    "binPath=",
                    &bin_path,
                    "DisplayName=",
                    "fftps FTP/SFTP Server",
                    "start=",
                    "auto",
                ],
            )?;
            run_command("sc.exe", &["start", "fftpd"])
        }
        Action::Uninstall => {
            let _ = run_command("sc.exe", &["stop", "fftpd"]);
            run_command("sc.exe", &["delete", "fftpd"])
        }
        Action::AutostartOn => run_command("sc.exe", &["config", "fftpd", "start=", "auto"]),
        Action::AutostartOff => run_command("sc.exe", &["config", "fftpd", "start=", "demand"]),
    }
}

#[cfg(windows)]
fn query_status() -> Result<ServiceStatus, String> {
    let query = run_command_line("sc.exe", &["query", "fftpd"]).ok();
    let config = run_command_line("sc.exe", &["qc", "fftpd"]).ok();
    let installed = query
        .as_deref()
        .is_some_and(|s| s.contains("SERVICE_NAME: fftpd"));
    Ok(ServiceStatus {
        installed,
        running: query.as_deref().is_some_and(|s| s.contains("RUNNING")),
        autostart: config.as_deref().is_some_and(|s| s.contains("AUTO_START")),
        platform: "Windows SCM",
        detail: query.unwrap_or_else(|| "未安装或查询失败".into()),
    })
}

#[cfg(windows)]
fn fftpd_exe_path() -> Result<std::path::PathBuf, String> {
    let dir = std::env::current_exe()
        .map_err(|e| format!("无法定位程序目录：{e}"))?
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| "无法定位程序目录".to_owned())?;
    Ok(dir.join("fftpd.exe"))
}

// ---------- 命令执行 ----------

/// 执行命令并返回 stdout（成功）/ stderr 或 stdout（失败）
fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = command(program)
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

/// 执行命令并返回首个非空输出行（状态查询不因非零退出码失败）
fn run_command_line(program: &str, args: &[&str]) -> Result<String, String> {
    let output = command(program)
        .args(args)
        .output()
        .map_err(|e| format!("无法执行 {program}：{e}"))?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).into_owned()
    } else {
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let line = text.lines().map(str::trim).find(|s| !s.is_empty());
    Ok(line.unwrap_or("").to_owned())
}

/// 平台命令（Windows 下隐藏控制台窗口）
#[cfg_attr(not(windows), allow(unused_mut))]
fn command(program: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

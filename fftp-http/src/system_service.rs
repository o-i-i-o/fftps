//! 系统服务管理：fftpd 守护进程的安装/卸载/启停/开机自启/状态
//!
//! Linux 走 `systemctl --user`（用户态服务，无需 root），Windows 走 `sc.exe`
//! （注册/删除 SCM 服务，需要管理员权限）。所有命令固定参数、不拼接用户输入，
//! 阻塞进程调用经 `spawn_blocking` 挪出异步运行时。
//!
//! # 权限模型（Windows）
//!
//! - `sc.exe query fftpd` / `qc fftpd`（只读查询）：普通用户即可执行，
//!   不需要管理员权限。
//! - `sc.exe create` / `delete` / `start` / `stop` / `restart` / `config`（操作）：
//!   必须具备 [`SE_SERVICE_CONTROL_PRIVILEGE`]，普通用户调用会返回 Win32 Error 5
//!   （`[SC] StartService: OpenService FAILED 5: Access is denied.`）。
//!
//! 本模块在执行操作类动作前先通过 [`is_user_admin`] 预检，非管理员直接返回
//! 清晰错误；同时对 `sc.exe` 输出的权限拒绝文本做兜底识别，避免误报为通用
//! 命令失败。
//!
//! 注意：本模块管理的是**fftpd 守护进程本身**，不是 fftpd 内部的 FTP/SFTP
//! 协议监听（后者走 `/api/service/*` 的 IPC 命令）。`fftp-http` 本身由桌面
//! 入口按需启动/由 SCM 托管，页面上的「关闭 Web 服务」走空闲模块的自身关停路径。

use serde::Serialize;

/// 系统服务管理动作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 安装（注册 + 启动 + 开机自启）
    Install,
    /// 卸载（停止 + 删除/禁用）
    Uninstall,
    /// 启动守护进程
    Start,
    /// 停止守护进程
    Stop,
    /// 重启守护进程
    Restart,
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
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "restart" => Some(Self::Restart),
            "autostart-on" => Some(Self::AutostartOn),
            "autostart-off" => Some(Self::AutostartOff),
            _ => None,
        }
    }

    /// 稳定标识（审计/日志用）
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::AutostartOn => "autostart-on",
            Self::AutostartOff => "autostart-off",
        }
    }

    /// 成功提示
    #[must_use]
    pub fn ok_text(self) -> &'static str {
        match self {
            Self::Install => "系统服务已安装并启动",
            Self::Uninstall => "系统服务已卸载",
            Self::Start => "fftpd 守护进程已启动",
            Self::Stop => "fftpd 守护进程已停止",
            Self::Restart => "fftpd 守护进程已重启",
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
        Action::Start => &["--user", "start", "fftpd"],
        Action::Stop => &["--user", "stop", "fftpd"],
        Action::Restart => &["--user", "restart", "fftpd"],
        Action::AutostartOn => &["--user", "enable", "fftpd"],
        Action::AutostartOff => &["--user", "disable", "fftpd"],
    };
    run_command("systemctl", args)
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)] // 与 Windows 分支保持同一签名
fn query_status() -> Result<ServiceStatus, String> {
    let enabled = run_command_output("systemctl", &["--user", "is-enabled", "fftpd"]).ok();
    let active = run_command_output("systemctl", &["--user", "is-active", "fftpd"]).ok();
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
    // Windows SCM 写操作必须管理员权限；只读查询在 query_status 独立路径，
    // 此处一律做预检，避免给用户抛晦涩的 OpenService FAILED 5。
    if !is_user_admin() {
        return Err(no_admin_error(action));
    }

    match action {
        Action::Install => {
            let bin_path = format!("\"{}\" --service", fftpd_exe_path()?.display());
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
        Action::Start => run_command("sc.exe", &["start", "fftpd"]),
        Action::Stop => run_command("sc.exe", &["stop", "fftpd"]),
        Action::Restart => {
            // 未运行时 stop 会失败，忽略后仍继续启动
            let _ = run_command("sc.exe", &["stop", "fftpd"]);
            std::thread::sleep(std::time::Duration::from_millis(500));
            run_command("sc.exe", &["start", "fftpd"])
        }
        Action::AutostartOn => run_command("sc.exe", &["config", "fftpd", "start=", "auto"]),
        Action::AutostartOff => run_command("sc.exe", &["config", "fftpd", "start=", "demand"]),
    }
}

/// 为需要管理员的系统服务动作构造友好错误信息
#[cfg(windows)]
fn no_admin_error(action: Action) -> String {
    let hint = match action {
        Action::Install => {
            "在安装向导中点击“安装服务”按钮，或右键开始菜单 fftps → 更多 → 以管理员身份运行"
        }
        Action::Uninstall => "请右键开始菜单 fftps → 更多 → 以管理员身份运行后再执行卸载",
        _ => "请右键开始菜单 fftps → 更多 → 以管理员身份运行后重试",
    };
    format!(
        "需要管理员权限：当前会话未提升，无法通过 SCM 执行 {}。{hint}。",
        action.as_str()
    )
}

#[cfg(windows)]
fn query_status() -> Result<ServiceStatus, String> {
    // 必须保留完整输出：`sc.exe query` 的首行是 SERVICE_NAME，
    // STATE（RUNNING/STOPPED）在其后若干行；只取首行会导致 running 永远为 false。
    let query = run_command_output("sc.exe", &["query", "fftpd"]).ok();
    let config = run_command_output("sc.exe", &["qc", "fftpd"]).ok();
    Ok(ServiceStatus {
        installed: query.as_deref().is_some_and(sc_query_installed),
        running: query.as_deref().is_some_and(sc_query_running),
        autostart: config.as_deref().is_some_and(sc_config_autostart),
        platform: "Windows SCM",
        detail: query
            .as_deref()
            .and_then(sc_query_summary)
            .unwrap_or_else(|| "未安装或查询失败".into()),
    })
}

/// `sc.exe query` 输出是否表示服务已注册
///
/// 成功输出形如：
/// ```text
/// SERVICE_NAME: fftpd
///         TYPE               : 10  WIN32_OWN_PROCESS
///         STATE              : 4  RUNNING
/// ```
/// 未注册时 stdout 为空，stderr 为 `[SC] ...OpenService FAILED 1060`，
/// 不含 `SERVICE_NAME` 行。
#[cfg(any(windows, test))]
fn sc_query_installed(output: &str) -> bool {
    output.lines().any(|line| {
        line.trim()
            .strip_prefix("SERVICE_NAME:")
            .is_some_and(|name| name.trim() == "fftpd")
    })
}

/// `sc.exe query` 输出中的服务是否处于 RUNNING 状态
///
/// 按整词匹配 `RUNNING`，避免误判 `STOPPED`/`START_PENDING` 等状态。
#[cfg(any(windows, test))]
fn sc_query_running(output: &str) -> bool {
    output
        .lines()
        .flat_map(str::split_whitespace)
        .any(|token| token == "RUNNING")
}

/// `sc.exe qc` 输出是否表示开机自启（`START_TYPE : 2 AUTO_START`）
#[cfg(any(windows, test))]
fn sc_config_autostart(output: &str) -> bool {
    output
        .lines()
        .flat_map(str::split_whitespace)
        .any(|token| token == "AUTO_START")
}

/// 提取 `sc.exe query` 的状态行作为单行摘要（页面展示用）
#[cfg(any(windows, test))]
fn sc_query_summary(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("STATE"))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .or_else(|| {
            output
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(str::to_owned)
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

/// 判断当前进程是否以提升后的管理员权限运行
///
/// 通过 `whoami.exe /groups /fo csv /nh` 查询当前进程 token 中
/// `BUILTIN\Administrators`(S-1-5-32-544) 是否为启用状态。
/// 未提权时 UAC 会把该组标记为 `Group used for deny only`，
/// 此时进程不具备 SCM 写权限（[`SE_SERVICE_CONTROL_PRIVILEGE`]）。
#[cfg(windows)]
fn is_user_admin() -> bool {
    // 用 Windows 内置 whoami.exe 查询当前进程的组 SID，
    // 解析 CSV 输出看 BUILTIN\Administrators(S-1-5-32-544) 是否为启用状态。
    // 未提权时 UAC 会把该组标为 "Group used for deny only"，此时 SCM 写操作会被拒绝。
    // 走外部命令而非 FFI：避免 mingw/MSVC 链接差异，零额外依赖。
    let Ok(output) = std::process::Command::new("whoami.exe")
        .args(["/groups", "/fo", "csv", "/nh"])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(line) = text.lines().find(|l| l.contains("S-1-5-32-544")) else {
        return false;
    };
    // 普通会话下管理员组是 deny-only：
    //   "BUILTIN\Administrators","Alias","S-1-5-32-544","Group used for deny only"
    // 提权后变成：
    //   "BUILTIN\Administrators","Alias","S-1-5-32-544","Mandatory group, Enabled by default, Enabled group"
    !line.contains("deny only")
}

// ---------- 命令执行 ----------

/// 执行命令并返回 stdout（成功）/ stderr 或 stdout（失败）
///
/// # Windows 编码处理
///
/// 外部命令（`sc.exe` 等）在管道输出时使用系统 ANSI 代码页（中文 Windows
/// 为 GBK/CP936），而非 UTF-8。Rust 的 `Command::output()` 捕获的是原始
/// 字节流，`String::from_utf8_lossy` 会把 GBK 多字节序列误判为无效 UTF-8，
/// 产生 `ʧ��`、`�ܾ����ʡ�` 这类乱码。
///
/// 本函数使用 [`decode_cmd_output`] 先尝试 UTF-8，失败则回退到
/// 系统 ANSI 代码页（CP_ACP）解码，保证中英文 Windows 下都输出可读文本。
fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = command(program)
        .args(args)
        .output()
        .map_err(|e| format!("无法执行 {program}：{e}"))?;
    if output.status.success() {
        Ok(decode_cmd_output(&output.stdout).trim().to_owned())
    } else {
        let stderr = decode_cmd_output(&output.stderr);
        let stdout = decode_cmd_output(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim().to_owned()
        } else {
            stderr.trim().to_owned()
        };
        Err(interpret_command_failure(
            program,
            &detail,
            output.status.code(),
        ))
    }
}

/// 将外部命令输出字节流解码为 UTF-8 文本
///
/// Windows 下先尝试 UTF-8（PowerShell 5 内置命令、Python 3 等都输出 UTF-8），
/// 若包含 U+FFFD（来自 `from_utf8_lossy`）则回退到系统 ANSI 代码页 `CP_ACP`
/// 解码（覆盖 `sc.exe`、`net.exe`、老式 console 工具）。
#[cfg(windows)]
fn decode_cmd_output(bytes: &[u8]) -> String {
    let utf8 = String::from_utf8_lossy(bytes).into_owned();
    // 若 UTF-8 解码已无替换字符，直接返回
    if !utf8.contains('\u{FFFD}') {
        return utf8;
    }
    // 回退：用系统 ANSI 代码页（CP_ACP）解码
    match decode_ansi(bytes) {
        Some(ansi) => ansi,
        None => utf8, // FFI 失败则保留 UTF-8 lossy 结果
    }
}

#[cfg(not(windows))]
fn decode_cmd_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Windows CP_ACP（系统 ANSI 代码页）解码：`MultiByteToWideChar` → Rust String
///
/// 例如中文 Windows 上 CP_ACP=936（GBK），这里会正确把 `BE E2 BE CD B7 C3 CE CA`
/// 解码为 `拒绝访问`。
#[cfg(windows)]
fn decode_ansi(bytes: &[u8]) -> Option<String> {
    const CP_ACP: u32 = 0; // 系统默认 ANSI 代码页

    // FFI 声明（user32.dll 始终存在于任何 Windows 系统）
    #[link(name = "user32")]
    unsafe extern "system" {
        fn MultiByteToWideChar(
            codepage: u32,
            flags: u32,
            multi_byte_str: *const u8,
            cb_multi_byte_str: i32,
            wide_char_str: *mut u16,
            cch_wide_char_str: i32,
        ) -> i32;
    }

    // SAFETY: 单次只读调用，flags=0 不启用 MB_ERR_INVALID_CHARS 避免部分字节序列被误判
    let required = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            0, // flags: 允许未定义字节通过，由 Rust String 替换字符兜底
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        )
    };
    if required <= 0 {
        return None;
    }
    let mut buf = vec![0u16; required as usize];
    // SAFETY: buf 长度 = required，调用只读转换
    let written = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            buf.as_mut_ptr(),
            buf.len() as i32,
        )
    };
    if written <= 0 {
        return None;
    }
    // SAFETY: buf[..written] 是 MultiByteToWideChar 写入的有效 UTF-16 序列
    Some(String::from_utf16_lossy(&buf[..written as usize]))
}

/// 解读 sc.exe/外部命令失败，将常见错误码翻译为用户可理解的提示
///
/// 主要关心 SCM 权限拒绝（Win32 Error 5 / 拒绝访问 / Access is denied）——
/// 即使调用方已过 [`is_user_admin`] 预检，这里仍作为兜底，避免透传
/// `OpenService FAILED 5` 这类晦涩文本。
fn interpret_command_failure(program: &str, detail: &str, code: Option<i32>) -> String {
    let has_access_denied = detail.contains("5")
        && (detail.contains("OpenService")
            || detail.contains("CreateService")
            || detail.contains("Access is denied")
            || detail.contains("拒绝访问"));
    if has_access_denied {
        return format!(
            "{program} 执行失败：需要管理员权限（SCM 拒绝访问）。请以管理员身份运行后重试。"
        );
    }
    if detail.trim().is_empty() {
        format!("{program} 执行失败（退出码 {code:?}）")
    } else {
        format!("{program} 执行失败：{detail}")
    }
}

/// 执行命令并返回完整输出（状态查询不因非零退出码失败）
///
/// 与 [`run_command`] 不同：查询类命令（`sc.exe query`、`systemctl is-active`）
/// 失败时也把 stderr 文本作为结果返回，由调用方解析。Windows 下输出会经
/// [`decode_cmd_output`] 解码，避免中文系统的 GBK 文本乱码。
fn run_command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = command(program)
        .args(args)
        .output()
        .map_err(|e| format!("无法执行 {program}：{e}"))?;
    let text = if output.stdout.is_empty() {
        decode_cmd_output(&output.stderr)
    } else {
        decode_cmd_output(&output.stdout)
    };
    Ok(text.trim().to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_parse_covers_lifecycle_and_autostart() {
        for (text, expected) in [
            ("install", Action::Install),
            ("uninstall", Action::Uninstall),
            ("start", Action::Start),
            ("stop", Action::Stop),
            ("restart", Action::Restart),
            ("autostart-on", Action::AutostartOn),
            ("autostart-off", Action::AutostartOff),
        ] {
            assert_eq!(Action::parse(text), Some(expected));
            assert_eq!(expected.as_str(), text);
        }
        assert_eq!(Action::parse("bogus"), None);
    }

    #[test]
    fn ok_text_distinguishes_daemon_and_autostart_actions() {
        assert!(Action::Start.ok_text().contains("守护进程"));
        assert!(Action::Stop.ok_text().contains("守护进程"));
        assert!(Action::Restart.ok_text().contains("守护进程"));
        assert!(Action::AutostartOn.ok_text().contains("自启"));
    }

    /// `sc.exe query fftpd` 的真实输出（已运行）
    const SC_QUERY_RUNNING: &str = "\nSERVICE_NAME: fftpd \n        TYPE               : 10  WIN32_OWN_PROCESS  \n        STATE              : 4  RUNNING \n                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x0\n";

    /// `sc.exe query fftpd` 的真实输出（已安装但停止）
    const SC_QUERY_STOPPED: &str = "\nSERVICE_NAME: fftpd \n        TYPE               : 10  WIN32_OWN_PROCESS  \n        STATE              : 1  STOPPED \n        WIN32_EXIT_CODE    : 1066  (0x42a)\n";

    /// `sc.exe qc fftpd` 的真实输出（开机自启）
    const SC_QC_AUTO: &str = "[SC] QueryServiceConfig SUCCESS\n\nSERVICE_NAME: fftpd\n        TYPE               : 10  WIN32_OWN_PROCESS \n        START_TYPE         : 2   AUTO_START\n        BINARY_PATH_NAME   : \"C:\\Program Files\\fftps\\fftpd.exe\" --service\n";

    #[test]
    fn sc_query_detects_running_beyond_first_line() {
        // 回归：首行是 SERVICE_NAME，RUNNING 在第 4 行
        assert!(sc_query_installed(SC_QUERY_RUNNING));
        assert!(sc_query_running(SC_QUERY_RUNNING));
        assert!(sc_query_installed(SC_QUERY_STOPPED));
        assert!(!sc_query_running(SC_QUERY_STOPPED));
    }

    #[test]
    fn sc_query_rejects_missing_service() {
        let not_installed =
            "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\n指定的服务未安装。";
        assert!(!sc_query_installed(not_installed));
        assert!(!sc_query_running(not_installed));
    }

    #[test]
    fn sc_config_detects_autostart_not_demand() {
        assert!(sc_config_autostart(SC_QC_AUTO));
        let demand = SC_QC_AUTO.replace("AUTO_START", "DEMAND_START");
        assert!(!sc_config_autostart(&demand));
    }

    #[test]
    fn sc_query_summary_is_single_state_line() {
        assert_eq!(
            sc_query_summary(SC_QUERY_RUNNING).as_deref(),
            Some("STATE : 4 RUNNING")
        );
        assert_eq!(
            sc_query_summary(SC_QUERY_STOPPED).as_deref(),
            Some("STATE : 1 STOPPED")
        );
        assert_eq!(
            sc_query_summary("[SC] OpenService FAILED 1060").as_deref(),
            Some("[SC] OpenService FAILED 1060")
        );
    }
}

//! `fftp-http launch`：桌面快捷方式入口
//!
//! 流程：读取配置 → 健康探测（校验 app 身份）→ 必要时启动 fftpd 与
//! fftp-http（systemd 用户服务优先，失败回退脱离终端启动）→ 等待就绪 →
//! 用默认浏览器打开。服务已运行时只打开浏览器，不重复启动。
//!
//! 首次启动且无管理员账户时，打开 `/setup?token=...` 引导页；令牌由
//! 服务启动时写入 0600 文件（见 [`crate::setup`]）。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::HttpConfig;
use crate::setup;

/// 启动等待上限（秒）
const START_TIMEOUT_SECS: u64 = 12;
/// 健康探测超时（毫秒）
const PROBE_TIMEOUT_MS: u64 = 600;

/// 健康探测结果
#[derive(Debug, Clone, Copy)]
struct Health {
    setup_required: bool,
}

/// 桌面入口
///
/// # Errors
/// 配置非法、启动失败或健康检查超时时返回错误（同时显示通知/消息框）
pub fn run() -> Result<()> {
    let path = fftp_common::paths::http_config_path();
    let cfg =
        HttpConfig::load(&path).with_context(|| format!("加载配置失败: {}", path.display()))?;
    cfg.validate()?;
    let url = browser_url(&cfg)?;

    if let Ok(health) = probe(&cfg) {
        return open_target(&url, health);
    }

    let Some(_lock) = acquire_lock()? else {
        // 另一个启动器正在启动：短暂等待后直接打开
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(300));
            if let Ok(health) = probe(&cfg) {
                return open_target(&url, health);
            }
        }
        let msg = "另一个 fftp-http 启动器正在启动，请稍后重试";
        show_error(msg);
        anyhow::bail!(msg);
    };

    // 拿锁后二次探测，避免与刚完成启动的实例竞争
    if let Ok(health) = probe(&cfg) {
        return open_target(&url, health);
    }

    start_backend();
    if !start_frontend() {
        let _ = spawn_detached();
    }

    let Some(health) = wait_ready(&cfg) else {
        let detail = diagnostics();
        let msg = format!(
            "fftp-http 启动超时（{} 秒）。\n\n{}",
            START_TIMEOUT_SECS,
            if detail.is_empty() {
                "请检查配置与日志。"
            } else {
                &detail
            }
        );
        show_error(&msg);
        anyhow::bail!(msg);
    };
    open_target(&url, health)
}

/// 浏览器访问地址：通配绑定映射到回环地址，IPv6 加方括号
pub(crate) fn browser_url(cfg: &HttpConfig) -> Result<String> {
    let scheme = if cfg.tls.enabled { "https" } else { "http" };
    let host = match cfg.listen.address.as_str() {
        "0.0.0.0" => "127.0.0.1".to_string(),
        "::" | "[::]" => "[::1]".to_string(),
        addr => match addr.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(_)) => format!("[{addr}]"),
            Ok(std::net::IpAddr::V4(_)) => addr.to_string(),
            Err(_) => anyhow::bail!("listen.address 非法: {addr}"),
        },
    };
    Ok(format!("{scheme}://{host}:{}", cfg.listen.port))
}

/// 健康探测用的地址（通配绑定用回环）
fn probe_addr(cfg: &HttpConfig) -> Result<SocketAddr> {
    let host = match cfg.listen.address.as_str() {
        "0.0.0.0" => "127.0.0.1".to_string(),
        "::" | "[::]" => "::1".to_string(),
        addr => addr.to_string(),
    };
    let text = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{}", cfg.listen.port)
    } else {
        format!("{host}:{}", cfg.listen.port)
    };
    text.parse()
        .with_context(|| format!("健康探测地址非法: {text}"))
}

/// 探测 `/api/health`；TLS 下仅做 TCP 连通性检查（自签证书无法校验身份）
fn probe(cfg: &HttpConfig) -> std::result::Result<Health, String> {
    let addr = probe_addr(cfg).map_err(|e| e.to_string())?;
    let timeout = Duration::from_millis(PROBE_TIMEOUT_MS);
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("连接 {addr} 失败: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    if cfg.tls.enabled {
        return Ok(Health {
            setup_required: cfg.admin_users.is_empty(),
        });
    }

    let request = format!(
        "GET /api/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nUser-Agent: fftp-http-launch\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("发送健康请求失败: {e}"))?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 16 * 1024 {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(format!("读取健康响应失败: {e}")),
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "健康响应缺少 HTTP 状态行".to_string())?;
    if status != 200 {
        return Err(format!("健康检查返回 HTTP {status}（可能被 IP 过滤拒绝）"));
    }
    let json: Value = serde_json::from_str(body).map_err(|e| format!("健康响应不是 JSON: {e}"))?;
    if json.get("app").and_then(Value::as_str) != Some("fftp-http") {
        return Err("端口已被其他程序占用（health 身份不匹配）".to_string());
    }
    Ok(Health {
        setup_required: json
            .get("setup_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// 打开浏览器；未完成 setup 时打开引导页
fn open_target(url: &str, health: Health) -> Result<()> {
    let target = if health.setup_required {
        match setup::read_token() {
            Some(token) => format!("{url}/setup?token={token}"),
            None => format!("{url}/setup"),
        }
    } else {
        url.to_string()
    };
    open_browser(&target)
}

/// 启动后端 fftpd（失败不阻塞前端，页面会显示离线横幅）
fn start_backend() {
    #[cfg(unix)]
    {
        let _ = hidden_command("systemctl")
            .args(["--user", "start", "fftpd"])
            .status();
    }
    #[cfg(windows)]
    {
        let _ = hidden_command("sc.exe").args(["start", "fftpd"]).status();
    }
}

/// 启动前端：systemd/SCM 成功返回 true，否则由调用方回退直接启动
fn start_frontend() -> bool {
    #[cfg(unix)]
    {
        hidden_command("systemctl")
            .args(["--user", "start", "fftp-http"])
            .status()
            .is_ok_and(|s| s.success())
    }
    #[cfg(windows)]
    {
        if !hidden_command("sc.exe")
            .args(["query", "fftp-http"])
            .status()
            .is_ok_and(|s| s.success())
        {
            return false;
        }
        hidden_command("sc.exe")
            .args(["start", "fftp-http"])
            .status()
            .is_ok_and(|s| s.success())
    }
}

/// 脱离终端启动自身 `serve` 子命令，日志追加到状态目录
fn spawn_detached() -> Result<()> {
    let exe = std::env::current_exe().context("无法定位 fftp-http 可执行文件")?;
    let log_path = log_path();
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();
    let (out, err) = match log {
        Some(file) => {
            let clone = file.try_clone().ok();
            (Stdio::from(file), clone.map_or(Stdio::null(), Stdio::from))
        }
        None => (Stdio::null(), Stdio::null()),
    };

    let mut cmd = Command::new(exe);
    cmd.arg("serve")
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: pre_exec 中只调用 async-signal-safe 的 setsid(2)
        unsafe {
            cmd.pre_exec(|| {
                nix::unistd::setsid()
                    .map(|_| ())
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    cmd.spawn().context("启动 fftp-http 进程失败")?;
    Ok(())
}

/// 轮询等待服务就绪
fn wait_ready(cfg: &HttpConfig) -> Option<Health> {
    let deadline = Instant::now() + Duration::from_secs(START_TIMEOUT_SECS);
    while Instant::now() < deadline {
        if let Ok(health) = probe(cfg) {
            return Some(health);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
}

/// 启动锁：防止连点同时拉起多个实例
fn acquire_lock() -> Result<Option<LaunchLock>> {
    let path = lock_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("打开启动锁失败: {}", path.display()))?;
    #[cfg(unix)]
    {
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(lock) => Ok(Some(LaunchLock { _lock: lock })),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(None),
            Err((_, e)) => Err(anyhow::anyhow!("获取启动锁失败: {e}")),
        }
    }
    #[cfg(not(unix))]
    {
        Ok(Some(LaunchLock { _file: file }))
    }
}

struct LaunchLock {
    #[cfg(unix)]
    _lock: nix::fcntl::Flock<std::fs::File>,
    #[cfg(not(unix))]
    _file: std::fs::File,
}

fn lock_path() -> PathBuf {
    #[cfg(windows)]
    {
        fftp_common::paths::state_dir().join("launch.lock")
    }
    #[cfg(not(windows))]
    {
        fftp_common::paths::runtime_dir().join("launch.lock")
    }
}

fn log_path() -> PathBuf {
    fftp_common::paths::state_dir().join("fftp-http.log")
}

/// 平台命令（Windows 下隐藏控制台窗口）
#[cfg_attr(not(windows), allow(unused_mut))]
fn hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// 打开默认浏览器；失败时回退到常见命令
fn open_browser(url: &str) -> Result<()> {
    #[cfg(unix)]
    {
        let candidates: &[(&str, &[&str])] = &[
            ("xdg-open", &[]),
            ("gio", &["open"]),
            ("sensible-browser", &[]),
        ];
        for (program, args) in candidates {
            let mut cmd = Command::new(program);
            cmd.args(*args)
                .arg(url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if cmd.spawn().is_ok() {
                return Ok(());
            }
        }
        show_error(&format!("无法打开浏览器，请手动访问：{url}"));
        anyhow::bail!("无法打开浏览器");
    }
    #[cfg(windows)]
    {
        let mut cmd = hidden_command("rundll32.exe");
        cmd.arg("url.dll,FileProtocolHandler")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if cmd.spawn().is_ok() {
            return Ok(());
        }
        let mut cmd = hidden_command("explorer.exe");
        if cmd.arg(url).spawn().is_ok() {
            return Ok(());
        }
        show_error(&format!("无法打开浏览器，请手动访问：{url}"));
        anyhow::bail!("无法打开浏览器");
    }
}

/// 收集启动失败诊断（systemd/SCM 状态 + 日志尾部）
fn diagnostics() -> String {
    let mut out = String::new();
    #[cfg(unix)]
    {
        for (program, args) in [
            (
                "systemctl",
                vec!["--user", "status", "fftp-http", "--no-pager", "-l"],
            ),
            (
                "journalctl",
                vec!["--user", "-u", "fftp-http", "-n", "20", "--no-pager"],
            ),
        ] {
            if let Ok(output) = Command::new(program).args(args).output() {
                let text = String::from_utf8_lossy(&output.stdout);
                let err = String::from_utf8_lossy(&output.stderr);
                for line in text.lines().chain(err.lines()).take(20) {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
    }
    #[cfg(windows)]
    {
        for args in [vec!["query", "fftp-http"], vec!["qc", "fftp-http"]] {
            if let Ok(output) = hidden_command("sc.exe").args(args).output() {
                out.push_str(&String::from_utf8_lossy(&output.stdout));
                out.push_str(&String::from_utf8_lossy(&output.stderr));
            }
        }
    }
    out.trim().to_string()
}

/// 桌面通知 / 消息框；无可用工具时写 stderr
pub fn show_error(message: &str) {
    #[cfg(unix)]
    {
        let _ = Command::new("notify-send")
            .args(["FFTPS", message])
            .status();
        let _ = Command::new("zenity")
            .args(["--error", "--title", "FFTPS", "--text", message])
            .status();
        eprintln!("{message}");
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        let title: Vec<u16> = "FFTPS\0".encode_utf16().collect();
        let text: Vec<u16> = std::ffi::OsStr::new(message)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: 传入有效的 NUL 结尾宽字符串与空父窗口
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
}

//! Windows GUI 子系统启动器：避免快捷方式弹出控制台黑框 + 自动提权
//!
//! ## 提权机制（两层防线）
//!
//! 1. **编译期 manifest**：`build.rs` 把 `src/resources/launcher.exe.manifest`
//!    嵌入 launcher.exe（MSVC `/manifest:` 或 mingw windres）。Shell 在用户
//!    双击时读取 manifest 的 `requestedExecutionLevel=requireAdministrator`
//!    并自动弹出 UAC，用管理员 token 启动进程。——这是**主路径**。
//!
//! 2. **运行时自提权**：`ensure_elevated()` 打开当前进程的主令牌，查询
//!    `TokenElevation`。若 elevation=false（普通用户 token），则调
//!    `ShellExecuteW("runas", <self>)` 重启自身并传入 NULL 参数。
//!    Shell 收到 runas 动词会再次触发 UAC。——这是**兜底**，用于 manifest
//!    因异常未生效（如 Windows Server Core、PE 环境、或被安全软件 strip）的
//!    场景。
//!
//! 两层机制都生效时，第二次 ShellExecuteW 调用会被自动跳过（因为
//! `is_elevated()` 已返回 true）。
//!
//! 若用户在 UAC 弹窗中**取消**，launcher 弹出 MessageBox 提示"FFTPS
//! 需要管理员权限才能管理系统服务"后退出，不会继续往下走到 sc.exe。
//!
//! ## 为什么让 launcher 提权而不是 fftp-http.exe？
//!
//! fftp-http.exe 本身保持 `asInvoker`：
//! - 从管理员 cmd/PowerShell 手工运行时不会二次触发 UAC
//! - 从非管理员 cmd 运行时会被 Shell 拦截（os error 740），此时
//!   `system_service.rs` 中的 `is_user_admin()` 检查会给出清晰错误信息
//!   而非 `OpenService FAILED 5`
//!
//! Linux 下不需要本程序（`.desktop` 直接执行 `fftp-http launch`），但仍会
//! 参与编译以便统一工作区构建。

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::{Command, Stdio};

/// 跳过自提权的环境变量（CI 调试、打包验证等场景可临时关闭）
const SKIP_ELEVATION_ENV: &str = "FFTP_SKIP_ELEVATION";

fn main() {
    // Windows 下先尝试自提权（manifest 已生效时会被 is_elevated() 短路）
    #[cfg(windows)]
    {
        if std::env::var_os(SKIP_ELEVATION_ENV).is_none() {
            ensure_elevated();
        }
    }

    if let Err(e) = run() {
        show_error(&e);
    }
}

fn run() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("无法定位启动器路径：{e}"))?;
    let dir = exe.parent().ok_or_else(|| "无法定位程序目录".to_owned())?;
    let target = dir.join(if cfg!(windows) {
        "fftp-http.exe"
    } else {
        "fftp-http"
    });
    if !target.is_file() {
        return Err(format!("未找到 fftp-http 可执行文件：{}", target.display()));
    }

    let mut cmd = Command::new(target);
    cmd.arg("launch")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.spawn()
        .map_err(|e| format!("启动 fftp-http launch 失败：{e}"))?;
    Ok(())
}

// ---------- Windows 自提权 ----------

/// 若当前进程未以管理员 token 运行，通过 ShellExecuteW("runas") 重新启动自身
///
/// 调用时序：
/// 1. `is_elevated()` 查询主令牌 `TokenElevation` 字段
///    - 返回 true → 已经是管理员 token，直接返回（manifest 生效时走这条）
///    - 返回 false → 进入第 2 步
/// 2. 调 `ShellExecuteW(NULL, "runas", <self>, NULL, NULL, SW_SHOWNORMAL)`
///    - 返回值 > 32：成功拉起提升实例，当前非提升实例 exit(0) 退出
///    - 返回值 ≤ 32：失败
///      - Win32 Error 1223 = 用户取消 UAC → 友好提示后 exit(1)
///      - 其他错误 → 通用错误信息后 exit(1)
#[cfg(windows)]
fn ensure_elevated() {
    if is_elevated() {
        return;
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    use std::os::windows::ffi::OsStrExt;
    let exe_wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;

        const SW_SHOWNORMAL: i32 = 1;

        let verb: Vec<u16> = "runas\0".encode_utf16().collect();
        let ret = ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe_wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
        // HINSTANCE 返回值：> 32 = 成功；≤ 32 = 失败
        if ret as isize <= 32 {
            let err = GetLastError();
            let msg = if err == 1223 {
                "UAC 已取消。FFTPS 需要管理员权限才能管理系统服务。请右键以管理员身份运行 FFTPS 快捷方式。"
                    .to_owned()
            } else {
                format!("启动自提权失败（Win32 error {err}）")
            };
            show_error(&msg);
            std::process::exit(1);
        }
        // 非提升实例到此退出；提升实例会从 main() 重新进入，
        // 那时 is_elevated() = true，直接进入 run() 拉起 fftp-http。
        std::process::exit(0);
    }
}

/// 检测当前进程是否拥有提升后的管理员 token（`TokenElevation` = true）
///
/// 普通用户 token 经 UAC 过滤后 `TokenElevation` = false；被提权的管理员 token
/// `TokenElevation` = true。此检测是 Windows 上判断"是否已以管理员身份运行"
/// 的标准方式，比检查用户名更可靠（避免 `BUILTIN\Administrators` 的 deny-only
/// SID 导致误判）。
///
/// SAFETY: 所有 FFI 目标都是系统 DLL，返回值经非零检查后才使用。
#[cfg(windows)]
fn is_elevated() -> bool {
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        #[repr(C)]
        struct TokenElevationData {
            token_is_elevated: u32,
        }

        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TokenElevationData {
            token_is_elevated: 0,
        };
        let mut return_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<TokenElevationData>() as u32,
            &mut return_len,
        );
        CloseHandle(token);
        if ok == 0 {
            return false;
        }
        elevation.token_is_elevated != 0
    }
}

// ---------- 常量 ----------

#[cfg(windows)]
const TOKEN_QUERY: u32 = 0x0008;

// ---------- 错误提示 ----------

#[cfg(windows)]
fn show_error(message: &str) {
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

#[cfg(not(windows))]
fn show_error(message: &str) {
    eprintln!("{message}");
}

//! Windows GUI 子系统启动器：避免快捷方式弹出控制台黑框
//!
//! 安装器创建的开始菜单/桌面快捷方式指向本程序。它以 `CREATE_NO_WINDOW`
//! 拉起同目录的 `fftp-http.exe launch` 后立即退出；真正的启动、健康检查与
//! 浏览器打开都由 `fftp-http launch` 完成（错误用 `MessageBox` 提示）。
//!
//! Linux 下不需要本程序（`.desktop` 直接执行 `fftp-http launch`），但仍会
//! 参与编译以便统一工作区构建。

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::{Command, Stdio};

fn main() {
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

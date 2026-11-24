//! Windows 构建脚本：为 `fftp-http-launcher.exe` 嵌入应用程序清单（manifest）
//!
//! 唯一职责：把 manifest 嵌入 launcher.exe，让 Windows Shell 在用户双击
//! 快捷方式时弹出 UAC，使 fftp-http.exe 及其子进程（sc.exe 等）以管理员
//! 权限运行。
//!
//! 提权两层防线：
//!   1. **manifest 主路径**（本 build.rs）：Shell 自动弹 UAC
//!   2. **launcher.rs 运行时自提权**：通过 ShellExecuteW("runas") 重启自身
//!      作为 manifest 失效时的兜底（Server Core / PE / 安全软件 strip）
//!
//! 只嵌入 launcher：fftp-http.exe 本身保持 asInvoker，这样从管理员 shell
//! 手工运行时不会二次触发 UAC；从非管理员 shell 运行时被 Shell 拦截，
//! 由 system_service.rs 的 is_user_admin() 检查给出清晰错误。
//!
//! MSVC 构建要点：
//!   - 不能用绝对路径：rustc 在 Windows 上会把绝对路径转成 `\\?\` 长路径前缀，
//!     但 link.exe 的 /manifest: 参数不接受这种格式（LNK1117 语法错误）。
//!   - 必须用相对路径（相对 cwd，即工作区根目录），而且路径不能含空格。
//!
//! （launcher bin 已设置 test = false，cargo test 不会尝试执行它）

fn main() {
    // 用相对路径，避免 rustc 在传递给 link.exe 时加 `\\?\` 长路径前缀
    let manifest_rel = "fftp-http/src/resources/launcher.exe.manifest";

    embed_manifest(manifest_rel);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", manifest_rel);
}

#[cfg(all(windows, target_env = "msvc"))]
fn embed_manifest(manifest_rel: &str) {
    // MSVC link.exe manifest 参数组合：
    //
    // /MANIFEST:EMBED
    //   必须显式指定，否则 MANIFESTINPUT 会被 LNK1220 拒绝。
    //
    // /MANIFESTUAC:level='requireAdministrator' uiAccess='false'
    //   link.exe 默认生成的 manifest snippet 带 UAC 片段
    //   （level='asInvoker'）。我们的自定义清单 level='requireAdministrator'，
    //   mt.exe 合并时发现同一属性值不同 → c1010001 错误。
    //   显式告诉 link.exe 默认片段也用 requireAdministrator，冲突消除。
    //
    // /MANIFESTINPUT:<path>
    //   自定义清单，link.exe 会与默认清单合并后嵌入 .rsrc 段。
    //
    // 路径必须用相对路径。rustc 对绝对路径加 \\?\ 长路径前缀后，
    // link.exe 无法识别（LNK1117 语法错误）。路径不含空格，无需引号。
    println!("cargo:rustc-link-arg-bin=fftp-http-launcher=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bin=fftp-http-launcher=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
    );
    println!("cargo:rustc-link-arg-bin=fftp-http-launcher=/MANIFESTINPUT:{manifest_rel}");
}

#[cfg(not(all(windows, target_env = "msvc")))]
fn embed_manifest(_manifest_rel: &str) {
    // 非 MSVC 环境：不嵌入 manifest，依赖 launcher.rs 自带的自提权逻辑
    // 这包括：非 Windows（无事可做）、GNU/mingw（不再维护编译环境）、
    // 以及任何其他 target_env
}

//! Windows 构建脚本：为 `fftp-http-launcher.exe` 嵌入应用程序清单（manifest）
//!
//! 唯一职责：把 `src/resources/launcher.exe.manifest` 嵌入 launcher.exe，
//! 让 Windows Shell 在用户双击快捷方式时弹出 UAC，使 fftp-http.exe 及其
//! 子进程（sc.exe / net.exe 等 SCM 命令）以管理员权限运行。
//!
//! 只嵌入 launcher：fftp-http.exe 本身保持 `asInvoker`，这样从管理员 shell
//! 手工运行时不会二次触发 UAC；从非管理员 shell 运行时被 Shell 拦截，
//! 由 `system_service.rs` 的 `is_user_admin()` 检查给出清晰错误信息。
//!
//! 提权是两层防线：
//!   1. **manifest 主路径**（本 build.rs）：Shell 自动弹出 UAC
//!   2. **launcher.rs 运行时自提权**：通过 ShellExecuteW("runas") 重启自身
//!      作为 manifest 失效时的兜底（Windows Server Core / PE / 安全软件 strip）
//!
//! ## MSVC 路径（主编译环境）
//!
//! MSVC linker（link.exe）支持 `/manifest:<path>`，直接把外部 manifest 当作
//! 主清单嵌入 `.rsrc` 段 ID 1 资源，**不会**自动注入默认清单，无冲突风险。
//!
//! ## CI / 交叉编译环境兜底
//!
//! 若使用非 MSVC 工具链，本脚本静默跳过 manifest 嵌入。launcher.rs 自带的
//! ShellExecuteW("runas") 自提权代码会接管 UAC 弹出——这一条在任何 Windows
//! 版本上都能工作，不依赖编译器或链接器的 manifest 支持。
//!
//! （构建约束：[[bin]] fftp-http-launcher 已设置 `test = false`，cargo test
//! 不会尝试执行要求管理员权限的 launcher）

fn main() {
    let manifest = std::path::Path::new("src/resources/launcher.exe.manifest")
        .canonicalize()
        .expect("manifest 文件必须存在");

    embed_manifest(&manifest);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", manifest.display());
}

#[cfg(all(windows, target_env = "msvc"))]
fn embed_manifest(manifest: &std::path::Path) {
    // MSVC link.exe: /manifest:<path> 直接嵌入外部清单
    // link.exe 对绝对路径更可靠（相对路径受 cwd 影响）
    let abs = manifest.display().to_string();
    println!("cargo:rustc-link-arg-bin=fftp-http-launcher=/manifest:\"{abs}\"");
}

#[cfg(not(all(windows, target_env = "msvc")))]
fn embed_manifest(_manifest: &std::path::Path) {
    // 非 MSVC 环境：不嵌入 manifest，依赖 launcher.rs 自带的自提权逻辑
    // 这包括：非 Windows（无事可做）、GNU/mingw（不再维护编译环境）、
    // 以及任何其他 target_env
}

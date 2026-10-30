//! 编译期把 ui/app.slint（含各页面 import）生成 Rust 绑定

fn main() {
    slint_build::compile("ui/app.slint").expect("slint 编译失败");
}

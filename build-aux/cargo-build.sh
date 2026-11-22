#!/usr/bin/env sh
# meson 调用的 cargo 构建包装。
#
# 用法: cargo-build.sh <outdir> [rust target] [profile] <bin 名...>
#
# meson 不感知 cargo 缓存，因此本脚本只做两件事：
#   1. 触发 cargo build（debug=dev / release）
#   2. 把产物拷贝到 meson 的 @OUTDIR@，供 custom_target 输出与 install 使用
#
# 注意：custom_target 仅以 Cargo.toml/Cargo.lock 为显式输入，改动 rust 源码后
# ninja 无法自动感知，需要重新执行 meson compile（或 meson setup --reconfigure）。
set -eu

outdir="$1"; shift
target="${1:-}"; shift || true
profile="${1:-release}"; shift || true

# outdir 可能是相对 @OUTDIR@，必须在 cd 到项目根之前解析为绝对路径
outdir="$(cd "$outdir" && pwd)"

project_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_dir"

# 交叉目标优先走 cargo-zigbuild（与 scripts/build.sh 的工具策略一致：
# zig 充当通用 linker/libc，免去逐架构准备原生交叉连接器）；缺失则回退 cargo 原生交叉
if [ -n "${target:-}" ] && command -v cargo-zigbuild > /dev/null 2>&1; then
    run_cargo() { cargo zigbuild "$@"; }
else
    run_cargo() { cargo "$@"; }
fi

if [ "$profile" = "debug" ]; then
    if [ -n "$target" ]; then
        run_cargo build --target "$target"
        src="target/$target/debug"
    else
        run_cargo build
        src="target/debug"
    fi
else
    if [ -n "$target" ]; then
        run_cargo build --release --target "$target"
        src="target/$target/release"
    else
        run_cargo build --release
        src="target/release"
    fi
fi

for bin in "$@"; do
    cp "$src/$bin" "$outdir/"
    chmod 755 "$outdir/$bin"
done

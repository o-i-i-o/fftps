#!/usr/bin/env bash
# fftps 交叉编译统一入口
#
# 用法:
#   ./scripts/build.sh [target]        # 编译单个目标（默认 x86_64-unknown-linux-gnu）
#   ./scripts/build.sh all             # 全矩阵
#
# 目标矩阵:
#   x86_64-unknown-linux-gnu     fftpd / fftp-http
#   aarch64-unknown-linux-gnu    fftpd / fftp-http
#   x86_64-unknown-linux-musl    fftpd / fftp-http
#   x86_64-pc-windows-msvc       fftpd.exe / fftp-http.exe / fftp-http-launcher.exe
#   aarch64-pc-windows-msvc      fftpd.exe / fftp-http.exe / fftp-http-launcher.exe
#
# 工具策略:
#   - Linux 目标: cargo-zigbuild + zig（zig 0.13 覆盖 musl/gnu）
#   - Windows MSVC 目标: cargo-xwin + clang（zig 无 MSVC CRT，不可用于 MSVC）
#     XWIN_CROSS_COMPILER=clang 强制用 clang 后端（ring 的 build.rs 会把 clang-cl
#     替换成 clang，而 clang-cl 的 /imsvc CFLAGS 普通 clang 不认识）
# 产物统一落 dist/<target>/，release profile。

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="${PROJECT_DIR}/dist"

# 目标矩阵（build.sh all 的执行顺序）
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "x86_64-pc-windows-msvc"
    "aarch64-pc-windows-msvc"
)

show_help() {
    cat << EOF
用法: $0 [target|all]

目标:
    x86_64-unknown-linux-gnu      x86_64 Linux (glibc)
    aarch64-unknown-linux-gnu     ARM64 Linux (glibc)
    x86_64-unknown-linux-musl     x86_64 Linux (静态 musl)
    x86_64-pc-windows-msvc       x86_64 Windows (MSVC ABI)
    aarch64-pc-windows-msvc       ARM64 Windows (MSVC ABI)
    all                           全矩阵顺序构建

产物: dist/<target>/{fftpd,fftp-http}[.exe]（release profile）
      Windows 另附 fftp-http-launcher.exe（安装向导快捷方式目标）

依赖:
    Linux: cargo-zigbuild + zig（可用 pip install ziglang）
    Windows MSVC: cargo-xwin + clang/clang++（sudo apt-get install -y clang llvm）
EOF
}

# ---------------------------------------------------------------------------
# 前置检查
# ---------------------------------------------------------------------------

check_base_tools() {
    if ! command -v cargo &> /dev/null; then
        log_error "未找到 cargo，请先安装 Rust 工具链: https://rustup.rs"
        exit 1
    fi
    if ! command -v rustup &> /dev/null; then
        log_error "未找到 rustup，请先安装: https://rustup.rs"
        exit 1
    fi
}

check_rust_target() {
    local target="$1"
    if ! rustup target list --installed | grep -qx "$target"; then
        log_error "Rust 目标未安装: ${target}"
        log_info "请执行: rustup target add ${target}"
        exit 1
    fi
}

# 定位 zig：PATH、CARGO_ZIGBUILD_ZIG_PATH、python ziglang 模块
resolve_zig() {
    if [ -n "${CARGO_ZIGBUILD_ZIG_PATH:-}" ] && [ -x "${CARGO_ZIGBUILD_ZIG_PATH}" ]; then
        return 0
    fi
    if command -v zig &> /dev/null; then
        return 0
    fi
    local candidate
    for candidate in \
        "${SCRIPT_DIR}/node_modules/.bin/zig" \
        "${PROJECT_DIR}/node_modules/.bin/zig" \
        "${HOME}/.local/bin/zig" \
        "${HOME}/node_modules/.bin/zig"; do
        if [ -x "$candidate" ]; then
            export CARGO_ZIGBUILD_ZIG_PATH="$candidate"
            log_info "使用 zig: ${candidate}"
            return 0
        fi
    done
    if command -v python3 &> /dev/null && python3 -m ziglang version &> /dev/null; then
        log_info "使用 Python ziglang 模块中的 zig $(python3 -m ziglang version)"
        return 0
    fi
    return 1
}

check_zigbuild() {
    if ! command -v cargo-zigbuild &> /dev/null; then
        log_error "未找到 cargo-zigbuild（cargo install cargo-zigbuild）"
        exit 1
    fi
    if ! resolve_zig; then
        log_error "未找到 zig（https://ziglang.org/download 或 pip install ziglang）"
        exit 1
    fi
}

check_xwin() {
    if ! command -v cargo-xwin &> /dev/null; then
        log_error "未找到 cargo-xwin（cargo install cargo-xwin）"
        exit 1
    fi
    if ! command -v clang &> /dev/null; then
        log_error "cargo-xwin 需要 clang（sudo apt-get install -y clang llvm）"
        exit 1
    fi
    if ! command -v clang++ &> /dev/null; then
        log_error "cargo-xwin 需要 clang++（sudo apt-get install -y clang llvm）"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# 构建
# ---------------------------------------------------------------------------

collect_artifacts() {
    local target="$1"
    local src="${PROJECT_DIR}/target/${target}/release"
    local out="${DIST_DIR}/${target}"
    mkdir -p "$out"

    local names=(fftpd fftp-http)
    if [[ "$target" == *windows* ]]; then
        names=(fftpd.exe fftp-http.exe fftp-http-launcher.exe)
    fi

    for name in "${names[@]}"; do
        if [ ! -f "${src}/${name}" ]; then
            log_error "缺少构建产物: ${src}/${name}"
            exit 1
        fi
        cp "${src}/${name}" "${out}/"
        chmod 755 "${out}/${name}" 2> /dev/null || true
    done

    log_success "产物已就绪: ${out}"
    ls -lh "$out"
}

build_target() {
    local target="$1"
    echo "========================================"
    log_info "构建目标: ${target}"
    echo "========================================"

    check_rust_target "$target"
    cd "${PROJECT_DIR}"

    if [[ "$target" == *windows-msvc ]]; then
        check_xwin
        log_info "使用 cargo-xwin + clang 编译: ${target}"
        # clang 后端避免 clang-cl 的 /imsvc CFLAGS 与 ring 冲突
        XWIN_CROSS_COMPILER=clang \
            cargo xwin build --release --target "$target" -p fftpd -p fftp-http
    else
        check_zigbuild
        log_info "使用 cargo-zigbuild 编译: ${target}"
        cargo zigbuild --release --target "$target" -p fftpd -p fftp-http
    fi

    collect_artifacts "$target"
}

# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    show_help
    exit 0
fi

check_base_tools

TARGET="${1:-x86_64-unknown-linux-gnu}"

if [ "$TARGET" = "all" ]; then
    for t in "${TARGETS[@]}"; do
        build_target "$t"
    done
    log_success "全矩阵构建完成，产物位于 dist/"
else
    case "$TARGET" in
        x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-unknown-linux-musl|x86_64-pc-windows-msvc|aarch64-pc-windows-msvc)
            build_target "$TARGET"
            ;;
        *)
            log_error "未知目标: ${TARGET}"
            show_help
            exit 1
            ;;
    esac
fi

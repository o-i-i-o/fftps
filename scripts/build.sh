#!/usr/bin/env bash
# fftps 交叉编译统一入口
#
# 用法:
#   ./scripts/build.sh [target]        # 编译单个目标（默认 x86_64-unknown-linux-gnu）
#   ./scripts/build.sh all             # 全矩阵：linux-gnu x86_64/aarch64、musl、windows-gnu
#
# 目标矩阵:
#   x86_64-unknown-linux-gnu     fftpd / fftp-gui / fftp-http
#   aarch64-unknown-linux-gnu    fftpd / fftp-gui / fftp-http
#   x86_64-unknown-linux-musl    fftpd / fftp-gui / fftp-http
#   x86_64-pc-windows-gnu        fftpd.exe / fftp-gui.exe / fftp-http.exe
#
# 工具策略: linux 目标与 windows-gnu 均用 cargo-zigbuild；
# 若 cargo-zigbuild 对 windows-gnu 不可用（缺 zig / 构建失败），回退
# cargo + mingw-w64 原生链接器（x86_64-w64-mingw32-gcc）。
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
    "x86_64-pc-windows-gnu"
)

show_help() {
    cat << EOF
用法: $0 [target|all]

目标:
    x86_64-unknown-linux-gnu      x86_64 Linux (glibc)
    aarch64-unknown-linux-gnu     ARM64 Linux (glibc)
    x86_64-unknown-linux-musl     x86_64 Linux (静态 musl)
    x86_64-pc-windows-gnu         x86_64 Windows (fftpd.exe / fftp-gui.exe / fftp-http.exe)
    all                           全矩阵顺序构建

产物: dist/<target>/{fftpd,fftp-gui,fftp-http}[.exe]（release profile）

依赖:
    cargo、rustup 目标、cargo-zigbuild、zig（windows-gnu 回退需要 mingw-w64）
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

# 检查 rustup 目标是否已安装，缺失时给出 rustup target add 提示
check_rust_target() {
    local target="$1"
    if ! rustup target list --installed | grep -qx "$target"; then
        log_error "Rust 目标未安装: ${target}"
        log_info "请执行: rustup target add ${target}"
        exit 1
    fi
}

# 检查 cargo-zigbuild 与 zig；缺失返回 1（调用方决定回退或报错）
check_zigbuild() {
    local ok=0
    if ! command -v cargo-zigbuild &> /dev/null; then
        log_warning "未找到 cargo-zigbuild（cargo install cargo-zigbuild 可安装）"
        ok=1
    fi
    if ! command -v zig &> /dev/null; then
        log_warning "未找到 zig（https://ziglang.org/download 或包管理器安装）"
        ok=1
    fi
    return "$ok"
}

check_mingw() {
    if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        log_error "回退 mingw 需要 x86_64-w64-mingw32-gcc"
        log_info "请执行: sudo apt-get install -y mingw-w64"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# 构建
# ---------------------------------------------------------------------------

# 把 target/<triple>/release 下的产物拷贝到 dist/<triple>/
collect_artifacts() {
    local target="$1"
    local src="${PROJECT_DIR}/target/${target}/release"
    local out="${DIST_DIR}/${target}"
    mkdir -p "$out"

    local names=(fftpd fftp-gui fftp-http)
    if [[ "$target" == *windows* ]]; then
        names=(fftpd.exe fftp-gui.exe fftp-http.exe)
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

    if [[ "$target" == *windows* ]]; then
        build_windows "$target"
    else
        if check_zigbuild; then
            log_info "使用 cargo-zigbuild 编译: ${target}"
            cargo zigbuild --release --target "$target" -p fftpd -p fftp-gui -p fftp-http
        else
            log_error "linux 目标需要 cargo-zigbuild + zig"
            log_info "安装: cargo install cargo-zigbuild ；并安装 zig 后重试"
            exit 1
        fi
    fi

    collect_artifacts "$target"
}

# windows-gnu：优先 cargo-zigbuild，失败或缺工具时回退 mingw 原生 target
build_windows() {
    local target="$1"
    if check_zigbuild; then
        log_info "使用 cargo-zigbuild 编译: ${target}"
        if cargo zigbuild --release --target "$target" -p fftpd -p fftp-gui -p fftp-http; then
            return 0
        fi
        log_warning "cargo-zigbuild 对 ${target} 不可用，回退 mingw 原生编译"
    else
        log_warning "cargo-zigbuild 不可用，使用 mingw 原生编译"
    fi

    check_mingw
    log_info "使用 mingw 链接器编译: ${target}"
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
        cargo build --release --target "$target" -p fftpd -p fftp-gui -p fftp-http
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
        x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-unknown-linux-musl|x86_64-pc-windows-gnu)
            build_target "$TARGET"
            ;;
        *)
            log_error "未知目标: ${TARGET}"
            show_help
            exit 1
            ;;
    esac
fi

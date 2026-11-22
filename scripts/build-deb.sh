#!/usr/bin/env bash
# FFTPS DEB 打包入口（debhelper + meson 构建链）
#
# 构建链：本脚本 → dpkg-buildpackage → debian/rules (dh) → meson（触发 cargo）
# 产出统一放到 dist/：
#   dist/fftps_<version>_<amd64|arm64>.deb
#
# 版本单一来源仍是 Cargo.toml（[workspace.package].version）：
# 本脚本负责把 Cargo.toml 版本同步进 debian/changelog 顶层条目。
#
# 交叉构建（-a arm64）：经 dpkg-buildpackage -a arm64 走 dh → meson cross，
# cargo 目标由 debian/rules 自动传给 meson；cargo-zigbuild + zig 可用时优先
# 使用，否则需自备 aarch64 交叉连接器。
#
# 预编译模式（-b/--bin-dir，CI 打包阶段使用）：直接复用 dist/<rust-target> 下
# 已交叉编译的 fftpd / fftp-http，跳过 cargo/meson 编译，只做安装与压制。
#
# 示例:
#   ./scripts/build-deb.sh                       # 当前架构（源码构建）
#   ./scripts/build-deb.sh -a arm64              # 交叉构建 arm64
#   ./scripts/build-deb.sh -a all -o dist        # 双架构
#   ./scripts/build-deb.sh -a amd64 -b dist/x86_64-unknown-linux-gnu -n
#   DEB_BUILD_OPTIONS=noopt ./scripts/build-deb.sh  # debug profile 快速验证

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }

show_help() {
    cat << EOF
用法: $0 [选项]

选项:
    -a, --arch ARCH     目标架构 (amd64, arm64, all) [默认: 自动检测]
    -b, --bin-dir DIR   复用预编译产物目录（跳过 cargo/meson 编译）
    -o, --output DIR    产物输出目录 [默认: dist]
    -n, --no-lintian    跳过 lintian 检查
    -h, --help          显示此帮助

环境:
    DEB_BUILD_OPTIONS   透传给 dpkg-buildpackage（如 noopt/debug/terse）

示例:
    $0                                  # 为当前架构打 deb
    $0 -a arm64                         # 交叉构建 arm64 deb（工具链自备）
    $0 -a all -o dist -n                # 双架构打包并跳过 lintian
    $0 -a amd64 -b dist/x86_64-unknown-linux-gnu -n   # 复用预编译二进制
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="${PROJECT_DIR}/dist"

TARGET_ARCH=""
BIN_DIR=""
OUTPUT_DIR="$DIST_DIR"
SKIP_LINTIAN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--arch) TARGET_ARCH="$2"; shift 2 ;;
        -b|--bin-dir) BIN_DIR="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -n|--no-lintian) SKIP_LINTIAN=true; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) log_error "未知选项: $1"; show_help; exit 1 ;;
    esac
done

# cargo 工具链路径（rustup 默认安装位置）
if [ -d "${HOME}/.cargo/bin" ]; then
    export PATH="${HOME}/.cargo/bin:$PATH"
fi

check_dependencies() {
    local missing=()
    local deps=(dpkg-buildpackage dpkg-parsechangelog)
    # 预编译模式只做安装与压制，不需要 cargo/meson
    if [ -z "$BIN_DIR" ]; then
        deps+=(cargo meson)
    fi
    for dep in "${deps[@]}"; do
        command -v "$dep" &> /dev/null || missing+=("$dep")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少必要的依赖: ${missing[*]}"
        log_info "需要: debhelper(>=13)、dpkg-dev；源码构建另需 meson、cargo/rustc"
        exit 1
    fi
}

# 预编译模式：校验二进制目录并解析为绝对路径（debian/rules 直接引用）
check_prebuilt() {
    if [ -z "$BIN_DIR" ]; then
        return 0
    fi
    if [ ! -d "$BIN_DIR" ]; then
        log_error "预编译产物目录不存在: ${BIN_DIR}"
        log_info "先执行 scripts/build.sh <rust-target>，或用 -b 指定正确目录"
        exit 1
    fi
    BIN_DIR="$(cd "$BIN_DIR" && pwd)"
    for bin in fftpd fftp-http; do
        if [ ! -x "${BIN_DIR}/${bin}" ]; then
            log_error "缺少可执行文件: ${BIN_DIR}/${bin}"
            exit 1
        fi
    done
    log_info "预编译模式: ${BIN_DIR}（跳过 cargo/meson 编译）"
}

detect_arch() {
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "$arch" ;;
    esac
}

# 把 Cargo.toml 版本同步到 debian/changelog 顶层条目（版本不一致时连日期一起刷新）
sync_changelog_version() {
    local version="$1"
    local first_line
    first_line=$(head -n1 debian/changelog)
    if [[ "$first_line" == *"(${version})"* ]]; then
        return 0
    fi
    sed -i -E "1s/fftps \([^)]*\)/fftps (${version})/" debian/changelog
    sed -i -E "s|^ -- fftps developers <developers@fftps.dev>  .*$| -- fftps developers <developers@fftps.dev>  $(date -R)|" debian/changelog
    log_info "debian/changelog 版本已同步为 ${version}"
}

build_one() {
    local arch="$1"

    echo "========================================"
    if [ -n "$BIN_DIR" ]; then
        log_info "DEB 打包（预编译产物）: ${arch}"
    else
        log_info "DEB 打包（debhelper + meson）: ${arch}"
    fi
    echo "========================================"

    local dpkg_arch="$arch"
    local dpkg_args=(-b -us -uc)
    if [ "$dpkg_arch" != "$(detect_arch)" ]; then
        dpkg_args+=(-a "$dpkg_arch")
        log_info "交叉构建: ${dpkg_arch}"
    fi

    if [ -n "$BIN_DIR" ]; then
        # 预编译模式：源码构建依赖（cargo/rustc/meson）无需安装
        dpkg_args+=(-d)
    elif ! (cd "$PROJECT_DIR" && dpkg-checkbuilddeps ${dpkg_arch:+-a "$dpkg_arch"} 2> /dev/null); then
        # rustup 直装的 cargo/rustc 不在 dpkg 数据库里，dpkg-checkbuilddeps 会误报；
        # 关键工具实际都在 PATH 时降级跳过依赖检查（-d），否则如实失败
        if command -v cargo > /dev/null 2>&1 && command -v rustc > /dev/null 2>&1 \
            && command -v meson > /dev/null 2>&1; then
            log_warning "Build-Depends 未全部以 deb 包形式安装，但工具链在 PATH 中可用，跳过依赖检查（-d）"
            dpkg_args+=(-d)
        else
            log_error "构建依赖不满足且工具链缺失，请安装: debhelper(>=13) meson cargo rustc"
            exit 1
        fi
    fi

    (
        cd "$PROJECT_DIR"
        FFTPS_PREBUILT_DIR="$BIN_DIR" dpkg-buildpackage "${dpkg_args[@]}"
    )

    mkdir -p "$OUTPUT_DIR"
    local moved=0
    for deb in "${PROJECT_DIR}/../fftps_${VERSION}_${dpkg_arch}.deb"; do
        [ -f "$deb" ] || { log_error "未找到产物: $deb"; exit 1; }
        mv "$deb" "$OUTPUT_DIR/"
        moved=1
    done
    # 清理 dpkg-buildpackage 在源码上层目录可能残留的辅助文件
    rm -f "${PROJECT_DIR}/../fftps_"*.buildinfo "${PROJECT_DIR}/../fftps_"*.changes 2>/dev/null || true

    local deb_file="${OUTPUT_DIR}/fftps_${VERSION}_${dpkg_arch}.deb"
    if [ "$SKIP_LINTIAN" = false ] && command -v lintian &> /dev/null; then
        log_info "  运行 lintian 检查: ${deb_file}"
        lintian "$deb_file" || log_warning "lintian 检查发现问题，请检查上述输出"
    fi

    log_success "构建成功: ${deb_file} ($(du -h "$deb_file" | cut -f1))"
}

check_dependencies
check_prebuilt

VERSION=$(grep -m1 "^version = " "${PROJECT_DIR}/Cargo.toml" | sed 's/version = "\(.*\)"/\1/' | head -1)
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

(
    cd "$PROJECT_DIR"
    sync_changelog_version "$VERSION"
)

if [ -z "$TARGET_ARCH" ]; then
    TARGET_ARCH=$(detect_arch)
fi

case "$TARGET_ARCH" in
    amd64|arm64)
        build_one "$TARGET_ARCH"
        ;;
    all)
        build_one amd64
        build_one arm64
        ;;
    *)
        log_error "不支持的架构: ${TARGET_ARCH}（仅支持 amd64 / arm64 / all）"
        exit 1
        ;;
esac

echo ""
echo "安装方法:"
echo "  sudo apt install ${OUTPUT_DIR}/fftps_${VERSION}_$( [ "$TARGET_ARCH" = "all" ] && echo amd64 || echo "$TARGET_ARCH" ).deb"
echo "  （双架构请分别安装对应架构的包）"
echo "安装时会为活跃桌面用户自动启用并启动 fftpd（无需 root）。"
echo "启动 Web 管理界面: 从应用菜单打开「FFTPS」，或执行 fftp-http launch"
echo "卸载方法: sudo apt remove fftps"
echo "========================================"

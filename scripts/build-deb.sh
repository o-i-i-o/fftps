#!/usr/bin/env bash
# FFTPS DEB 打包脚本（Debian / Ubuntu / UOS / 麒麟等 debian 系）
#
# 产出统一放到 dist/：
#   dist/fftp-http_<version>_<amd64|arm64>.deb
#
# 打包物料统一位于 deploy/：
#   deploy/common/    两个 systemd 用户单元、桌面入口、图标、配置模板
#   deploy/debian/    control 模板、维护脚本、changelog/copyright 模板
#
# 示例:
#   ./scripts/build-deb.sh -a amd64 -b dist/x86_64-unknown-linux-gnu
#   ./scripts/build-deb.sh -a arm64 --cross
#   ./scripts/build-deb.sh -a all --cross

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

show_help() {
    cat << EOF
用法: $0 [选项]

选项:
    -a, --arch ARCH       目标架构 (amd64, arm64, all) [默认: 自动检测]
    -b, --bin-dir DIR     使用预编译产物目录（跳过编译）
    -c, --clean           构建前清理 target 目录
    -d, --debug           使用 debug 模式编译
    -h, --help            显示此帮助
    -n, --no-lintian      跳过 lintian 检查
    -o, --output DIR      产物输出目录 [默认: dist]
    -r, --release         使用 release 模式编译 [默认]
    -t, --target TARGET   Rust 目标三元组（如 aarch64-unknown-linux-gnu）
    -v, --version VERSION 指定包版本 [默认: 从 Cargo.toml 读取]
    --cross               经 scripts/build.sh 交叉编译

示例:
    $0                                      # 为当前架构打 deb
    $0 -a arm64 --cross                     # 交叉编译并打 arm64 deb
    $0 -a amd64 -b dist/x86_64-unknown-linux-gnu
    $0 -a all --cross -n                    # 双架构打包并跳过 lintian
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPLOY_DIR="${PROJECT_DIR}/deploy"
DEPLOY_COMMON="${DEPLOY_DIR}/common"
DEPLOY_DEBIAN="${DEPLOY_DIR}/debian"
DIST_DIR="${PROJECT_DIR}/dist"
PACKAGE="fftp-http"
SHARE_DIR="usr/share/fftpd"

detect_arch() {
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "$arch" ;;
    esac
}

get_rust_target() {
    case "$1" in
        amd64) echo "x86_64-unknown-linux-gnu" ;;
        arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) echo "" ;;
    esac
}

require_materials() {
    local missing=()
    for item in \
        "${DEPLOY_COMMON}/config.toml" \
        "${DEPLOY_COMMON}/fftp-http.toml" \
        "${DEPLOY_COMMON}/fftpd.service" \
        "${DEPLOY_COMMON}/fftp-http.service" \
        "${DEPLOY_COMMON}/fftp-http.desktop" \
        "${DEPLOY_COMMON}/fftp-http.svg" \
        "${DEPLOY_DEBIAN}/control.in" \
        "${DEPLOY_DEBIAN}/changelog.in" \
        "${DEPLOY_DEBIAN}/copyright" \
        "${DEPLOY_DEBIAN}/postinst" \
        "${DEPLOY_DEBIAN}/prerm" \
        "${DEPLOY_DEBIAN}/postrm"; do
        [ -f "$item" ] || missing+=("$item")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少打包物料: ${missing[*]}"
        exit 1
    fi
}

check_dependencies() {
    local missing=()
    local deps=(dpkg-deb dpkg)
    [ -n "$BIN_DIR" ] || deps+=(cargo)
    for dep in "${deps[@]}"; do
        command -v "$dep" &> /dev/null || missing+=("$dep")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少必要的依赖: ${missing[*]}"
        exit 1
    fi
    if [ -z "$BIN_DIR" ] && [ "$ENABLE_CROSS" = true ] && [ ! -x "${SCRIPT_DIR}/build.sh" ]; then
        log_error "交叉编译需要 scripts/build.sh"
        exit 1
    fi
}

CLEAN_BUILD=false
DEBUG_MODE=false
SKIP_LINTIAN=false
ENABLE_CROSS=false
TARGET_ARCH=""
RUST_TARGET=""
BIN_DIR=""
OUTPUT_DIR="$DIST_DIR"
CUSTOM_VERSION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--arch) TARGET_ARCH="$2"; shift 2 ;;
        -b|--bin-dir) BIN_DIR="$2"; shift 2 ;;
        -c|--clean) CLEAN_BUILD=true; shift ;;
        -d|--debug) DEBUG_MODE=true; shift ;;
        -h|--help) show_help; exit 0 ;;
        -n|--no-lintian) SKIP_LINTIAN=true; shift ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -r|--release) DEBUG_MODE=false; shift ;;
        -t|--target) RUST_TARGET="$2"; shift 2 ;;
        -v|--version) CUSTOM_VERSION="$2"; shift 2 ;;
        --cross) ENABLE_CROSS=true; shift ;;
        *) log_error "未知选项: $1"; show_help; exit 1 ;;
    esac
done

if [ -n "${SUDO_USER:-}" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    USER_CARGO_BIN="$USER_HOME/.cargo/bin"
    if [ -d "$USER_CARGO_BIN" ]; then
        export PATH="$USER_CARGO_BIN:$PATH"
        export CARGO_HOME="$USER_HOME/.cargo"
        export RUSTUP_HOME="$USER_HOME/.rustup"
        log_info "已添加用户 cargo 路径到 PATH: $USER_CARGO_BIN"
    fi
fi

if [ -n "$CUSTOM_VERSION" ]; then
    VERSION="$CUSTOM_VERSION"
else
    VERSION=$(grep -m1 "^version = " "${PROJECT_DIR}/Cargo.toml" | sed 's/version = "\(.*\)"/\1/' | tr -d '"' | head -1)
fi

if [ -z "$TARGET_ARCH" ]; then
    TARGET_ARCH=$(detect_arch)
fi

if [ "$TARGET_ARCH" = "all" ]; then
    if [ -n "$BIN_DIR" ]; then
        log_error "双架构打包不能共用单一 -b/--bin-dir，请按架构分别打包，或先编译到 dist/<target>"
        exit 1
    fi
    depend_args=()
    if [ "$SKIP_LINTIAN" = true ]; then depend_args+=(-n); fi
    if [ "$ENABLE_CROSS" = true ]; then depend_args+=(--cross); fi
    if [ "$DEBUG_MODE" = true ]; then depend_args+=(-d); fi
    for arch in amd64 arm64; do
        "$0" -a "$arch" -o "$OUTPUT_DIR" -v "$VERSION" "${depend_args[@]}"
    done
    log_success "双架构 deb 打包完成，产物位于 ${OUTPUT_DIR}"
    exit 0
fi

case "$TARGET_ARCH" in
    amd64|arm64) ;;
    *) log_error "不支持的架构: ${TARGET_ARCH}（仅支持 amd64 / arm64）"; exit 1 ;;
esac

if [ -z "$RUST_TARGET" ]; then
    RUST_TARGET=$(get_rust_target "$TARGET_ARCH")
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

require_materials
check_dependencies

BUILD_MODE=$([ "$DEBUG_MODE" = true ] && echo "" || echo "--release")

echo "========================================"
echo "  FFTPS DEB 打包（fftp-http）"
echo "========================================"
echo "版本: ${VERSION}"
echo "架构: ${TARGET_ARCH}"
echo "Rust 目标: ${RUST_TARGET:-默认}"
echo "编译模式: $([ -n "$BIN_DIR" ] && echo "跳过（使用预编译产物）" || { [ "$DEBUG_MODE" = true ] && echo "debug" || echo "release"; })"
echo "交叉编译: $([ "$ENABLE_CROSS" = true ] && echo "是" || echo "否")"
[ -n "$BIN_DIR" ] && echo "产物目录: ${BIN_DIR}"
echo "输出目录: ${OUTPUT_DIR}"
echo "========================================"

cd "${PROJECT_DIR}"

if [ "$CLEAN_BUILD" = true ] && [ -z "$BIN_DIR" ]; then
    log_info "[1/5] 清理旧的构建文件..."
    rm -rf "${PROJECT_DIR}/target"
fi

if [ -n "$BIN_DIR" ]; then
    log_info "[2/5] 使用预编译产物，跳过编译: ${BIN_DIR}"
    if [ ! -d "$BIN_DIR" ]; then
        log_error "预编译产物目录不存在: ${BIN_DIR}"
        exit 1
    fi
    TARGET_DIR="$(cd "$BIN_DIR" && pwd)"
elif [ "$ENABLE_CROSS" = true ]; then
    log_info "[2/5] 编译项目（交叉编译）..."
    log_info "使用 scripts/build.sh 交叉编译: ${RUST_TARGET}"
    "${SCRIPT_DIR}/build.sh" "$RUST_TARGET"
    TARGET_DIR="${DIST_DIR}/${RUST_TARGET}"
else
    log_info "[2/5] 编译项目..."
    if [ -n "$RUST_TARGET" ]; then
        log_info "使用 cargo 编译目标: ${RUST_TARGET}"
        cargo build $BUILD_MODE --target "$RUST_TARGET"
        TARGET_DIR="${PROJECT_DIR}/target/${RUST_TARGET}/$([ "$DEBUG_MODE" = true ] && echo "debug" || echo "release")"
    else
        cargo build $BUILD_MODE
        TARGET_DIR="${PROJECT_DIR}/target/$([ "$DEBUG_MODE" = true ] && echo "debug" || echo "release")"
    fi
fi

log_info "[3/5] 校验编译产物..."
for bin in fftpd fftp-http; do
    if [ ! -f "${TARGET_DIR}/${bin}" ]; then
        log_error "编译失败: 缺少可执行文件 ${TARGET_DIR}/${bin}"
        exit 1
    fi
done
log_success "产物齐备: ${TARGET_DIR}"

# ---------------------------------------------------------------------------
# 暂存包内容
# ---------------------------------------------------------------------------

BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fftp-deb.XXXXXX")
trap 'rm -rf "${BUILD_DIR}"' EXIT
deb_dir="${BUILD_DIR}/${PACKAGE}_${VERSION}_${TARGET_ARCH}"
deb_file="${OUTPUT_DIR}/${PACKAGE}_${VERSION}_${TARGET_ARCH}.deb"

log_info "[4/5] 暂存包内容..."
mkdir -p "${deb_dir}/DEBIAN" "${deb_dir}/usr/bin" "${deb_dir}/usr/lib/systemd/user" \
    "${deb_dir}/usr/share/applications" "${deb_dir}/usr/share/doc/${PACKAGE}" \
    "${deb_dir}/usr/share/pixmaps" "${deb_dir}/usr/share/icons/hicolor/scalable/apps" \
    "${deb_dir}/${SHARE_DIR}"

install -m 0755 "${TARGET_DIR}/fftpd" "${TARGET_DIR}/fftp-http" "${deb_dir}/usr/bin/"

install -m 0644 "${DEPLOY_COMMON}/fftpd.service" "${DEPLOY_COMMON}/fftp-http.service" \
    "${deb_dir}/usr/lib/systemd/user/"
install -m 0644 "${DEPLOY_COMMON}/fftp-http.desktop" "${deb_dir}/usr/share/applications/"
install -m 0644 "${DEPLOY_COMMON}/fftp-http.svg" \
    "${deb_dir}/usr/share/icons/hicolor/scalable/apps/fftp-http.svg"
install -m 0644 "${DEPLOY_COMMON}/fftp-http.svg" "${deb_dir}/usr/share/pixmaps/fftp-http.svg"

if command -v convert &> /dev/null; then
    mkdir -p "${deb_dir}/usr/share/icons/hicolor/256x256/apps"
    if convert -background none -size 256x256 "${DEPLOY_COMMON}/fftp-http.svg" \
        "${deb_dir}/usr/share/icons/hicolor/256x256/apps/fftp-http.png" 2> /dev/null; then
        chmod 644 "${deb_dir}/usr/share/icons/hicolor/256x256/apps/fftp-http.png"
        cp "${deb_dir}/usr/share/icons/hicolor/256x256/apps/fftp-http.png" "${deb_dir}/usr/share/pixmaps/"
    else
        log_warning "  PNG 图标生成失败（保留 SVG）"
    fi
fi

install -m 0644 "${DEPLOY_COMMON}/config.toml" "${deb_dir}/${SHARE_DIR}/config.toml"
install -m 0644 "${DEPLOY_COMMON}/fftp-http.toml" "${deb_dir}/${SHARE_DIR}/fftp-http.toml"

log_info "  生成 DEBIAN/control..."
sed -e "s|@VERSION@|${VERSION}|g" \
    -e "s|@ARCH@|${TARGET_ARCH}|g" \
    -e "s|@INSTALLED_SIZE@|$(du -sk "${deb_dir}" | cut -f1)|g" \
    "${DEPLOY_DEBIAN}/control.in" > "${deb_dir}/DEBIAN/control"

for maintscript in preinst postinst prerm postrm; do
    if [ -f "${DEPLOY_DEBIAN}/${maintscript}" ]; then
        install -m 0755 "${DEPLOY_DEBIAN}/${maintscript}" "${deb_dir}/DEBIAN/"
    fi
done

log_info "  生成 changelog/copyright..."
sed -e "s|@VERSION@|${VERSION}|g" \
    -e "s|@DATE@|$(date -R)|g" \
    "${DEPLOY_DEBIAN}/changelog.in" > "${deb_dir}/usr/share/doc/${PACKAGE}/changelog"
gzip -9 "${deb_dir}/usr/share/doc/${PACKAGE}/changelog"
install -m 0644 "${DEPLOY_DEBIAN}/copyright" "${deb_dir}/usr/share/doc/${PACKAGE}/copyright"

log_info "  设置目录权限..."
chown -R root:root "${deb_dir}" 2> /dev/null || \
    log_warning "chown 不可用（非 POSIX 文件系统？），归档属主由 --root-owner-group 保证"
chmod -R 755 "${deb_dir}/usr/bin"

log_info "  构建 DEB 包..."
dpkg-deb --root-owner-group --build "$deb_dir" "$deb_file"

if [ ! -f "$deb_file" ]; then
    log_error "DEB 包构建失败: ${deb_file}"
    exit 1
fi

if [ "$SKIP_LINTIAN" = false ] && command -v lintian &> /dev/null; then
    log_info "  运行 lintian 检查: ${deb_file}"
    lintian "$deb_file" || log_warning "lintian 检查发现问题，请检查上述输出"
fi

if [ -n "${SUDO_USER:-}" ]; then
    chown "${SUDO_USER}:$(id -gn "${SUDO_USER}")" "$deb_file" 2> /dev/null || true
fi

log_info "[5/5] 清理临时目录..."
log_success "构建成功: ${deb_file} ($(du -h "$deb_file" | cut -f1))"
echo ""
echo "安装方法:"
echo "  sudo apt install ${deb_file}"
echo "  （请用 apt 而不是 dpkg -i：本包 Conflicts/Replaces 旧的 fftps/fftp-gui，"
echo "    apt 会自动移除旧包及其 ftp-gui 桌面入口）"
echo ""
echo "安装时会为活跃桌面用户自动启用并启动 fftpd（无需 root）。"
echo "若安装时没有活跃会话，请登录后执行:"
echo "  systemctl --user enable --now fftpd"
echo "启动 Web 管理界面:"
echo "  从应用菜单打开「FFTPS Web 管理」，或执行 fftp-http launch"
echo ""
echo "卸载方法:"
echo "  sudo apt remove fftp-http"
echo "========================================"

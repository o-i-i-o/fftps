#!/bin/bash
# fftps DEB 打包脚本（仅 fftp-http Web 管理版）
#
# 产出单一包：
#   fftp-http   fftpd 后端 + fftp-http Web 管理前端、桌面入口、
#               fftpd.service 与 fftp-http.service 两个 systemd 用户单元
#
# cargo build 编译 fftpd / fftp-http，拷贝到 /usr/bin，
# 附 systemd --user 单元、桌面文件、图标、changelog/copyright 与初始配置。

set -e
set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_help() {
    cat << EOF
用法: $0 [选项]

选项:
    -a, --arch ARCH       目标架构 (arm64, amd64, armhf, i386) [默认: 自动检测]
    -b, --bin-dir DIR     使用预编译产物目录（跳过编译，CI 打包用）
    -c, --clean           构建前清理target目录
    -d, --debug           使用debug模式编译
    -h, --help            显示此帮助信息
    -n, --no-lintian      跳过lintian检查
    -o, --output DIR      指定输出目录 [默认: debian/]
    -r, --release         使用release模式编译 [默认]
    -t, --target TARGET   Rust编译目标三元组 (如: aarch64-unknown-linux-gnu)
    -v, --version VERSION 指定包版本 [默认: 从Cargo.toml读取]
    --cross               启用交叉编译模式（经 scripts/build.sh / cargo-zigbuild）

示例:
    $0                          # 构建当前架构的 deb 包
    $0 -a arm64                 # 构建 arm64 包
    $0 -a amd64 --cross         # 交叉编译 amd64 包
    $0 -a arm64 -b dist/aarch64-unknown-linux-gnu   # 用预编译产物打包
    $0 -c -n                    # 清理构建并跳过 lintian 检查
EOF
}

detect_arch() {
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armhf) echo "armhf" ;;
        i686|i386) echo "i386" ;;
        *) echo "$arch" ;;
    esac
}

get_rust_target() {
    case "$1" in
        arm64) echo "aarch64-unknown-linux-gnu" ;;
        amd64) echo "x86_64-unknown-linux-gnu" ;;
        armhf) echo "armv7-unknown-linux-gnueabihf" ;;
        i386) echo "i686-unknown-linux-gnu" ;;
        *) echo "" ;;
    esac
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
    if [ -z "$BIN_DIR" ] && [ "$ENABLE_CROSS" = "true" ] && [ ! -x "${PROJECT_DIR}/scripts/build.sh" ]; then
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
OUTPUT_DIR=""
CUSTOM_VERSION=""
PACKAGE="fftp-http"

while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--arch) TARGET_ARCH="$2"; shift 2 ;;
        -b|--bin-dir) BIN_DIR="$2"; shift 2 ;;
        -c|--clean) CLEAN_BUILD=true; shift ;;
        -d|--debug) DEBUG_MODE=true; shift ;;
        -h|--help) show_help; exit 0 ;;
        -n|--no-lintian) SKIP_LINTIAN=true; shift ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -p|--package)
            if [ "$2" != "fftp-http" ] && [ "$2" != "all" ]; then
                log_error "仅支持 fftp-http 变体（当前: $2）"
                exit 1
            fi
            shift 2
            ;;
        -r|--release) DEBUG_MODE=false; shift ;;
        -t|--target) RUST_TARGET="$2"; shift 2 ;;
        -v|--version) CUSTOM_VERSION="$2"; shift 2 ;;
        --cross) ENABLE_CROSS=true; shift ;;
        *) log_error "未知选项: $1"; show_help; exit 1 ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    log_error "请使用root权限运行此脚本"
    echo "Usage: sudo $0"
    exit 1
fi

if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    USER_CARGO_BIN="$USER_HOME/.cargo/bin"
    if [ -d "$USER_CARGO_BIN" ]; then
        export PATH="$USER_CARGO_BIN:$PATH"
        export CARGO_HOME="$USER_HOME/.cargo"
        export RUSTUP_HOME="$USER_HOME/.rustup"
        log_info "已添加用户cargo路径到PATH: $USER_CARGO_BIN"
    fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${SCRIPT_DIR}/build"
SHARE_DIR="usr/share/fftpd"

if [ -n "$CUSTOM_VERSION" ]; then
    VERSION="$CUSTOM_VERSION"
else
    VERSION=$(grep -m1 "^version = " "${PROJECT_DIR}/Cargo.toml" | sed 's/version = "\(.*\)"/\1/' | tr -d '"' | head -1)
fi

[ -n "$TARGET_ARCH" ] || TARGET_ARCH=$(detect_arch)
[ -n "$RUST_TARGET" ] || RUST_TARGET=$(get_rust_target "$TARGET_ARCH")
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$SCRIPT_DIR"
fi
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"

check_dependencies

echo "========================================"
echo "  FFTPS DEB包构建脚本（fftp-http）"
echo "========================================"
echo "版本: ${VERSION}"
echo "架构: ${TARGET_ARCH}"
echo "Rust目标: ${RUST_TARGET:-默认}"
echo "编译模式: $([ -n "$BIN_DIR" ] && echo "跳过（使用预编译产物）" || { [ "$DEBUG_MODE" = true ] && echo "debug" || echo "release"; })"
echo "交叉编译: $([ "$ENABLE_CROSS" = true ] && echo "是" || echo "否")"
[ -n "$BIN_DIR" ] && echo "产物目录: ${BIN_DIR}"
echo "项目目录: ${PROJECT_DIR}"
echo "构建目录: ${BUILD_DIR}"
echo "输出目录: ${OUTPUT_DIR}"
echo "========================================"

cd "${PROJECT_DIR}"

if [ "$CLEAN_BUILD" = true ] && [ -z "$BIN_DIR" ]; then
    log_info "[1/5] 清理旧的构建文件..."
    rm -rf "${BUILD_DIR}" "${PROJECT_DIR}/target"
fi
mkdir -p "${BUILD_DIR}"

BUILD_MODE=$([ "$DEBUG_MODE" = true ] && echo "" || echo "--release")

if [ -n "$BIN_DIR" ]; then
    log_info "[2/5] 使用预编译产物，跳过编译: ${BIN_DIR}"
    if [ ! -d "$BIN_DIR" ]; then
        log_error "预编译产物目录不存在: ${BIN_DIR}"
        exit 1
    fi
    TARGET_DIR="$(cd "$BIN_DIR" && pwd)"
elif [ "$ENABLE_CROSS" = true ]; then
    log_info "[2/5] 编译项目（交叉编译）..."
    if [ -z "$RUST_TARGET" ]; then
        log_error "--cross 需要同时给出 -t/--target 或 -a/--arch"
        exit 1
    fi
    log_info "使用 scripts/build.sh 交叉编译: ${RUST_TARGET}"
    "${PROJECT_DIR}/scripts/build.sh" "$RUST_TARGET"
    TARGET_DIR="${PROJECT_DIR}/dist/${RUST_TARGET}"
else
    log_info "[2/5] 编译项目..."
    if [ -n "$RUST_TARGET" ]; then
        log_info "使用cargo编译目标: ${RUST_TARGET}"
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
# 打包
# ---------------------------------------------------------------------------

deb_dir="${BUILD_DIR}/${PACKAGE}_${VERSION}_${TARGET_ARCH}"
deb_file="${OUTPUT_DIR}/${PACKAGE}_${VERSION}_${TARGET_ARCH}.deb"

log_info "[4/5] 暂存包内容..."
rm -rf "$deb_dir"
mkdir -p "${deb_dir}/DEBIAN" "${deb_dir}/usr/bin" "${deb_dir}/usr/lib/systemd/user" \
    "${deb_dir}/usr/share/applications" "${deb_dir}/usr/share/doc/${PACKAGE}" \
    "${deb_dir}/usr/share/pixmaps" "${deb_dir}/usr/share/icons/hicolor/scalable/apps" \
    "${deb_dir}/${SHARE_DIR}"

for bin in fftpd fftp-http; do
    cp "${TARGET_DIR}/${bin}" "${deb_dir}/usr/bin/"
    chmod 755 "${deb_dir}/usr/bin/${bin}"
done

cp "${SCRIPT_DIR}/fftpd.service" "${deb_dir}/usr/lib/systemd/user/"
cp "${SCRIPT_DIR}/fftp-http.service" "${deb_dir}/usr/lib/systemd/user/"
chmod 644 "${deb_dir}/usr/lib/systemd/user/fftpd.service" \
    "${deb_dir}/usr/lib/systemd/user/fftp-http.service"

cp "${SCRIPT_DIR}/fftp-http.desktop" "${deb_dir}/usr/share/applications/"
chmod 644 "${deb_dir}/usr/share/applications/fftp-http.desktop"

cp "${SCRIPT_DIR}/fftp-http.svg" "${deb_dir}/usr/share/icons/hicolor/scalable/apps/"
cp "${SCRIPT_DIR}/fftp-http.svg" "${deb_dir}/usr/share/pixmaps/"
chmod 644 "${deb_dir}/usr/share/icons/hicolor/scalable/apps/fftp-http.svg" \
    "${deb_dir}/usr/share/pixmaps/fftp-http.svg"

if command -v convert &> /dev/null; then
    mkdir -p "${deb_dir}/usr/share/icons/hicolor/256x256/apps"
    if convert -background none -size 256x256 "${SCRIPT_DIR}/fftp-http.svg" \
        "${deb_dir}/usr/share/icons/hicolor/256x256/apps/fftp-http.png" 2> /dev/null; then
        chmod 644 "${deb_dir}/usr/share/icons/hicolor/256x256/apps/fftp-http.png"
        cp "${deb_dir}/usr/share/icons/hicolor/256x256/apps/fftp-http.png" "${deb_dir}/usr/share/pixmaps/"
    else
        log_warning "  PNG 图标生成失败（保留 SVG）"
    fi
fi

# 包内配置模板（postinst 预置到各用户 ~/.config/fftpd/）
cp "${SCRIPT_DIR}/config_example.toml" "${deb_dir}/${SHARE_DIR}/config.toml"
cp "${PROJECT_DIR}/examples/fftp-http.toml.example" "${deb_dir}/${SHARE_DIR}/fftp-http.toml"
chmod 644 "${deb_dir}/${SHARE_DIR}/config.toml" "${deb_dir}/${SHARE_DIR}/fftp-http.toml"

log_info "  创建DEBIAN控制文件..."
cat > "${deb_dir}/DEBIAN/control" << EOF
Package: ${PACKAGE}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${TARGET_ARCH}
Maintainer: fftps developers <developers@fftps.dev>
Conflicts: fftps, fftp-gui
Replaces: fftps, fftp-gui
Homepage: https://github.com/fftps/fftps
Depends: libc6
Installed-Size: $(du -sk "${deb_dir}" | cut -f1)
Description: SFTP/FTP(FTPS) server suite with Web management frontend
 Contains the fftpd FTP(FTPS)/SFTP server backend and the fftp-http
 Web (HTTP/HTTPS) management frontend, each with its own systemd
 user service unit. A desktop entry starts the Web service on demand
 and opens it in the default browser.
 Pure Rust headless deployment: manage the servers from a browser.
Description-zh_CN: SFTP/FTP(FTPS) 服务套件（Web 管理版）
 自带 fftpd 服务端后端与 fftp-http Web 管理前端，
 两者各带一个 systemd 用户服务单元；桌面入口按需启动 Web 服务并打开浏览器。
 使用纯 Rust 实现，可用浏览器管理服务器。
EOF

for maintscript in preinst postinst prerm postrm; do
    if [ -f "${SCRIPT_DIR}/${maintscript}" ]; then
        cp "${SCRIPT_DIR}/${maintscript}" "${deb_dir}/DEBIAN/"
        chmod 755 "${deb_dir}/DEBIAN/${maintscript}"
    fi
done

log_info "  创建changelog文件..."
CHANGELOG_DATE=$(date -R)
cat > "${deb_dir}/usr/share/doc/${PACKAGE}/changelog" << EOF
${PACKAGE} (${VERSION}) stable; urgency=medium

  * Release version ${VERSION}
  * Support SFTP and FTP(FTPS) server management
  * Frontend: fftp-http Web (HTTP/HTTPS) management interface
  * Desktop entry starts the Web service on demand and opens the browser
  * Includes the fftpd backend (per-user systemd service, no root needed)
  * Multi-architecture support

 -- fftps developers <developers@fftps.dev>  ${CHANGELOG_DATE}
EOF
gzip -9 "${deb_dir}/usr/share/doc/${PACKAGE}/changelog"

log_info "  创建copyright文件..."
cat > "${deb_dir}/usr/share/doc/${PACKAGE}/copyright" << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: fftps
Source: https://github.com/fftps/fftps

Files: *
Copyright: 2025-2026 fftps developers <developers@fftps.dev>
License: GPL-3.0

License: GPL-3.0
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
EOF

log_info "  设置目录权限..."
chown -R root:root "${deb_dir}" 2> /dev/null || \
    log_warning "chown 不可用（非 POSIX 文件系统？），归档属主由 --root-owner-group 保证"
chmod -R 755 "${deb_dir}/usr/bin"

log_info "  构建DEB包..."
dpkg-deb --root-owner-group --build "$deb_dir" "$deb_file"

if [ ! -f "$deb_file" ]; then
    log_error "DEB包构建失败: ${deb_file}"
    exit 1
fi

if [ "$SKIP_LINTIAN" = false ] && command -v lintian &> /dev/null; then
    log_info "  运行lintian检查: ${deb_file}"
    lintian "$deb_file" || log_warning "lintian检查发现问题，请检查上述输出"
fi

rm -rf "$deb_dir"

log_info "[5/5] 清理构建目录..."
rm -rf "${BUILD_DIR}"

if [ -n "$SUDO_USER" ]; then
    chown -R "${SUDO_USER}:$(id -gn "${SUDO_USER}")" "${OUTPUT_DIR}" "${BUILD_DIR}" 2> /dev/null || true
fi

log_success "构建成功: ${deb_file} ($(du -h "$deb_file" | cut -f1))"
echo ""
echo "安装方法:"
echo "  sudo apt install ${deb_file}"
echo "  （请用 apt 而不是 dpkg -i：本包 Conflicts/Replaces 旧的 fftps/fftp-gui，"
echo "    apt 会自动移除旧包及其 ftp-gui 桌面入口）"
echo ""
echo "启用后台服务（桌面用户，无需 root）:"
echo "  systemctl --user enable --now fftpd"
echo "启动 Web 管理界面:"
echo "  从应用菜单打开「FFTPS Web 管理」，或执行 fftp-http launch"
echo ""
echo "卸载方法:"
echo "  sudo apt remove fftp-http"
echo ""
echo "查看包信息: dpkg -I <包文件>"
echo "查看包内容: dpkg -c <包文件>"
echo "========================================"

#!/bin/bash
# fftps DEB 打包脚本（从 wftpd-linux/debian/build-deb.sh 改名适配）
#
# cargo build 编译 fftpd / fftp-gui，拷贝到 /usr/bin，
# 附 systemd --user 单元、桌面文件、图标、changelog/copyright 与初始配置。

set -e

set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    cat << EOF
用法: $0 [选项]

选项:
    -a, --arch ARCH       目标架构 (arm64, amd64, armhf, i386) [默认: 自动检测]
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
    $0                          # 默认构建当前架构
    $0 -a arm64                 # 构建arm64包
    $0 -a amd64 --cross         # 交叉编译amd64包
    $0 -c -n                    # 清理构建并跳过lintian检查
EOF
}

detect_arch() {
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        armv7l|armhf)
            echo "armhf"
            ;;
        i686|i386)
            echo "i386"
            ;;
        *)
            echo "$arch"
            ;;
    esac
}

get_rust_target() {
    local arch="$1"
    case "$arch" in
        arm64)
            echo "aarch64-unknown-linux-gnu"
            ;;
        amd64)
            echo "x86_64-unknown-linux-gnu"
            ;;
        armhf)
            echo "armv7-unknown-linux-gnueabihf"
            ;;
        i386)
            echo "i686-unknown-linux-gnu"
            ;;
        *)
            echo ""
            ;;
    esac
}

get_version_from_cargo() {
    local cargo_toml="$1"
    if [ -f "$cargo_toml" ]; then
        grep -m1 '^version = ' "$cargo_toml" | sed 's/version = "\(.*\)"/\1/' | tr -d '"'
    else
        echo "0.0.0"
    fi
}

check_dependencies() {
    local missing=()

    local deps=("cargo" "dpkg-deb" "dpkg")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少必要的依赖: ${missing[*]}"
        log_info "请安装缺少的依赖后重试"
        exit 1
    fi

    if [ "$ENABLE_CROSS" = "true" ]; then
        # 交叉编译统一走 scripts/build.sh（cargo-zigbuild，windows-gnu 回退 mingw）
        if [ ! -x "${PROJECT_DIR}/scripts/build.sh" ]; then
            log_error "交叉编译需要 scripts/build.sh"
            exit 1
        fi
    fi
}

CLEAN_BUILD=false
DEBUG_MODE=false
SKIP_LINTIAN=false
ENABLE_CROSS=false
TARGET_ARCH=""
RUST_TARGET=""
OUTPUT_DIR=""
CUSTOM_VERSION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        -d|--debug)
            DEBUG_MODE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -n|--no-lintian)
            SKIP_LINTIAN=true
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -r|--release)
            DEBUG_MODE=false
            shift
            ;;
        -t|--target)
            RUST_TARGET="$2"
            shift 2
            ;;
        -v|--version)
            CUSTOM_VERSION="$2"
            shift 2
            ;;
        --cross)
            ENABLE_CROSS=true
            shift
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
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
PACKAGE_NAME="fftps"

if [ -n "$CUSTOM_VERSION" ]; then
    VERSION="$CUSTOM_VERSION"
else
    VERSION=$(grep -m1 "^version = " "${PROJECT_DIR}/Cargo.toml" | sed 's/version = "\(.*\)"/\1/' | tr -d '"' | head -1)
fi

if [ -z "$TARGET_ARCH" ]; then
    TARGET_ARCH=$(detect_arch)
fi

if [ -z "$RUST_TARGET" ]; then
    RUST_TARGET=$(get_rust_target "$TARGET_ARCH")
fi

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$SCRIPT_DIR"
fi
# 输出目录统一转为绝对路径：脚本后续会 cd 到 BUILD_DIR，相对路径会失效
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"

check_dependencies

echo "========================================"
echo "  FFTPS DEB包构建脚本"
echo "========================================"
echo "包名称: ${PACKAGE_NAME}"
echo "版本: ${VERSION}"
echo "架构: ${TARGET_ARCH}"
echo "Rust目标: ${RUST_TARGET:-默认}"
echo "编译模式: $([ "$DEBUG_MODE" = true ] && echo "debug" || echo "release")"
echo "交叉编译: $([ "$ENABLE_CROSS" = true ] && echo "是" || echo "否")"
echo "项目目录: ${PROJECT_DIR}"
echo "构建目录: ${BUILD_DIR}"
echo "输出目录: ${OUTPUT_DIR}"
echo "========================================"

cd "${PROJECT_DIR}"

if [ "$CLEAN_BUILD" = true ]; then
    log_info "[1/9] 清理旧的构建文件..."
    rm -rf "${BUILD_DIR}"
    rm -rf "${PROJECT_DIR}/target"
fi

mkdir -p "${BUILD_DIR}"

log_info "[2/9] 编译项目..."
BUILD_MODE=$([ "$DEBUG_MODE" = true ] && echo "" || echo "--release")

if [ "$ENABLE_CROSS" = true ]; then
    if [ -z "$RUST_TARGET" ]; then
        log_error "--cross 需要同时给出 -t/--target 或 -a/--arch"
        exit 1
    fi
    log_info "使用 scripts/build.sh 交叉编译: ${RUST_TARGET}"
    "${PROJECT_DIR}/scripts/build.sh" "$RUST_TARGET"
    TARGET_DIR="${PROJECT_DIR}/dist/${RUST_TARGET}"
else
    if [ -n "$RUST_TARGET" ]; then
        log_info "使用cargo编译目标: ${RUST_TARGET}"
        cargo build $BUILD_MODE --target "$RUST_TARGET"
        TARGET_DIR="${PROJECT_DIR}/target/${RUST_TARGET}/$([ "$DEBUG_MODE" = true ] && echo "debug" || echo "release")"
    else
        cargo build $BUILD_MODE
        TARGET_DIR="${PROJECT_DIR}/target/$([ "$DEBUG_MODE" = true ] && echo "debug" || echo "release")"
    fi
fi

if [ ! -f "${TARGET_DIR}/fftp-gui" ]; then
    log_error "编译失败: 未找到可执行文件 ${TARGET_DIR}/fftp-gui"
    exit 1
fi

log_success "找到已编译的可执行文件: ${TARGET_DIR}/fftp-gui"

log_info "[3/9] 创建 DEB 包目录结构..."
DEB_DIR="${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${TARGET_ARCH}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/bin"
mkdir -p "${DEB_DIR}/usr/share/applications"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/256x256/apps"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/48x48/apps"
mkdir -p "${DEB_DIR}/usr/lib/systemd/user"
mkdir -p "${DEB_DIR}/usr/share/doc/${PACKAGE_NAME}"
mkdir -p "${DEB_DIR}/usr/share/${PACKAGE_NAME}"

log_info "[4/9] 复制可执行文件..."

if [ -f "${TARGET_DIR}/fftp-gui" ]; then
    cp "${TARGET_DIR}/fftp-gui" "${DEB_DIR}/usr/bin/"
    chmod 755 "${DEB_DIR}/usr/bin/fftp-gui"
    chown root:root "${DEB_DIR}/usr/bin/fftp-gui" 2> /dev/null || true
    log_info "  已复制: fftp-gui (GUI管理程序)"
fi

if [ -f "${TARGET_DIR}/fftpd" ]; then
    cp "${TARGET_DIR}/fftpd" "${DEB_DIR}/usr/bin/"
    chmod 755 "${DEB_DIR}/usr/bin/fftpd"
    chown root:root "${DEB_DIR}/usr/bin/fftpd" 2> /dev/null || true
    log_info "  已复制：fftpd (后台服务程序)"
fi

log_info "[5/9] 复制桌面文件..."
if [ -f "${SCRIPT_DIR}/fftp-gui.desktop" ]; then
    cp "${SCRIPT_DIR}/fftp-gui.desktop" "${DEB_DIR}/usr/share/applications/"
    chmod 644 "${DEB_DIR}/usr/share/applications/fftp-gui.desktop"
    log_info "  已复制: fftp-gui.desktop"
fi

log_info "[6/9] 创建图标文件..."
mkdir -p "${DEB_DIR}/usr/share/pixmaps"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps"

log_info "  生成SVG图标..."
cat > "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps/fftp-gui.svg" << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#4A90E2;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#357ABD;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect x="20" y="20" width="216" height="216" rx="20" ry="20" fill="url(#grad)"/>
  <text x="128" y="110" font-family="Arial, sans-serif" font-size="50" font-weight="bold" fill="white" text-anchor="middle">FFTPS</text>
  <text x="128" y="160" font-family="Arial, sans-serif" font-size="30" fill="white" text-anchor="middle">Server</text>
</svg>
EOF
chmod 644 "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps/fftp-gui.svg"
cp "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps/fftp-gui.svg" "${DEB_DIR}/usr/share/pixmaps/fftp-gui.svg"
chmod 644 "${DEB_DIR}/usr/share/pixmaps/fftp-gui.svg"

if command -v convert &> /dev/null; then
    log_info "  生成PNG图标 (使用ImageMagick)..."
    convert -background none -size 256x256 "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps/fftp-gui.svg" \
        "${DEB_DIR}/usr/share/icons/hicolor/256x256/apps/fftp-gui.png" 2>/dev/null || \
        log_warning "    PNG 256x256生成失败"

    if [ -f "${DEB_DIR}/usr/share/icons/hicolor/256x256/apps/fftp-gui.png" ]; then
        chmod 644 "${DEB_DIR}/usr/share/icons/hicolor/256x256/apps/fftp-gui.png"
        convert -background none -size 48x48 "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps/fftp-gui.svg" \
            "${DEB_DIR}/usr/share/icons/hicolor/48x48/apps/fftp-gui.png" 2>/dev/null || \
            log_warning "    PNG 48x48生成失败"

        if [ -f "${DEB_DIR}/usr/share/icons/hicolor/48x48/apps/fftp-gui.png" ]; then
            chmod 644 "${DEB_DIR}/usr/share/icons/hicolor/48x48/apps/fftp-gui.png"
        fi

        cp "${DEB_DIR}/usr/share/icons/hicolor/256x256/apps/fftp-gui.png" "${DEB_DIR}/usr/share/pixmaps/fftp-gui.png"
    fi
else
    log_warning "  未安装ImageMagick，跳过PNG图标生成"
fi

log_info "[7/9] 复制 systemd 用户服务单元..."
if [ -f "${SCRIPT_DIR}/fftpd.service" ]; then
    cp "${SCRIPT_DIR}/fftpd.service" "${DEB_DIR}/usr/lib/systemd/user/"
    chmod 644 "${DEB_DIR}/usr/lib/systemd/user/fftpd.service"
    log_info "  已复制：fftpd.service（用户服务，无需 root）"
fi

log_info "[8/9] 安装初始配置文件..."
if [ -f "${SCRIPT_DIR}/config_example.toml" ]; then
    # 打包阶段把示例配置复制为 config.toml 随包交付（安装位置 /usr/share/fftps/），
    # 各用户的实际配置位于 ~/.config/fftpd/config.toml
    cp "${SCRIPT_DIR}/config_example.toml" "${DEB_DIR}/usr/share/${PACKAGE_NAME}/config.toml"
    chmod 644 "${DEB_DIR}/usr/share/${PACKAGE_NAME}/config.toml"
    log_info "  已复制：config_example.toml -> config.toml（实际配置位于 ~/.config/fftpd/config.toml）"
fi

log_info "[9/9] 创建DEBIAN控制文件..."

cat > "${DEB_DIR}/DEBIAN/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${TARGET_ARCH}
Maintainer: fftps developers <developers@fftps.dev>
Description: SFTP/FTP(FTPS) server suite with GUI management tool
 fftp-suite provides the fftpd FTP(FTPS)/SFTP server daemon and the
 fftp-gui cross-platform (iced) management frontend.
 A pure Rust implementation for managing SFTP and FTP servers with a
 user-friendly interface.
Description-zh_CN: SFTP/FTP(FTPS) 服务套件与图形化管理工具
 适用于Linux的SFTP+FTP(FTPS)服务套件。
 使用纯Rust实现（fftpd 服务端 + fftp-gui iced 图形界面），
 提供友好的用户界面来管理SFTP和FTP服务器。
Homepage: https://github.com/fftps/fftps
Depends: libc6, libxkbcommon0
Recommends: libvulkan1
Installed-Size: $(du -sk "${DEB_DIR}" | cut -f1)
EOF

if [ -f "${SCRIPT_DIR}/preinst" ]; then
    cp "${SCRIPT_DIR}/preinst" "${DEB_DIR}/DEBIAN/"
    chmod 755 "${DEB_DIR}/DEBIAN/preinst"
fi

if [ -f "${SCRIPT_DIR}/postinst" ]; then
    cp "${SCRIPT_DIR}/postinst" "${DEB_DIR}/DEBIAN/"
    chmod 755 "${DEB_DIR}/DEBIAN/postinst"
fi

if [ -f "${SCRIPT_DIR}/prerm" ]; then
    cp "${SCRIPT_DIR}/prerm" "${DEB_DIR}/DEBIAN/"
    chmod 755 "${DEB_DIR}/DEBIAN/prerm"
fi

if [ -f "${SCRIPT_DIR}/postrm" ]; then
    cp "${SCRIPT_DIR}/postrm" "${DEB_DIR}/DEBIAN/"
    chmod 755 "${DEB_DIR}/DEBIAN/postrm"
fi

log_info "创建changelog文件..."
CHANGELOG_DATE=$(date -R)
cat > "${DEB_DIR}/usr/share/doc/${PACKAGE_NAME}/changelog" << EOF
${PACKAGE_NAME} (${VERSION}) stable; urgency=medium

  * Release version ${VERSION}
  * Support SFTP and FTP(FTPS) server management
  * iced cross-platform GUI interface
  * Per-user systemd service model (no root needed)
  * Multi-architecture support

 -- fftps developers <developers@fftps.dev>  ${CHANGELOG_DATE}
EOF
gzip -9 "${DEB_DIR}/usr/share/doc/${PACKAGE_NAME}/changelog"

log_info "创建copyright文件..."
cat > "${DEB_DIR}/usr/share/doc/${PACKAGE_NAME}/copyright" << 'EOF'
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

log_info "设置目录权限..."
# NTFS 等非 POSIX 挂载上 chown 可能失败；打包时用 --root-owner-group 保证归 root
chown -R root:root "${DEB_DIR}" 2> /dev/null || log_warning "chown 不可用（非 POSIX 文件系统？），归档属主由 --root-owner-group 保证"
chmod -R 755 "${DEB_DIR}/usr/bin"

log_info "构建DEB包..."
mkdir -p "${OUTPUT_DIR}"
cd "${BUILD_DIR}"
dpkg-deb --root-owner-group --build "${PACKAGE_NAME}_${VERSION}_${TARGET_ARCH}" "${OUTPUT_DIR}/${PACKAGE_NAME}_${VERSION}_${TARGET_ARCH}.deb"

DEB_FILE="${OUTPUT_DIR}/${PACKAGE_NAME}_${VERSION}_${TARGET_ARCH}.deb"

if [ -f "$DEB_FILE" ]; then
    if [ "$SKIP_LINTIAN" = false ] && command -v lintian &> /dev/null; then
        log_info "运行lintian检查..."
        lintian "$DEB_FILE" || log_warning "lintian检查发现问题，请检查上述输出"
    fi

    log_success "构建成功!"
    echo ""
    echo "========================================"
    echo "  构建完成"
    echo "========================================"
    echo "DEB包位置: ${DEB_FILE}"
    echo "包大小: $(du -h "$DEB_FILE" | cut -f1)"
    echo ""
    echo "安装方法:"
    echo "  sudo dpkg -i ${DEB_FILE}"
    echo ""
    echo "或者:"
    echo "  sudo apt install ${DEB_FILE}"
    echo ""
    echo "启用后台服务（桌面用户，无需 root）:"
    echo "  systemctl --user enable --now fftpd"
    echo ""
    echo "卸载方法:"
    echo "  sudo apt remove ${PACKAGE_NAME}"
    echo ""
    echo "查看包信息:"
    echo "  dpkg -I ${DEB_FILE}"
    echo ""
    echo "查看包内容:"
    echo "  dpkg -c ${DEB_FILE}"
    echo "========================================"

    rm -rf "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${TARGET_ARCH}/"

    # 以 sudo 运行时把产物目录归还给原用户，避免 CI 后续步骤（tarball 打包）或本地后续操作因 root 属主而 Permission denied
    if [ -n "$SUDO_USER" ]; then
        chown -R "${SUDO_USER}:$(id -gn "${SUDO_USER}")" "${OUTPUT_DIR}" "${BUILD_DIR}" 2> /dev/null || true
    fi

    exit 0
else
    log_error "DEB包构建失败"
    exit 1
fi

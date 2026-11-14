#!/usr/bin/env bash
# FFTPS Windows zip 交付物打包脚本（x86_64 / arm64）
#
# 产出统一放到 dist/：
#   dist/fftps_<version>_windows-x64.zip
#   dist/fftps_<version>_windows-arm64.zip
#
# zip 内容（扁平结构，解压后双击 install.bat 即装）：
#   fftpd.exe / fftp-http.exe / fftp-http-launcher.exe
#   install.bat / install.ps1 / uninstall.bat / uninstall.ps1
#   config.toml / fftp-http.toml（配置模板，安装时仅首次预置）
#
# 打包物料统一位于 deploy/：
#   deploy/windows/   安装/卸载脚本
#   deploy/common/    配置模板
#
# 示例:
#   ./scripts/build-zip.sh                    # x86_64（dist/x86_64-pc-windows-gnu）
#   ./scripts/build-zip.sh -a arm64           # arm64（dist/aarch64-pc-windows-msvc）

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

show_help() {
    cat << EOF
用法: $0 [选项]

选项:
    -a, --arch ARCH      目标架构 (x86_64, arm64) [默认: x86_64]
    -b, --bin-dir DIR    预编译产物目录 [默认: dist/<windows-target>]
    -o, --output DIR     产物输出目录 [默认: dist]
    -v, --version VER    包版本 [默认: 读取 Cargo.toml]
    -h, --help           显示此帮助
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPLOY_DIR="${PROJECT_DIR}/deploy"
DIST_DIR="${PROJECT_DIR}/dist"

ARCH="x86_64"
TARGET=""
BIN_DIR=""
OUTPUT_DIR="$DIST_DIR"
CUSTOM_VERSION=""

while [ $# -gt 0 ]; do
    case "$1" in
        -a|--arch) ARCH="$2"; shift 2 ;;
        -b|--bin-dir) BIN_DIR="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -v|--version) CUSTOM_VERSION="$2"; shift 2 ;;
        -h|--help) show_help; exit 0 ;;
        *) log_error "未知选项: $1"; show_help; exit 1 ;;
    esac
done

case "$ARCH" in
    x86_64|amd64|x64) ARCH=x86_64; ZIP_ARCH=x64; TARGET=x86_64-pc-windows-gnu ;;
    arm64|aarch64) ARCH=arm64; ZIP_ARCH=arm64; TARGET=aarch64-pc-windows-msvc ;;
    *) log_error "不支持的架构: $ARCH（仅支持 x86_64 / arm64）"; exit 1 ;;
esac

if [ -n "$CUSTOM_VERSION" ]; then
    VERSION="$CUSTOM_VERSION"
else
    VERSION=$(grep -m1 '^version = ' "${PROJECT_DIR}/Cargo.toml" | cut -d'"' -f2)
fi

[ -z "$BIN_DIR" ] && BIN_DIR="${DIST_DIR}/${TARGET}"

for bin in fftpd.exe fftp-http.exe fftp-http-launcher.exe; do
    if [ ! -f "${BIN_DIR}/${bin}" ]; then
        log_error "缺少可执行文件: ${BIN_DIR}/${bin}"
        log_info "先执行 scripts/build.sh ${TARGET}"
        exit 1
    fi
done

for mat in install.bat install.ps1 uninstall.bat uninstall.ps1; do
    if [ ! -f "${DEPLOY_DIR}/windows/${mat}" ]; then
        log_error "缺少打包物料: deploy/windows/${mat}"
        exit 1
    fi
done

if ! command -v zip &> /dev/null; then
    log_error "未找到 zip 命令（sudo apt install zip）"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

cp "${BIN_DIR}/fftpd.exe" "${BIN_DIR}/fftp-http.exe" "${BIN_DIR}/fftp-http-launcher.exe" "$STAGE/"
cp "${DEPLOY_DIR}/windows/install.bat" "${DEPLOY_DIR}/windows/install.ps1" \
   "${DEPLOY_DIR}/windows/uninstall.bat" "${DEPLOY_DIR}/windows/uninstall.ps1" "$STAGE/"
cp "${DEPLOY_DIR}/common/config.toml" "${DEPLOY_DIR}/common/fftp-http.toml" "$STAGE/"

# 版本号写入 install.ps1（ARP 注册展示用）
sed -i "s/^\\\$Version = '.*'  # build-zip.sh 打包时替换\$/\$Version = '${VERSION}'  # build-zip.sh 打包时替换/" \
    "${STAGE}/install.ps1"
if ! grep -q "\$Version = '${VERSION}'" "${STAGE}/install.ps1"; then
    log_error "install.ps1 版本号注入失败"
    exit 1
fi

ZIP_FILE="${OUTPUT_DIR}/fftps-${VERSION}-windows-${ZIP_ARCH}.zip"
(cd "$STAGE" && zip -9 -q "$ZIP_FILE" *.exe *.bat *.ps1 *.toml)

log_success "构建成功: ${ZIP_FILE} ($(du -h "$ZIP_FILE" | cut -f1))"

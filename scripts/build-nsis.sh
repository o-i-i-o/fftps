#!/usr/bin/env bash
# FFTPS Windows NSIS 安装器打包脚本
#
# 产出统一放到 dist/：
#   dist/fftps-http_<version>_windows-x86_64-setup.exe
#
# 打包物料统一位于 deploy/：
#   deploy/windows/   NSIS 脚本（fftps-http.nsi）
#   deploy/common/    配置模板（config.toml、fftp-http.toml）
#
# 示例:
#   ./scripts/build-nsis.sh                            # 使用 dist/x86_64-pc-windows-gnu 产物
#   ./scripts/build-nsis.sh --cross                    # 先交叉编译再打包
#   ./scripts/build-nsis.sh -b dist/x86_64-pc-windows-gnu -v 0.1.1

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

show_help() {
    cat << EOF
用法: $0 [选项]

选项:
    -b, --bin-dir DIR    预编译产物目录 [默认: dist/x86_64-pc-windows-gnu]
    -o, --output DIR     产物输出目录 [默认: dist]
    -v, --version VER    包版本 [默认: 读取 Cargo.toml]
    -h, --help           显示此帮助

示例:
    $0                                   # 使用 dist/x86_64-pc-windows-gnu 产物打包
    $0 -b dist/win -o out                # 指定产物目录与输出目录
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPLOY_DIR="${PROJECT_DIR}/deploy"
DIST_DIR="${PROJECT_DIR}/dist"
NSI_SCRIPT="${DEPLOY_DIR}/windows/fftps-http.nsi"

TARGET="x86_64-pc-windows-gnu"
BIN_DIR=""
OUTPUT_DIR="$DIST_DIR"
CUSTOM_VERSION=""

while [ $# -gt 0 ]; do
    case "$1" in
        -b|--bin-dir) BIN_DIR="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -v|--version) CUSTOM_VERSION="$2"; shift 2 ;;
        -h|--help) show_help; exit 0 ;;
        *) log_error "未知选项: $1"; show_help; exit 1 ;;
    esac
done

if [ -n "$CUSTOM_VERSION" ]; then
    VERSION="$CUSTOM_VERSION"
else
    VERSION=$(grep -m1 '^version = ' "${PROJECT_DIR}/Cargo.toml" | cut -d'"' -f2)
fi

if [ -z "$BIN_DIR" ]; then
    BIN_DIR="${DIST_DIR}/${TARGET}"
fi

if ! command -v makensis &> /dev/null; then
    log_error "未找到 makensis（Debian/Ubuntu: sudo apt install nsis；Fedora: sudo dnf install mingw64-nsis）"
    exit 1
fi

for bin in fftpd.exe fftp-http.exe fftp-http-launcher.exe; do
    if [ ! -f "${BIN_DIR}/${bin}" ]; then
        log_error "缺少可执行文件: ${BIN_DIR}/${bin}"
        log_info "先执行 scripts/build.sh ${TARGET}"
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

echo "========================================"
log_info "版本: ${VERSION}"
log_info "产物目录: ${BIN_DIR}"
log_info "输出目录: ${OUTPUT_DIR}"

cd "${PROJECT_DIR}"

makensis \
    -DAPP_VERSION="${VERSION}" \
    -DDIST_DIR="$(cd "$BIN_DIR" && pwd)" \
    -DOUT_DIR="${OUTPUT_DIR}" \
    -DREPO_ROOT="${PROJECT_DIR}" \
    "${NSI_SCRIPT}"

SETUP_FILE="${OUTPUT_DIR}/fftps-http-${VERSION}-windows-x86_64-setup.exe"
if [ ! -f "$SETUP_FILE" ]; then
    log_error "NSIS 安装器构建失败: ${SETUP_FILE}"
    exit 1
fi

log_success "构建成功: ${SETUP_FILE} ($(du -h "$SETUP_FILE" | cut -f1))"

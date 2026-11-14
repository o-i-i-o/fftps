#!/usr/bin/env bash
# FFTPS Windows MSI 安装包构建脚本（WiX 5，x86_64 / arm64 双架构）
#
# 产出统一放到 dist/：
#   dist/fftps-http_<version>_windows-x64.msi
#   dist/fftps-http_<version>_windows-arm64.msi
#
# MSI 特性（与原 NSIS 安装器语义对齐，见 deploy/windows/fftps.wxs 头注释）：
#   - 原生 msiexec（ARM64 Windows 上无 x86 模拟 stub）
#   - fftpd 注册 SCM 自启服务；标准「设置→应用」卸载入口
#   - %ProgramData%\fftpd 配置模板为 Permanent 组件，用户改动自动保留
#
# 运行平台：仅支持 Windows 原生构建（MSI 数据库绑定依赖 msi.dll；
# Linux 上编译 Directory/@Name 亦会因路径根语义差异误报 WIX0389）。
# CI 中在 windows-latest runner 上调用本脚本。
#
# 依赖（Windows）:
#   dotnet SDK
#   dotnet tool install --global wix --version 5.0.2   # v7 起需 OSMF 付费 EULA，锁定 v5
#   wix extension add -g WixToolset.Util.wixext
#
# 示例:
#   ./scripts/build-msi.sh                    # x64（dist/x86_64-pc-windows-gnu）
#   ./scripts/build-msi.sh -a arm64           # arm64（dist/aarch64-pc-windows-msvc）

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
DIST_DIR="${PROJECT_DIR}/dist"
WXS="${PROJECT_DIR}/deploy/windows/fftps.wxs"

ARCH="x86_64"
WIX_ARCH=""
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
    x86_64|amd64|x64) ARCH=x86_64; WIX_ARCH=x64; TARGET=x86_64-pc-windows-gnu ;;
    arm64|aarch64) ARCH=arm64; WIX_ARCH=arm64; TARGET=aarch64-pc-windows-msvc ;;
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

if ! command -v wix &> /dev/null; then
    export PATH="$PATH:$HOME/.dotnet/tools"
fi
if ! command -v wix &> /dev/null; then
    log_error "未找到 wix CLI。安装方式（Windows）:"
    log_info "  dotnet tool install --global wix --version 5.0.2"
    log_info "  wix extension add -g WixToolset.Util.wixext"
    log_info "注意: MSI 需在 Windows 上构建（绑定依赖 msi.dll，Linux 不支持）"
    exit 1
fi

# Util 扩展缺失时自动补装（幂等）
if ! wix extension list -g 2> /dev/null | grep -q "WixToolset.Util.wixext"; then
    log_info "自动安装 WixToolset.Util.wixext 扩展"
    wix extension add -g WixToolset.Util.wixext
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# Windows Git Bash 下将 MSYS 风格路径转成 wix 可识别的 Windows 路径
to_native() {
    if command -v cygpath &> /dev/null; then
        cygpath -m "$1"
    else
        echo "$1"
    fi
}

echo "========================================"
log_info "版本: ${VERSION}（WiX arch: ${WIX_ARCH}）"
log_info "产物目录: ${BIN_DIR}"
log_info "输出目录: ${OUTPUT_DIR}"

MSI_FILE="${OUTPUT_DIR}/fftps-http-${VERSION}-windows-${ARCH}.msi"

cd "${PROJECT_DIR}"
wix build \
    -arch "$WIX_ARCH" \
    -define ProjectRoot="$(to_native "$PROJECT_DIR")" \
    -define BinDir="$(to_native "$BIN_DIR")" \
    -define Version="$VERSION" \
    -ext WixToolset.Util.wixext \
    -intermediatefolder "$(to_native "$OUTPUT_DIR")/.wixobj" \
    -o "$(to_native "$MSI_FILE")" \
    "$(to_native "$WXS")"

rm -rf "${OUTPUT_DIR}/.wixobj"

if [ ! -f "$MSI_FILE" ]; then
    log_error "MSI 构建失败: ${MSI_FILE}"
    exit 1
fi

log_success "构建成功: ${MSI_FILE} ($(du -h "$MSI_FILE" | cut -f1))"

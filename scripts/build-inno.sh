#!/usr/bin/env bash
# FFTPS Windows 安装向导构建脚本（Inno Setup 7，x64 / arm64 各一包）
#
# 产出统一放到 dist/：
#   dist/fftps-<version>-windows-x64-setup.exe
#   dist/fftps-<version>-windows-arm64-setup.exe
#
# 安装包内容与语义见 deploy/windows/fftps.iss（服务注册、ProgramData ACL、
# 快捷方式、首次预置配置、卸载保留数据等）。
#
# 运行平台：
#   - Windows：安装 Inno Setup 6.7.4，ISCC.exe 在 PATH，或设置 ISCC 环境变量
#   - Linux：wine（需 wine32，Inno 6 的 ISCC 为 32 位）+ Inno Setup 6.7.4，
#     或设置 ISCC 指向 ISCC.exe
#   CI 使用 windows-latest，避免 Wine 的额外依赖。
#
# 依赖：
#   - 先执行 scripts/build.sh <target> 生成三个 exe
#   - Inno Setup 7.1.1（简体中文语言文件已 vendored 在 deploy/windows/languages/，
#     不依赖本地 Inno 安装是否带中文语言包）
#
# 示例:
#   ./scripts/build-inno.sh -a x64   -b dist/x86_64-pc-windows-msvc
#   ./scripts/build-inno.sh -a arm64 -b dist/aarch64-pc-windows-msvc

set -euo pipefail

# MSYS/Git Bash 会把 /xxx 形式的 flag 当成 POSIX 路径转换成 Windows 路径，
# 导致 ISCC 收到的不是 /Qp 而是 C:\msys64\Qp。CI 必须设这个变量。
export MSYS2_ARG_CONV_EXCL='*'

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
    -a, --arch ARCH      目标架构 (x64/amd64, arm64) [默认: x64]
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
ISS_SRC="${DEPLOY_DIR}/windows/fftps.iss"

ARCH="x64"
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
    x86_64|amd64|x64) ARCH=x64; TARGET=x86_64-pc-windows-msvc ;;
    arm64|aarch64) ARCH=arm64; TARGET=aarch64-pc-windows-msvc ;;
    *) log_error "不支持的架构: $ARCH（仅支持 x64/amd64、arm64）"; exit 1 ;;
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

for mat in config.toml fftp-http.toml; do
    if [ ! -f "${DEPLOY_DIR}/common/${mat}" ]; then
        log_error "缺少配置模板: deploy/common/${mat}"
        exit 1
    fi
done

for mat in "${ISS_SRC}" "${PROJECT_DIR}/LICENSE"; do
    if [ ! -f "${mat}" ]; then
        log_error "缺少打包物料: ${mat}"
        exit 1
    fi
done

# 简体中文语言文件随仓库 vendored，避免依赖本地 Inno 安装的 Languages 布局。
LANG_FILE="${DEPLOY_DIR}/windows/languages/ChineseSimplified.isl"
if [ ! -f "${LANG_FILE}" ]; then
    log_error "缺少 vendored 语言文件: ${LANG_FILE}"
    exit 1
fi

# Windows 版本资源要求 4 段纯数字；从 0.1.2 / 0.1.2-rc1 提取 0.1.2.0
VERSION_NUM=$(printf '%s' "$VERSION" | sed -E 's/^([0-9]+(\.[0-9]+)*).*/\1/')
IFS='.' read -r V1 V2 V3 V4 <<< "$VERSION_NUM"
VERSION_INFO="${V1:-0}.${V2:-0}.${V3:-0}.${V4:-0}"

find_iscc() {
    if [ -n "${ISCC:-}" ]; then
        printf '%s\n' "$ISCC"
        return 0
    fi
    local cand
    for cand in iscc iscc.exe ISCC.exe; do
        if command -v "$cand" > /dev/null 2>&1; then
            command -v "$cand"
            return 0
        fi
    done
    local p
    # Inno Setup 7 路径优先（64 位安装器，推荐版本）
    for p in \
        "$HOME/.wine/drive_c/Program Files/Inno Setup 7/ISCC.exe" \
        "$HOME/.wine/drive_c/Program Files (x86)/Inno Setup 7/ISCC.exe" \
        "$HOME/.wine/drive_c/Program Files/Inno Setup 6/ISCC.exe" \
        "$HOME/.wine/drive_c/Program Files (x86)/Inno Setup 6/ISCC.exe" \
        "/c/Program Files/Inno Setup 7/ISCC.exe" \
        "/c/Program Files (x86)/Inno Setup 7/ISCC.exe" \
        "/c/Program Files/Inno Setup 6/ISCC.exe" \
        "/c/Program Files (x86)/Inno Setup 6/ISCC.exe"; do
        if [ -f "$p" ]; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 1
}

ISCC_BIN=$(find_iscc) || {
    log_error "未找到 Inno Setup 编译器 ISCC.exe"
    log_info "Windows: 安装 Inno Setup 7.1.1 并把安装目录加入 PATH，或设置 ISCC 环境变量"
    log_info "  https://github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x64.exe"
    log_info "Linux: 安装 wine 后同样安装 Inno Setup，或设置 ISCC 指向 ISCC.exe"
    exit 1
}

ISCC_FLAGS=(/Qp)
OS_KIND="$(uname -s)"
if [[ "$ISCC_BIN" == *.exe ]] && [[ "$OS_KIND" != MINGW* && "$OS_KIND" != MSYS* && "$OS_KIND" != CYGWIN* ]]; then
    if ! command -v wine > /dev/null 2>&1; then
        log_error "非 Windows 平台编译需要 wine: ${ISCC_BIN}"
        exit 1
    fi
    ISCC_RUN=(wine "$ISCC_BIN")
    export WINEDEBUG="${WINEDEBUG:--all}"
else
    ISCC_RUN=("$ISCC_BIN")
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/fftps-inno.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT

cp "${BIN_DIR}/fftpd.exe" "${BIN_DIR}/fftp-http.exe" "${BIN_DIR}/fftp-http-launcher.exe" "$STAGE/"
cp "${DEPLOY_DIR}/common/config.toml" "${DEPLOY_DIR}/common/fftp-http.toml" "$STAGE/"
cp "${PROJECT_DIR}/LICENSE" "$STAGE/LICENSE.txt"
mkdir -p "$STAGE/languages"
cp "${LANG_FILE}" "$STAGE/languages/"

# 补 UTF-8 BOM：ISCC 依靠 BOM 识别 UTF-8 脚本，否则中文消息可能被按 ANSI 解析。
# 源文件已带 BOM（例如用 Inno IDE 保存过）时直接复制，避免双 BOM。
ISS_HEAD=$(head -c 3 "$ISS_SRC" | od -An -tx1 | tr -d ' \n')
if [ "$ISS_HEAD" = "efbbbf" ]; then
    cp "$ISS_SRC" "$STAGE/fftps.iss"
else
    {
        printf '\xEF\xBB\xBF'
        cat "$ISS_SRC"
    } > "$STAGE/fftps.iss"
fi

cat > "$STAGE/defines.iss" << EOF
#define Version "$VERSION"
#define ArchLabel "$ARCH"
#define VersionInfo "$VERSION_INFO"
EOF
if [ "$ARCH" = "arm64" ]; then
    printf '\n#define IsArm64\n' >> "$STAGE/defines.iss"
fi

echo "========================================"
log_info "版本: ${VERSION}（Inno arch: ${ARCH}）"
log_info "产物目录: ${BIN_DIR}"
log_info "输出目录: ${OUTPUT_DIR}"
log_info "Inno 编译器: ${ISCC_BIN}"

( cd "$STAGE" && "${ISCC_RUN[@]}" "${ISCC_FLAGS[@]}" fftps.iss )

OUTPUT_NAME="fftps-${VERSION}-windows-${ARCH}-setup.exe"
if [ ! -f "${STAGE}/${OUTPUT_NAME}" ]; then
    log_error "安装包未生成: ${STAGE}/${OUTPUT_NAME}"
    ls -l "$STAGE" >&2 || true
    exit 1
fi

mv "${STAGE}/${OUTPUT_NAME}" "${OUTPUT_DIR}/${OUTPUT_NAME}"
log_success "构建成功: ${OUTPUT_DIR}/${OUTPUT_NAME}"

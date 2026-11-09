#!/usr/bin/env bash
# FFTPS RPM 打包脚本（fftp-http Web 管理版）
# 使用预编译的 fftpd / fftp-http 生成 x86_64 / aarch64 的 RPM 包。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

ARCH=""
BIN_DIR=""
OUTPUT_DIR="${PROJECT_DIR}/dist"
VERSION=""

log_info() { echo -e "\033[0;34m[INFO]\033[0m $*"; }
log_success() { echo -e "\033[0;32m[SUCCESS]\033[0m $*"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }

usage() {
    cat <<EOF
用法: $0 [选项]

选项:
    -a, --arch ARCH       目标架构 (x86_64, aarch64/arm64) [默认: 自动检测]
    -b, --bin-dir DIR     预编译产物目录 [默认: dist/<rust-target>]
    -o, --output DIR      输出目录 [默认: dist]
    -v, --version VER     包版本 [默认: 读取 Cargo.toml]
    -h, --help            显示帮助

示例:
    $0 -a x86_64 -b dist/x86_64-unknown-linux-gnu
    $0 -a arm64  -b dist/aarch64-unknown-linux-gnu -o dist
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -a|--arch) ARCH="$2"; shift 2 ;;
        -b|--bin-dir) BIN_DIR="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -v|--version) VERSION="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "未知参数: $1"; usage; exit 1 ;;
    esac
done

if [ -z "$ARCH" ]; then
    case "$(uname -m)" in
        x86_64|amd64) ARCH=x86_64 ;;
        aarch64|arm64) ARCH=aarch64 ;;
        *) log_error "无法识别当前架构: $(uname -m)，请用 -a 指定"; exit 1 ;;
    esac
fi

case "$ARCH" in
    x86_64|amd64) RPM_ARCH=x86_64; RUST_TARGET=x86_64-unknown-linux-gnu ;;
    aarch64|arm64) RPM_ARCH=aarch64; RUST_TARGET=aarch64-unknown-linux-gnu ;;
    *) log_error "不支持的架构: $ARCH（仅支持 x86_64 / aarch64）"; exit 1 ;;
esac

if [ -z "$VERSION" ]; then
    VERSION=$(grep -m1 '^version = ' "${PROJECT_DIR}/Cargo.toml" | cut -d'"' -f2)
fi

if [ -z "$BIN_DIR" ]; then
    BIN_DIR="${PROJECT_DIR}/dist/${RUST_TARGET}"
fi

if ! command -v rpmbuild &> /dev/null; then
    log_error "未找到 rpmbuild（Debian/Ubuntu: sudo apt install rpm；Fedora: sudo dnf install rpm-build）"
    exit 1
fi

for bin in fftpd fftp-http; do
    if [ ! -x "${BIN_DIR}/${bin}" ]; then
        log_error "缺少可执行文件: ${BIN_DIR}/${bin}"
        log_info "先执行 scripts/build.sh ${RUST_TARGET}"
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"
TOP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fftp-rpm.XXXXXX")
trap 'rm -rf "$TOP_DIR"' EXIT
mkdir -p "$TOP_DIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

log_info "版本: ${VERSION}"
log_info "架构: ${RPM_ARCH} (${RUST_TARGET})"
log_info "产物目录: ${BIN_DIR}"

rpmbuild -bb \
    --target "$RPM_ARCH" \
    --define "_topdir ${TOP_DIR}" \
    --define "_dbpath ${TOP_DIR}/rpmdb" \
    --define "_fftp_version ${VERSION}" \
    --define "_fftp_bin_dir $(cd "$BIN_DIR" && pwd)" \
    --define "_fftp_project_dir ${PROJECT_DIR}" \
    "${SCRIPT_DIR}/fftp-http.spec"

RPM_FILE=$(find "$TOP_DIR/RPMS" -name '*.rpm' -type f | head -n 1)
if [ -z "$RPM_FILE" ]; then
    log_error "rpmbuild 未生成 RPM 包"
    exit 1
fi

cp "$RPM_FILE" "$OUTPUT_DIR/"
log_success "构建成功: ${OUTPUT_DIR}/$(basename "$RPM_FILE")"

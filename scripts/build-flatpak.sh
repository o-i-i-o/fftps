#!/usr/bin/env sh
# flatpak 打包包装（源码构建 / 预编译产物两种模式）。
#
# 用法: build-flatpak.sh [-i] [-a ARCH] [-b DIR]
#   -i        构建完成后装入当前用户安装（flatpak-builder --install）
#   -a ARCH   目标架构 x86_64 / aarch64 [默认: 宿主架构]
#   -b DIR    预编译模式：直接封装 DIR 下的 fftpd / fftp-http，不再触发 cargo 编译
#
# 预编译模式（CI 打包阶段使用，二进制来自 scripts/build.sh）：
#   ./scripts/build-flatpak.sh -a amd64 -b dist/x86_64-unknown-linux-gnu
#   ./scripts/build-flatpak.sh -a arm64 -b dist/aarch64-unknown-linux-gnu
#
# 源码模式（本地开发，沙箱内 cargo 离线编译）：
#   ./scripts/build-flatpak.sh
#
# 前置：flatpak/flatpak-builder 已安装，且已装 runtime/SDK（一次即可）：
#   flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
#   flatpak install -y flathub org.freedesktop.Platform//26.08 org.freedesktop.Sdk//26.08
#   （源码模式另需 org.freedesktop.Sdk.Extension.rust-stable//26.08）
#
# 产物：dist/flatpak-repo（ostree 仓库）、
#       dist/fftps_<版本>_<x86_64|aarch64>.flatpak（单文件 bundle）
# 状态目录 .flatpak-builder-state 独立于默认 ~/.local/share/flatpak-builder，
# 规避 rofiles 状态损坏问题（损坏时直接删除该目录重建即可）。
set -eu

cd "$(dirname "$0")/.."

app_id=org.fftps.FftpHttp
manifest=packaging/flatpak/org.fftps.FftpHttp.yml
state_dir=.flatpak-builder-state
repo_dir=dist/flatpak-repo
build_dir=dist/flatpak-build

usage() {
    cat << EOF
用法: $0 [-i] [-a ARCH] [-b DIR]

选项:
    -i            构建完成后装入当前用户安装
    -a, --arch ARCH
                  目标架构 x86_64 / aarch64 [默认: 宿主架构]
    -b, --bin-dir DIR
                  预编译模式：封装该目录下的 fftpd / fftp-http（跳过 cargo 编译）
    -h, --help    显示此帮助

示例:
    $0                                          # 源码模式（沙箱内离线 cargo 编译）
    $0 -a amd64 -b dist/x86_64-unknown-linux-gnu   # amd64 预编译打包
    $0 -a arm64 -b dist/aarch64-unknown-linux-gnu  # arm64 预编译打包（arm runner）
EOF
}

install=
bin_dir=
arch=
while [ $# -gt 0 ]; do
    case "$1" in
        -i) install=1; shift ;;
        -a|--arch) arch="$2"; shift 2 ;;
        -b|--bin-dir) bin_dir="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知选项: $1" >&2; usage; exit 1 ;;
    esac
done

if [ -z "$arch" ]; then
    case "$(uname -m)" in
        x86_64|amd64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) echo "无法识别宿主架构: $(uname -m)，请用 -a 指定 x86_64 / aarch64" >&2; exit 1 ;;
    esac
fi
case "$arch" in
    x86_64|amd64) flatpak_arch=x86_64 ;;
    aarch64|arm64) flatpak_arch=aarch64 ;;
    *) echo "不支持的架构: ${arch}（仅 x86_64 / aarch64）" >&2; exit 1 ;;
esac

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
bundle="dist/fftps_${version}_${flatpak_arch}.flatpak"

# 预编译模式：把二进制与 deploy 物料放进临时目录，生成简单安装清单，
# flatpak-builder 只执行安装命令，不参与编译（编译与打包严格分离）。
build_prebuilt() {
    # artifact 下载会丢失可执行位，此处只校验文件存在（清单内 install -Dm755）
    if [ ! -f "${bin_dir}/fftpd" ] || [ ! -f "${bin_dir}/fftp-http" ]; then
        echo "缺少预编译产物: ${bin_dir}/{fftpd,fftp-http}" >&2
        echo "先执行 scripts/build.sh <rust-target>" >&2
        exit 1
    fi

    stage="$(mktemp -d "${TMPDIR:-/tmp}/fftp-flatpak.XXXXXX")"
    trap 'rm -rf "$stage"' EXIT INT TERM

    cp "${bin_dir}/fftpd" "${bin_dir}/fftp-http" "$stage/"
    cp deploy/flatpak/fftp-http-launch.sh "$stage/"
    cp deploy/flatpak/org.fftps.FftpHttp.desktop "$stage/"
    cp deploy/flatpak/org.fftps.FftpHttp.metainfo.xml "$stage/"
    cp deploy/common/fftp-http.svg "$stage/"
    cp deploy/common/config.toml deploy/common/fftp-http.toml "$stage/"

    cat > "$stage/manifest.yml" << 'YAML'
# 由 scripts/build-flatpak.sh -b 生成：只封装预编译二进制与静态物料
id: org.fftps.FftpHttp
runtime: org.freedesktop.Platform
runtime-version: "26.08"
sdk: org.freedesktop.Sdk
command: fftp-http-launch
finish-args:
  - --share=network
  - --filesystem=home
  - --talk-name=org.freedesktop.portal.Desktop
modules:
  - name: fftps
    buildsystem: simple
    build-commands:
      - install -Dm755 fftpd /app/bin/fftpd
      - install -Dm755 fftp-http /app/bin/fftp-http
      - install -Dm755 fftp-http-launch.sh /app/bin/fftp-http-launch
      - install -Dm644 org.fftps.FftpHttp.desktop /app/share/applications/org.fftps.FftpHttp.desktop
      - install -Dm644 org.fftps.FftpHttp.metainfo.xml /app/share/metainfo/org.fftps.FftpHttp.metainfo.xml
      - install -Dm644 fftp-http.svg /app/share/icons/hicolor/scalable/apps/org.fftps.FftpHttp.svg
      - install -Dm644 fftp-http.svg /app/share/pixmaps/fftp-http.svg
      - install -Dm644 config.toml /app/share/fftpd/config.toml
      - install -Dm644 fftp-http.toml /app/share/fftpd/fftp-http.toml
    sources:
      - type: dir
        path: .
YAML

    flatpak-builder --user --force-clean --disable-rofiles-fuse \
        --arch "$flatpak_arch" \
        --state-dir "$state_dir" \
        --repo "$repo_dir" \
        "$build_dir" "$stage/manifest.yml"
}

# 源码模式：沿用 packaging/flatpak 清单，cargo 依赖经 cargo-sources.json vendor
build_source() {
    # 本地网络环境优化（参考 fdebi 的 USTC 镜像策略）：crate 下载主 URL 切到
    # USTC 镜像（文件字节与 static.crates.io 一致，sha256 校验不变），官方地址
    # 保留为兜底。幂等操作；提交 flathub 前重新生成 cargo-sources.json 即还原。
    python3 - packaging/flatpak/cargo-sources.json << 'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    sources = json.load(f)
changed = False
for s in sources:
    url = s.get("url", "")
    if url.startswith("https://static.crates.io/crates/") and "mirror-urls" not in s:
        # static: crates/{name}/{name}-{version}.crate → USTC: api/v1/crates/{name}/{version}/download
        name, filename = url[len("https://static.crates.io/crates/"):].split("/")
        version = filename[len(name) + 1:-len(".crate")]
        s["url"] = f"https://mirrors.ustc.edu.cn/crates.io/api/v1/crates/{name}/{version}/download"
        s["mirror-urls"] = [url]
        changed = True
if changed:
    with open(path, "w") as f:
        json.dump(sources, f, indent=1, sort_keys=True)
    print("cargo-sources.json: 已切换 USTC 镜像")
PY

    # --disable-rofiles-fuse：容器等 fuse 挂载不可用的环境必须加（挂载静默失败时
    # 报 "Build directory ... not initialized"）；桌面环境可去掉，仅损失写保护优化
    flatpak-builder --user --force-clean --disable-rofiles-fuse \
        --arch "$flatpak_arch" \
        --state-dir "$state_dir" \
        --repo "$repo_dir" \
        "$build_dir" "$manifest"
}

if [ -n "$bin_dir" ]; then
    build_prebuilt
else
    build_source
fi

flatpak build-bundle --arch "$flatpak_arch" "$repo_dir" "$bundle" "$app_id"

if [ -n "$install" ]; then
    if [ -n "$bin_dir" ]; then
        # 预编译模式直接安装已生成的 bundle，避免再次进入构建流程
        flatpak install --user --noninteractive "$bundle"
    else
        flatpak-builder --user --install --force-clean --disable-rofiles-fuse \
            --arch "$flatpak_arch" \
            --state-dir "$state_dir" \
            "$build_dir" "$manifest"
    fi
fi

echo "flatpak 构建完成: $bundle"

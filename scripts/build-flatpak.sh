#!/usr/bin/env sh
# flatpak 本地构建包装。
#
# 用法: build-flatpak.sh [-i]
#   -i  构建完成后装入当前用户安装（flatpak-builder --install）
#
# 前置：flatpak/flatpak-builder 已安装，且已装 runtime/SDK（一次即可）：
#   flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
#   flatpak install -y flathub \
#     org.freedesktop.Platform//26.08 org.freedesktop.Sdk//26.08 \
#     org.freedesktop.Sdk.Extension.rust-stable//26.08
#
# 产物：dist/flatpak-repo（ostree 仓库）、dist/fftps_<版本>.flatpak（单文件 bundle）
# 状态目录 .flatpak-builder-state 独立于默认 ~/.local/share/flatpak-builder，
# 规避 rofiles 状态损坏问题（损坏时直接删除该目录重建即可）。
set -eu

cd "$(dirname "$0")/.."

app_id=org.fftps.FftpHttp
manifest=packaging/flatpak/org.fftps.FftpHttp.yml
state_dir=.flatpak-builder-state
repo_dir=dist/flatpak-repo
build_dir=dist/flatpak-build

install=
if [ "${1:-}" = "-i" ]; then
    install=1
fi

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
bundle="dist/fftps_${version}.flatpak"

# 本地网络环境优化（参考 fdebi 的 USTC 镜像策略）：crate 下载主 URL 切到
# USTC 镜像（文件字节与 static.crates.io 一致，sha256 校验不变），官方地址
# 保留为兜底。幂等操作；提交 flathub 前重新生成 cargo-sources.json 即还原。
python3 - packaging/flatpak/cargo-sources.json <<'PY'
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
    --state-dir "$state_dir" \
    --repo "$repo_dir" \
    "$build_dir" "$manifest"

flatpak build-bundle "$repo_dir" "$bundle" "$app_id"

if [ -n "$install" ]; then
    flatpak-builder --user --install --force-clean --disable-rofiles-fuse \
        --state-dir "$state_dir" \
        "$build_dir" "$manifest"
fi

echo "flatpak 构建完成: $bundle"

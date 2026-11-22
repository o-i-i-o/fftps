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

flatpak-builder --user --force-clean \
    --state-dir "$state_dir" \
    --repo "$repo_dir" \
    "$build_dir" "$manifest"

flatpak build-bundle "$repo_dir" "$bundle" "$app_id"

if [ -n "$install" ]; then
    flatpak-builder --user --install --force-clean \
        --state-dir "$state_dir" \
        "$build_dir" "$manifest"
fi

echo "flatpak 构建完成: $bundle"

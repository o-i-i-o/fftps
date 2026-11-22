#!/usr/bin/env sh
# 从 Cargo.toml 提取 workspace 版本，供 meson project() 声明版本号使用。
# 单一版本来源仍是 Cargo.toml（[workspace.package].version），
# meson / deb / MSI / flatpak 一律经此脚本读取，避免多处维护。
set -eu

grep -m1 '^version = ' "$(dirname "$0")/../Cargo.toml" | sed 's/version = "\(.*\)"/\1/'

#!/bin/sh
# flatpak 桌面入口包装：沙箱内没有 systemd --user（launch 里 systemctl
# 静默失败），因此先在沙箱内脱离终端拉起 fftpd（重复启动会因端口占用
# 自行退出，落日志到状态目录），再交给 fftp-http launch 完成前端启动、
# 健康探测与浏览器打开（xdg-open 经 portal 打开宿主默认浏览器）。
set -eu

bin_dir="$(cd "$(dirname "$0")" && pwd)"
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/fftpd"
mkdir -p "$state_dir"

# fftpd 前台常驻进程，后台化脱离本脚本生命周期；已运行实例会写日志后退出
setsid "$bin_dir/fftpd" >> "$state_dir/fftpd.log" 2>&1 < /dev/null &

exec "$bin_dir/fftp-http" launch

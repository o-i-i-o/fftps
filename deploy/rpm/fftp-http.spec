# FFTPS RPM 规格（fftp-http Web 管理版）
#
# 由 scripts/build-rpm.sh 调用，使用预编译的 fftpd / fftp-http：
#   rpmbuild -bb --target aarch64 \
#       --define "_fftp_version 0.1.1" \
#       --define "_fftp_bin_dir $PWD/dist/aarch64-unknown-linux-gnu" \
#       --define "_fftp_project_dir $PWD" \
#       deploy/rpm/fftp-http.spec

%global debug_package %{nil}
# 交叉打包 aarch64 时宿主 strip 无法处理目标 ELF；二进制在 Cargo 构建时已 strip
%global __strip /bin/true
%global __objcopy /bin/true

%{!?_fftp_version:%global _fftp_version 0.1.1}
%{!?_fftp_bin_dir:%global _fftp_bin_dir %{_sourcedir}}
%{!?_fftp_project_dir:%global _fftp_project_dir .}

Name:           fftp-http
Version:        %{_fftp_version}
Release:        1
Summary:        SFTP/FTP(FTPS) server suite with Web management frontend
License:        GPL-3.0
URL:            https://github.com/fftps/fftps
Conflicts:      fftps
Conflicts:      fftp-gui
Requires:       glibc
# 交叉架构打包时关闭宿主依赖扫描，依赖已显式声明
AutoReqProv:    no

%description
Contains the fftpd FTP(FTPS)/SFTP server backend and the fftp-http
Web (HTTP/HTTPS) management frontend, each with its own systemd user
service unit. A desktop entry starts the Web service on demand and
opens it in the default browser.

%install
rm -rf %{buildroot}
install -d %{buildroot}/usr/bin
install -m 0755 %{_fftp_bin_dir}/fftpd %{buildroot}/usr/bin/fftpd
install -m 0755 %{_fftp_bin_dir}/fftp-http %{buildroot}/usr/bin/fftp-http

install -d %{buildroot}/usr/lib/systemd/user
install -m 0644 %{_fftp_project_dir}/deploy/common/fftpd.service %{buildroot}/usr/lib/systemd/user/fftpd.service
install -m 0644 %{_fftp_project_dir}/deploy/common/fftp-http.service %{buildroot}/usr/lib/systemd/user/fftp-http.service

install -d %{buildroot}/usr/share/applications
install -m 0644 %{_fftp_project_dir}/deploy/common/fftp-http.desktop %{buildroot}/usr/share/applications/fftp-http.desktop

install -d %{buildroot}/usr/share/icons/hicolor/scalable/apps
install -m 0644 %{_fftp_project_dir}/deploy/common/fftp-http.svg \
    %{buildroot}/usr/share/icons/hicolor/scalable/apps/fftp-http.svg
install -d %{buildroot}/usr/share/pixmaps
install -m 0644 %{_fftp_project_dir}/deploy/common/fftp-http.svg %{buildroot}/usr/share/pixmaps/fftp-http.svg

install -d %{buildroot}/usr/share/fftpd
install -m 0644 %{_fftp_project_dir}/deploy/common/config.toml %{buildroot}/usr/share/fftpd/config.toml
install -m 0644 %{_fftp_project_dir}/deploy/common/fftp-http.toml \
    %{buildroot}/usr/share/fftpd/fftp-http.toml

install -d %{buildroot}/usr/share/licenses/fftp-http
install -m 0644 %{_fftp_project_dir}/LICENSE %{buildroot}/usr/share/licenses/fftp-http/LICENSE

%post
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q || :
fi
for runtime_dir in /run/user/[0-9]*; do
    [ -d "$runtime_dir" ] || continue
    uid="${runtime_dir##*/}"
    user_name=$(getent passwd "$uid" | cut -d: -f1)
    [ -n "$user_name" ] || continue
    XDG_RUNTIME_DIR="$runtime_dir" su -s /bin/sh "$user_name" \
        -c "systemctl --user daemon-reload" >/dev/null 2>&1 || :
    # $1 == 1 首次安装：启用并启动 fftpd；升级时只重启已启用且在运行的服务
    if [ "$1" -eq 1 ]; then
        XDG_RUNTIME_DIR="$runtime_dir" su -s /bin/sh "$user_name" \
            -c "systemctl --user enable --now fftpd" >/dev/null 2>&1 || :
    else
        for service in fftpd fftp-http; do
            if XDG_RUNTIME_DIR="$runtime_dir" su -s /bin/sh "$user_name" \
                -c "systemctl --user is-enabled $service" 2>/dev/null | grep -q '^enabled'; then
                if XDG_RUNTIME_DIR="$runtime_dir" su -s /bin/sh "$user_name" \
                    -c "systemctl --user is-active --quiet $service" >/dev/null 2>&1; then
                    XDG_RUNTIME_DIR="$runtime_dir" su -s /bin/sh "$user_name" \
                        -c "systemctl --user restart $service" >/dev/null 2>&1 || :
                fi
            fi
        done
    fi
done
exit 0

%preun
if [ "$1" -eq 0 ]; then
    for runtime_dir in /run/user/[0-9]*; do
        [ -d "$runtime_dir" ] || continue
        uid="${runtime_dir##*/}"
        user_name=$(getent passwd "$uid" | cut -d: -f1)
        [ -n "$user_name" ] || continue
        for service in fftpd fftp-http; do
            XDG_RUNTIME_DIR="$runtime_dir" su -s /bin/sh "$user_name" \
                -c "systemctl --user disable --now $service" >/dev/null 2>&1 || :
        done
    done
fi
exit 0

%postun
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q || :
fi
for runtime_dir in /run/user/[0-9]*; do
    [ -d "$runtime_dir" ] || continue
    uid="${runtime_dir##*/}"
    user_name=$(getent passwd "$uid" | cut -d: -f1)
    [ -n "$user_name" ] || continue
    XDG_RUNTIME_DIR="$runtime_dir" su -s /bin/sh "$user_name" \
        -c "systemctl --user daemon-reload" >/dev/null 2>&1 || :
done
exit 0

%files
%defattr(-,root,root,-)
%license /usr/share/licenses/fftp-http/LICENSE
/usr/bin/fftpd
/usr/bin/fftp-http
/usr/lib/systemd/user/fftpd.service
/usr/lib/systemd/user/fftp-http.service
/usr/share/applications/fftp-http.desktop
/usr/share/icons/hicolor/scalable/apps/fftp-http.svg
/usr/share/pixmaps/fftp-http.svg
/usr/share/fftpd/config.toml
/usr/share/fftpd/fftp-http.toml

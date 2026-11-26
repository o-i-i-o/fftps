# fftps meson 编排骨架：编译仍由 cargo 完成，meson 负责触发与安装清单。
#
# 分工：
#   cargo workspace —— 依赖解析、编译（含 zigbuild/xwin 交叉编译策略，见 scripts/build.sh）
#   meson           —— custom_target 触发 cargo、声明式安装二进制与 deploy/ 打包物料
#                      （systemd 单元、桌面入口、图标、配置模板），供 deb / flatpak 复用
#
# 常用命令：
#   meson setup builddir                        # 宿主默认目标，release
#   meson setup builddir -Dprofile=debug        # debug 构建
#   meson setup builddir -Dcargo_target=<triple>  # 交叉目标（工具链自备）
#   meson compile -C builddir && meson install -C builddir
#
# 已知限制：rust 源码改动 ninja 不会自动触发重编，需重跑 meson compile。
project(
  'fftps',
  version: run_command('build-aux/version.sh', check: true).stdout().strip(),
  license: 'GPL-3.0',
  meson_version: '>= 1.1.0',
  default_options: [
    'prefix=/usr',
    'warning_level=1',
  ],
)

cargo = find_program('cargo', required: true)
cargo_wrap = find_program('build-aux/cargo-build.sh')

cargo_target = get_option('cargo_target')
profile = get_option('profile')

# Windows 交付物带 .exe 后缀；Linux 为裸二进制名
bins = ['fftpd', 'fftp-http']
if host_machine.system() == 'windows'
  bins = ['fftpd.exe', 'fftp-http.exe']
endif

built_bins = custom_target(
  'cargo-bins',
  input: ['Cargo.toml', 'Cargo.lock'],
  output: bins,
  command: [cargo_wrap, '@OUTDIR@', cargo_target, profile] + bins,
  build_by_default: true,
  install: true,
  install_dir: get_option('bindir'),
)

# Linux 才安装系统集成物料；Windows 交付物只含 exe（安装向导由 scripts/build-inno.sh 另行打包）
if host_machine.system() != 'windows'
  if get_option('flatpak')
    # flatpak 沙箱交付：没有 systemd --user，daemon 由启动包装在沙箱内拉起；
    # 桌面入口/图标必须以 app-id 命名，另附 AppStream metainfo。
    # 沙箱入口命令不带 .sh 后缀（flatpak command 与 desktop Exec 引用）
    configure_file(
      input: 'deploy/flatpak/fftp-http-launch.sh',
      output: 'fftp-http-launch',
      copy: true,
      install: true,
      install_dir: get_option('bindir'),
      install_mode: 'rwxr-xr-x',
    )
    install_data(
      'deploy/flatpak/org.fftps.Fftps.desktop',
      install_dir: get_option('datadir') / 'applications',
    )
    install_data(
      'deploy/flatpak/org.fftps.Fftps.metainfo.xml',
      install_dir: get_option('datadir') / 'metainfo',
    )
    configure_file(
      input: 'deploy/common/fftps.svg',
      output: 'org.fftps.Fftps.svg',
      copy: true,
      install: true,
      install_dir: get_option('datadir') / 'icons/hicolor/scalable/apps',
    )
  else
    install_data(
      'deploy/common/fftpd.service',
      'deploy/common/fftp-http.service',
      install_dir: 'lib/systemd/user',
    )
    install_data(
      'deploy/common/fftps.desktop',
      install_dir: get_option('datadir') / 'applications',
    )
    install_data(
      'deploy/common/fftps.svg',
      install_dir: get_option('datadir') / 'icons/hicolor/scalable/apps',
    )
  endif
  install_data(
    'deploy/common/fftps.svg',
    install_dir: get_option('datadir') / 'pixmaps',
  )
  install_data(
    'deploy/common/config.toml',
    'deploy/common/fftp-http.toml',
    install_dir: get_option('datadir') / 'fftpd',
  )
endif

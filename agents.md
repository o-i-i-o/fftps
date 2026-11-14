# 基础架构
- 本项目是 fftps：基于 Rust 的 FTP/FTPS/SFTP 服务端套件（fftpd）+ Web 管理前端（fftp-http）。

- UOS/麒麟一等公民，支持在 UOS/麒麟上直接运行；管理界面通过浏览器访问，无需桌面 GUI 框架。

- 本项目linux平台基于用户态服务 运行，针对桌面环境单用户环境，用户目录基于 \~，前端默认建议\~/Desktop/ ，Windows平台 目录基于 C:/Users/用户名 ,默认建议C:/Users/用户名/Desktop/；管理端可填写任意有权限的绝对路径，后端校验目录有效性与权限

- 设计目标 ，fftpd稳定后台驻守提供(s)ftp(s)服务，fftp-http管理按需启动、自动关闭。保证(s)ftp(s)服务本身永远占用最小资源。

# 质量保证
- 本项目采用 Rust 语言编写，确保代码质量和性能。
- 本项目采用 Rust 社区的代码规范，确保代码可读性和可维护性。
- 本项目采用 Rust 社区的测试框架，确保代码质量和稳定性。
- 每轮执行cargo test --workspace --offline 确保代码质量和稳定性。
- 每轮执行cargo clippy --workspace --all-targets --offline 确保代码质量和稳定性。
- 每轮执行cargo fmt --workspace 确保代码格式一致。
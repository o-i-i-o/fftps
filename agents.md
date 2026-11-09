# 本项目是 fftps：基于 Rust 的 FTP/FTPS/SFTP 服务端套件（fftpd）+ Web 管理前端（fftp-http）。

# UOS/麒麟一等公民，支持在 UOS/麒麟上直接运行；管理界面通过浏览器访问，无需桌面 GUI 框架。

# 本项目linux平台基于用户态服务 运行，用户目录基于 \~，默认\~/Desktop/ ，Windows平台 目录基于 $users ,默认$users/Desktop/

# 设计目标 ，fftpd稳定后台驻守提供(s)ftp(s)服务，fftp-http管理按需启动、自动关闭。保证(s)ftp(s)服务本身永远占用最小资源。

//! Windows 服务入口（SCM 调度 + 服务控制处理）
//!
//! 具体样板由 `fftp_common::windows_service_entry!` 生成；本模块只声明
//! 服务名与运行逻辑。

fftp_common::windows_service_entry!("fftpd", crate::run_daemon_blocking);

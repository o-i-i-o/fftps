//! fftp-ftp：fftps 的 FTP(FTPS) 服务端 crate
//!
//! 迁移整合自 wftpd-windows（libunftp 组装路线）与 wftpd-linux（认证/存储择优），
//! 对接统一共享层 [`fftp_common`]（配置/用户/配额/限速/防护/指标/审计）。
//!
//! # 模块结构
//! - [`service`]：服务组装与生命周期（[`FtpService`] / [`RunningFtpService`]）；
//! - [`auth`]：认证链、会话跟踪、用户详情与权限映射；
//! - [`storage`]：存储封装层（路径 jail + 配额 + 限速）；
//! - [`path_safety`]：虚拟路径净化与真实路径防逃逸；
//! - [`cert_gen`]：FTPS 自签证书生成（rcgen）；
//! - [`listeners`]：libunftp 数据/会话事件 → 审计与指标；
//! - [`active_mode`] / [`passive_mode`] / [`ip_utils`]：主动/被动模式策略与 IP 分类。
//!
//! # 存储栈组装（docs/design.md §4 Windows 组装路线）
//!
//! ```text
//! RestrictingVfs<JailFilesystem<RooterVfs<Filesystem, FtpUser, Meta>>, FtpUser, Meta>
//! ```
//!
//! [`JailFilesystem`](storage::JailFilesystem) 位于 rooter 之上，负责虚拟路径
//! 净化（防止 `..` 越界进入 rooter 的 unwrap/下溢 panic 分支）、真实路径防逃逸、
//! 配额记账与传输限速；会话根隔离由 `unftp-sbe-rooter` 承担，
//! 权限位映射由 `unftp-sbe-restrict` 承担。
//!
//! # 使用形态（fftpd 组装）
//!
//! ```no_run
//! use std::sync::{Arc, Mutex, RwLock};
//! use fftp_ftp::FtpService;
//! use fftp_common::{Config, Logging, LoggingConfig, UserManager};
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let service = FtpService::new(
//!     Arc::new(RwLock::new(Config::default())),
//!     Arc::new(Mutex::new(UserManager::new())),
//!     Arc::new(Logging::new(&LoggingConfig::default())),
//! );
//! let running = service.start().await?;
//! // 热重载：running.stop().await 后 service.start() 重新启动
//! running.stop().await;
//! # Ok(())
//! # }
//! ```

pub mod active_mode;
pub mod auth;
pub mod cert_gen;
pub mod ip_utils;
pub mod listeners;
pub mod passive_mode;
pub mod path_safety;
pub mod service;
pub mod storage;

pub use auth::{FtpAuthenticator, FtpUser, FtpUserDetailProvider, RootMode, SessionTracker};
pub use service::{FtpService, FtpStorage, RunningFtpService};

#[cfg(test)]
pub(crate) mod test_support {
    //! 测试共享设施
    use std::sync::Mutex;

    /// 修改路径环境变量（`FFTPD_CONFIG_DIR` / `FFTPD_STATE_DIR`）前必须持有的锁，
    /// 防止并行测试互相踩踏（Rust 2024 中 `std::env::set_var` 为 unsafe）
    pub static ENV_LOCK: Mutex<()> = Mutex::new(());
}

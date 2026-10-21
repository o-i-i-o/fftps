//! fftp-sftp：fftps SFTP 服务端（russh 传输层 + 并入的 russh-sftp 协议层）
//!
//! 对接 `fftp-common` 共享层：认证走 [`fftp_common::users::UserManager`]，
//! 配置走 [`fftp_common::config::Config`]，防护/限速/配额/指标/审计分别接
//! `fail2ban` / `rate_limit` / `quota` / `metrics` / `logging`，本 crate 不重复实现这些能力。
//!
//! # 模块结构
//! - [`service`]：服务组装与生命周期（[`SftpService`] / [`RunningService`]）
//! - [`handler`]：`russh::server::Handler` 实现（认证 + 会话通道管理）
//! - [`session`]：SFTP 子系统会话，实现协议层 [`protocol::Handler`] 并路由到业务逻辑
//! - [`protocol`]：并入的 russh-sftp 协议层（报文编解码、报文循环、Handler trait）
//! - [`attr_ops`] / [`file_ops`] / [`dir_ops`] / [`link_ops`] / [`lock_ops`] / [`extended`]：
//!   各 SFTP 命令业务实现（含 copy-file / hardlink / LOCK / md5sum / fsync / limits 等扩展）
//! - [`path_resolve`]：路径净化与 home jail（跨平台）
//! - [`host_key`]：Ed25519 主机密钥生成/加载/轮换
//! - [`state`]：会话状态；[`types`]：业务常量与句柄类型
//!
//! # 使用示例
//! ```no_run
//! use std::sync::{Arc, Mutex};
//! use fftp_common::config::Config;
//! use fftp_common::users::UserManager;
//! use fftp_sftp::SftpService;
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let config = Arc::new(Mutex::new(Config::default()));
//! let users = Arc::new(Mutex::new(UserManager::new()));
//! let service = SftpService::new(config, users);
//! let running = service.start().await?;
//! println!("SFTP listening on {}", running.addr());
//! // 配置变更时：running.stop().await; service.start().await?;
//! # Ok(())
//! # }
//! ```

// SFTP 报文与缓冲区长度均受协议层 `Config::max_client_packet_len` 钳制（远小于 u32::MAX），
// wire 字段的 usize→u32、u64→usize 转换在协议约束下不会溢出，故 crate 级放行该 lint
#![allow(clippy::cast_possible_truncation)]

// 并入的 russh-sftp 协议层沿用上游 `bitflags!` / `derive(Serialize)` 宏展开方式
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate serde;

pub mod attr_ops;
pub mod dir_ops;
pub mod extended;
pub mod file_ops;
pub mod handler;
pub mod host_key;
pub mod link_ops;
pub mod lock_ops;
pub mod path_resolve;
pub mod protocol;
pub mod service;
pub mod session;
pub mod state;
#[cfg(test)]
mod test_util;
pub mod types;

pub use handler::{SftpHandler, SessionTracker};
pub use protocol::message::OpenFlags;
pub use service::{RunningService, SftpService};
pub use session::Session;
pub use state::SftpState;
pub use types::{
    DirEntry, HANDLE_TIMEOUT_SECS, MAX_HANDLES, SFTP_READ_BUFFER_SIZE, SFTP_WRITE_FLUSH_THRESHOLD,
    SftpFileHandle,
};

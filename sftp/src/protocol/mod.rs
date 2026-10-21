//! SFTP 协议层（并入自 russh-sftp v3.0.1，裁剪 client 侧并新增 LOCK/UNLOCK）
//!
//! 模块结构：
//! - [`message`]：v3 报文结构与编解码（serde 驱动）
//! - [`de`] / [`ser`]：二进制反序列化/序列化器
//! - [`error`]：协议层错误
//! - [`extensions`]：OpenSSH 扩展常量与负载结构
//! - [`server`]：报文循环与业务 [`server::Handler`] trait
//!
//! 上游代码未按本项目 pedantic 约束编写，模块级统一放行。

#![allow(clippy::pedantic)]

mod buf;
pub mod de;
pub mod error;
pub mod extensions;
pub mod message;
pub mod ser;
pub mod server;
pub(crate) mod utils;

pub use error::Error;
pub use message::{
    Attrs, Data, ExtendedReply, File, FileAttributes, Handle, Name, Open, OpenFlags, Packet,
    Status, StatusCode, Version, VERSION,
};
pub use server::{run_with_config, Config, Handler, StatusReply};

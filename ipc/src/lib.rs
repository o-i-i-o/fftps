//! fftp-ipc：fftps 前后端通信层
//!
//! 轻量 JSON 帧协议（`u32 BE 长度` + JSON），统一运行在平台传输上：
//! Linux 为 Unix domain socket（0600），Windows 为 Named Pipe。
//! 前端 [`client`]、后端 [`server`] 复用同一套 [`protocol`] 类型。

pub mod client;
pub mod framing;
pub mod protocol;
pub mod server;
pub mod transport;

pub use client::{Client, ClientError, RequestError};
pub use protocol::{Command, ErrorCode, Event, Message, ServiceTarget};
pub use server::{serve, Handler, HandlerError};

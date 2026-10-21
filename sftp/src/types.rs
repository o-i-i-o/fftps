//! SFTP 业务常量与句柄类型
//!
//! 协议常量与消息结构在 [`crate::protocol`]（并入的 russh-sftp 协议层），
//! 此处仅保留业务侧的限值常量与会话句柄类型。

use crate::protocol::FileAttributes;

/// 单会话最大打开句柄数
pub const MAX_HANDLES: usize = 256;
/// 单次 READ 返回数据的上限
pub const SFTP_READ_BUFFER_SIZE: usize = 128 * 1024;
/// 写缓冲落盘阈值
pub const SFTP_WRITE_FLUSH_THRESHOLD: usize = 64 * 1024;
/// 句柄空闲回收超时（秒）
pub const HANDLE_TIMEOUT_SECS: u64 = 1800;
/// READDIR 单批返回条目数
pub const MAX_READDIR_ENTRIES: usize = 100;

/// 打开的文件/目录句柄
pub enum SftpFileHandle {
    /// 普通文件句柄
    File {
        /// 服务器上的绝对路径
        path: std::path::PathBuf,
        file: tokio::fs::File,
        /// 是否持有 LOCK（advisory）
        locked: bool,
        /// 打开前文件是否已存在（审计/配额用）
        existed: bool,
        written_bytes: u64,
        read_bytes: u64,
        pending_flush_bytes: u64,
        last_access: std::time::Instant,
        /// 配额预留字节数
        quota_reserved: u64,
        /// 打开前文件大小（配额按增量计）
        original_size: u64,
    },
    /// 目录句柄
    Dir {
        /// 服务器上的绝对路径
        path: std::path::PathBuf,
        entries: Vec<DirEntry>,
        index: usize,
        last_access: std::time::Instant,
    },
}

/// 目录项缓存
#[derive(Clone)]
pub struct DirEntry {
    pub name: String,
    pub attrs: FileAttributes,
}

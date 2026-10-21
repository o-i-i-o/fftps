//! SFTP 协议常量、状态码与句柄类型

/// `SSH_FXF_*`：`SSH_FXP_OPEN` 的打开标志位
pub const SSH_FXF_READ: u32 = 0x0000_0001;
pub const SSH_FXF_WRITE: u32 = 0x0000_0002;
pub const SSH_FXF_APPEND: u32 = 0x0000_0004;
pub const SSH_FXF_CREAT: u32 = 0x0000_0008;
pub const SSH_FXF_TRUNC: u32 = 0x0000_0010;
pub const SSH_FXF_EXCL: u32 = 0x0000_0020;

/// `SSH_FXP_*`：SFTP 报文类型码（draft-ietf-secsh-filexfer）
pub const SSH_FXP_INIT: u8 = 1;
pub const SSH_FXP_VERSION: u8 = 2;
pub const SSH_FXP_OPEN: u8 = 3;
pub const SSH_FXP_CLOSE: u8 = 4;
pub const SSH_FXP_READ: u8 = 5;
pub const SSH_FXP_WRITE: u8 = 6;
pub const SSH_FXP_LSTAT: u8 = 7;
pub const SSH_FXP_FSTAT: u8 = 8;
pub const SSH_FXP_SETSTAT: u8 = 9;
pub const SSH_FXP_FSETSTAT: u8 = 10;
pub const SSH_FXP_OPENDIR: u8 = 11;
pub const SSH_FXP_READDIR: u8 = 12;
pub const SSH_FXP_REMOVE: u8 = 13;
pub const SSH_FXP_MKDIR: u8 = 14;
pub const SSH_FXP_RMDIR: u8 = 15;
pub const SSH_FXP_REALPATH: u8 = 16;
pub const SSH_FXP_STAT: u8 = 17;
pub const SSH_FXP_RENAME: u8 = 18;
pub const SSH_FXP_READLINK: u8 = 19;
pub const SSH_FXP_SYMLINK: u8 = 20;
/// v5+ 文件区间锁定请求（draft 中的 BLOCK）
pub const SSH_FXP_BLOCK: u8 = 22;
/// v5+ 文件区间解锁请求（draft 中的 UNBLOCK）
pub const SSH_FXP_UNBLOCK: u8 = 23;
pub const SSH_FXP_EXTENDED: u8 = 200;

/// `SSH_FXP_*`：应答报文类型码
pub const SSH_FXP_STATUS: u8 = 101;
pub const SSH_FXP_HANDLE: u8 = 102;
pub const SSH_FXP_DATA: u8 = 103;
pub const SSH_FXP_NAME: u8 = 104;
pub const SSH_FXP_ATTRS: u8 = 105;
pub const SSH_FXP_EXTENDED_REPLY: u8 = 124;

/// `SSH_FX_*`：`SSH_FXP_STATUS` 状态码
pub const SSH_FX_OK: u32 = 0;
pub const SSH_FX_EOF: u32 = 1;
pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
pub const SSH_FX_FAILURE: u32 = 4;
pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;

/// `SSH_FILEXFER_ATTR_*`：属性标志位
pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x0000_0001;
pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x0000_0002;
pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x0000_0004;
pub const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x0000_0008;
pub const SSH_FILEXFER_ATTR_ACCESSTIME: u32 = 0x0000_0010;
pub const SSH_FILEXFER_ATTR_CREATETIME: u32 = 0x0000_0020;
/// Windows 扩展属性（createtime 子属性）
pub const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x8000_0000;

/// 单个 SFTP 包的最大长度（不含长度前缀）
pub const MAX_PACKET_SIZE: usize = 256 * 1024;
/// 会话接收缓冲上限，超出视为溢出攻击
pub const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024;
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
    pub is_dir: bool,
    pub size: u64,
    pub mtime: u32,
}

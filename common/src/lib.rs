//! fftp-common：fftps 前后端共享层
//!
//! 提供前后端共用的基础设施：
//! - [`config`]：config.toml 统一 schema（前后端共享同一份类型定义，避免格式漂移）
//! - [`paths`]：跨平台路径解析（Linux XDG / Windows ProgramData，docs/design.md §5.3）
//! - [`users`]：users.json 用户库（Argon2id 口令哈希 + 登录时惰性重哈希升级）
//! - [`logging`]：tracing 初始化、内存环形缓冲、日志文件管理与文件操作审计
//! - [`quota`]：用户磁盘配额统计与超限拦截
//! - [`rate_limit`]：全局/每用户传输限速与连接数治理
//! - [`fail2ban`]：登录失败统计、阈值封禁与持久化
//! - [`metrics`]：prometheus 运行指标

pub mod config;
pub mod fail2ban;
pub mod logging;
pub mod metrics;
pub mod paths;
pub mod quota;
pub mod rate_limit;
pub mod users;

pub use config::{
    Config, ConnectionMode, FtpConfig, FtpsConfig, LoggingConfig, SecurityConfig, SftpConfig,
};
pub use fail2ban::{BanEvent, Fail2BanManager};
pub use logging::{FileOpLogEntry, LogEntry, LogFileInfo, Logging};
pub use quota::QuotaManager;
pub use rate_limit::{ConnectionLimiter, RateLimiter};
pub use users::{Permissions, User, UserManager, is_safe_username};

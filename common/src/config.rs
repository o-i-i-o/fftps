//! 统一配置 schema（docs/design.md §5.1 的 config.toml）
//!
//! 以 Windows 侧实现的字段全集为基础，并补 Linux 侧的 logging 增量字段；
//! 前后端共用同一份类型定义，避免格式漂移。
//!
//! FTP 与 SFTP 的路径策略（符号链接）和 IP 黑白名单各自独立配置在
//! `[ftp]` / `[sftp]` 下，不再共用 `[security]` 全局字段。
//!
//! 可选值语义：`masquerade_address` / `anonymous_home` / `ftp_root` 与
//! `cert_path` / `key_path` / `host_key_path` / `log_dir` 在 TOML 里为
//! `String`，空串表示未设置（比 `Option<String>` 对配置文件更友好），
//! 用对应的 `*_opt()` / `resolved_*()` 辅助方法取值。

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::paths;

/// 空串（含全空白）视为未设置，返回原始字符串
fn non_empty(s: &str) -> Option<&str> {
    if s.trim().is_empty() { None } else { Some(s) }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub ftp: FtpConfig,
    pub sftp: SftpConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FtpConfig {
    pub enabled: bool,
    pub bind_ip: String,
    pub port: u16,
    pub welcome_message: String,
    pub allow_anonymous: bool,
    /// 匿名用户主目录，空串 = 未设置
    pub anonymous_home: String,
    /// 被动模式端口区间（含端点）
    pub passive_ports: (u16, u16),
    /// 单连接限速（KB/s），0 = 不限速
    pub max_speed_kbps: u64,
    /// 被动模式对外通告地址，空串 = 使用实际连接地址。
    ///
    /// libunftp 的 PASV 应答只支持 IPv4 地址或域名；IPv6 客户端使用 EPSV。
    pub masquerade_address: String,
    /// 空闲超时（秒）
    pub idle_timeout: u64,
    /// FTP 根目录，空串 = 各用户 home
    pub ftp_root: String,
    /// 单用户最大并发会话数，0 = 不限制
    pub max_sessions_per_user: u32,
    /// 是否允许跟随/创建符号链接
    pub allow_symlinks: bool,
    /// IP 白名单（CIDR），空表 = 全部放行
    pub allowed_ips: Vec<String>,
    /// IP 黑名单（CIDR），优先于白名单
    pub denied_ips: Vec<String>,
    pub ftps: FtpsConfig,
}

impl Default for FtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_ip: "0.0.0.0".to_string(),
            port: default_ftp_port(),
            welcome_message: "Welcome to fftps".to_string(),
            allow_anonymous: false,
            anonymous_home: String::new(),
            passive_ports: (50000, 51000),
            max_speed_kbps: 0,
            masquerade_address: String::new(),
            idle_timeout: 15,
            ftp_root: String::new(),
            max_sessions_per_user: 5,
            allow_symlinks: false,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            denied_ips: vec![],
            ftps: FtpsConfig::default(),
        }
    }
}

/// FTP 默认监听端口。
/// Windows 下 fftpd 以 SCM 服务（LocalSystem）运行，可绑定标准端口 21；
/// Linux 下为无特权用户态服务，绑定 <1024 端口会 EPERM，默认改用 2121。
#[cfg(target_os = "windows")]
const fn default_ftp_port() -> u16 {
    21
}

#[cfg(not(target_os = "windows"))]
const fn default_ftp_port() -> u16 {
    2121
}

impl FtpConfig {
    /// 匿名用户主目录（空串 = 未设置）
    #[must_use]
    pub fn anonymous_home_opt(&self) -> Option<&str> {
        non_empty(&self.anonymous_home)
    }

    /// 被动模式对外通告地址（空串 = 未设置）
    #[must_use]
    pub fn masquerade_address_opt(&self) -> Option<&str> {
        non_empty(&self.masquerade_address)
    }

    /// FTP 根目录（空串 = 未设置，即各用户 home）
    #[must_use]
    pub fn ftp_root_opt(&self) -> Option<&str> {
        non_empty(&self.ftp_root)
    }

    /// FTP 独立 IP 黑白名单判定
    #[must_use]
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        Config::is_ip_allowed_for(&self.allowed_ips, &self.denied_ips, ip)
    }
}

/// FTPS（显式 TLS）子表 `[ftp.ftps]`
///
/// 启用后强制 TLS：控制通道与数据通道都拒绝未升级的客户端，
/// 不再提供“启用 FTPS 但允许明文”的半开配置。需要明文 FTP 时直接关闭
/// `enabled`。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FtpsConfig {
    pub enabled: bool,
    /// 证书路径，空串 = 自动生成（rcgen）
    pub cert_path: String,
    /// 私钥路径，空串 = 自动生成（rcgen）
    pub key_path: String,
}

impl FtpsConfig {
    /// 证书路径（空串 = 未设置）
    #[must_use]
    pub fn cert_path_opt(&self) -> Option<&str> {
        non_empty(&self.cert_path)
    }

    /// 私钥路径（空串 = 未设置）
    #[must_use]
    pub fn key_path_opt(&self) -> Option<&str> {
        non_empty(&self.key_path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SftpConfig {
    pub enabled: bool,
    pub bind_ip: String,
    pub port: u16,
    /// 主机密钥路径，空串 = [`paths::default_host_key_path`]
    pub host_key_path: String,
    pub max_auth_attempts: u32,
    /// 允许口令认证（与 `public_key_auth` 至少开启一个）
    pub password_auth: bool,
    /// 允许公钥认证（与 `password_auth` 至少开启一个）
    pub public_key_auth: bool,
    /// 登录宽限时间（秒）：连接建立后必须在此时间内完成认证
    pub login_grace_time: u64,
    /// 会话空闲超时（秒）：认证完成后的无活动断开时间
    pub idle_timeout: u64,
    /// keepalive 发送间隔（秒），0 = 关闭
    pub keepalive_interval: u64,
    /// 连续未响应的 keepalive 次数上限
    pub keepalive_max: u32,
    /// 单用户最大并发会话数，0 = 不限制
    pub max_sessions_per_user: u32,
    /// 单连接限速（KB/s），0 = 不限速
    pub max_speed_kbps: u64,
    /// 是否允许跟随/创建符号链接
    pub allow_symlinks: bool,
    /// IP 白名单（CIDR），空表 = 全部放行
    pub allowed_ips: Vec<String>,
    /// IP 黑名单（CIDR），优先于白名单
    pub denied_ips: Vec<String>,
}

impl Default for SftpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_ip: "0.0.0.0".to_string(),
            port: 2222,
            host_key_path: String::new(),
            max_auth_attempts: 3,
            password_auth: true,
            public_key_auth: true,
            login_grace_time: 60,
            idle_timeout: 3600,
            keepalive_interval: 30,
            keepalive_max: 3,
            max_sessions_per_user: 5,
            max_speed_kbps: 0,
            allow_symlinks: false,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            denied_ips: vec![],
        }
    }
}

impl SftpConfig {
    /// 解析后的主机密钥路径（空串时回退 [`paths::default_host_key_path`]）
    #[must_use]
    pub fn resolved_host_key_path(&self) -> PathBuf {
        non_empty(&self.host_key_path).map_or_else(paths::default_host_key_path, PathBuf::from)
    }

    /// SFTP 独立 IP 黑白名单判定
    #[must_use]
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        Config::is_ip_allowed_for(&self.allowed_ips, &self.denied_ips, ip)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// 全局最大并发连接数（必须 > 0）
    pub max_connections: usize,
    /// 单 IP 最大并发连接数（必须 > 0）
    pub max_connections_per_ip: usize,
    pub fail2ban_enabled: bool,
    /// 触发封禁的失败次数
    pub fail2ban_threshold: u32,
    /// 封禁时长（秒）
    pub fail2ban_ban_time: u64,
    /// 失败计数窗口（秒）：窗口内的失败才累加
    pub fail2ban_find_time: u64,
    pub max_login_attempts: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            max_connections_per_ip: 10,
            fail2ban_enabled: false,
            fail2ban_threshold: 5,
            fail2ban_ban_time: 3600,
            fail2ban_find_time: 600,
            max_login_attempts: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// 日志目录，空串 = [`paths::default_log_dir`]
    pub log_dir: String,
    pub log_level: String,
    /// 轮转保留的日志文件数
    pub max_log_files: usize,
    /// 单个日志文件大小上限（字节）
    pub max_log_size: u64,
    /// JSON 格式日志
    pub enable_json: bool,
    /// 允许后端把日志实时推送给前端（订阅）
    pub enable_gui_logging: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_dir: String::new(),
            log_level: "info".to_string(),
            max_log_files: 10,
            max_log_size: 10 * 1024 * 1024,
            enable_json: false,
            enable_gui_logging: true,
        }
    }
}

impl LoggingConfig {
    /// 解析后的日志目录（空串时回退 [`paths::default_log_dir`]）
    #[must_use]
    pub fn resolved_log_dir(&self) -> PathBuf {
        non_empty(&self.log_dir).map_or_else(paths::default_log_dir, PathBuf::from)
    }
}

/// 把配置里的监听地址 + 端口拼成合法的 `host:port` 字符串。
///
/// IPv6 字面量必须加方括号（`[::1]:2121`），否则 `ToSocketAddrs` 解析失败。
/// 仅接受 IPv4/IPv6 字面量（不接受主机名），保证绑定目标确定且可校验。
///
/// # Errors
/// 地址为空、无法解析为 IP 字面量时返回错误
pub fn format_bind_addr(host: &str, port: u16) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        bail!("监听地址不能为空");
    }
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => Ok(format!("[{ip}]:{port}")),
        Ok(IpAddr::V4(ip)) => Ok(format!("{ip}:{port}")),
        Err(_) => bail!("监听地址必须是 IPv4/IPv6 字面量（不支持主机名）: {host}"),
    }
}

impl Config {
    /// 加载 TOML 配置；文件不存在时落盘一份默认配置并返回默认值
    ///
    /// 缺失字段按 [`Default`] 补齐，便于兼容字段较少的旧配置。
    ///
    /// # Errors
    /// 配置文件存在但读取失败，或内容不是合法的 TOML 配置时返回错误
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            let config = Self::default();
            if let Err(e) = config.save(path) {
                eprintln!("Warning: Failed to save default config: {e}");
            }
            return Ok(config);
        }

        let content = fs::read_to_string(path).context("Failed to read config file")?;

        let config: Config = toml::from_str(&content).context("Failed to parse config file")?;

        Ok(config)
    }

    /// 将配置序列化为 TOML 并写入 `path`（先写临时文件再原子重命名）
    ///
    /// # Errors
    /// 父目录创建、序列化、临时文件写入或重命名失败时返回错误
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, content).context("Failed to write temp config file")?;

        if let Err(e) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(e).context("Failed to rename temp config file");
        }

        Ok(())
    }

    #[must_use]
    pub fn get_config_path() -> PathBuf {
        paths::config_path()
    }

    #[must_use]
    pub fn get_users_path() -> PathBuf {
        paths::users_path()
    }

    /// 校验配置自身的一致性
    ///
    /// 覆盖监听地址/端口、IP 名单、协议认证方式、匿名目录与共享根冲突、
    /// IPv6 通告地址、0 值语义等启动期可确定的错误。
    ///
    /// # Errors
    /// 任一配置项非法时返回描述性错误
    pub fn validate(&self) -> Result<()> {
        self.validate_ftp()?;
        self.validate_sftp()?;
        self.validate_security()
    }

    /// 校验 `[ftp]` / `[ftp.ftps]`
    fn validate_ftp(&self) -> Result<()> {
        if !self.ftp.enabled {
            return Ok(());
        }

        format_bind_addr(&self.ftp.bind_ip, self.ftp.port).context("ftp.bind_ip/ftp.port 非法")?;

        let (start, end) = self.ftp.passive_ports;
        if start == 0 || end == 0 {
            bail!("ftp.passive_ports 不能为 0（当前 {start}-{end}）");
        }
        if start >= end {
            bail!("ftp.passive_ports 起止非法（当前 {start}-{end}），必须满足起始端口 < 结束端口");
        }
        if let Some(addr) = self.ftp.masquerade_address_opt()
            && addr
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<Ipv6Addr>()
                .is_ok()
        {
            bail!(
                "ftp.masquerade_address 不支持 IPv6 字面量（{addr}）：\
                 libunftp 的 PASV 应答仅支持 IPv4；IPv6 客户端会使用 EPSV，\
                 请留空或改为 IPv4 地址/域名"
            );
        }
        validate_ip_list("ftp.allowed_ips", &self.ftp.allowed_ips)?;
        validate_ip_list("ftp.denied_ips", &self.ftp.denied_ips)?;

        if self.ftp.allow_anonymous {
            if self.ftp.ftp_root_opt().is_some() {
                bail!(
                    "ftp.allow_anonymous 与 ftp.ftp_root 不能同时启用：\
                     共享根模式下匿名用户会以 ftp_root 为会话根，\
                     可读取所有用户的文件；请关闭匿名访问或取消 ftp_root"
                );
            }
            match self.ftp.anonymous_home_opt() {
                Some(home) => {
                    let home_path = Path::new(home);
                    if !home_path.exists() {
                        bail!("FTP匿名访问已启用，但匿名用户主目录不存在: {home}");
                    }
                    if !home_path.is_dir() {
                        bail!("FTP匿名访问已启用，但匿名用户主目录路径不是目录: {home}");
                    }
                }
                None => bail!("FTP匿名访问已启用，但未配置匿名用户主目录(anonymous_home)"),
            }
        }

        Ok(())
    }

    /// 校验 `[sftp]`
    fn validate_sftp(&self) -> Result<()> {
        if !self.sftp.enabled {
            return Ok(());
        }

        format_bind_addr(&self.sftp.bind_ip, self.sftp.port)
            .context("sftp.bind_ip/sftp.port 非法")?;

        if self.sftp.max_auth_attempts == 0 {
            bail!("sftp.max_auth_attempts 必须大于 0");
        }
        if !self.sftp.password_auth && !self.sftp.public_key_auth {
            bail!(
                "sftp.password_auth 与 sftp.public_key_auth 不能同时关闭：\
                 至少需要启用一种认证方式"
            );
        }
        if self.sftp.login_grace_time == 0 {
            bail!("sftp.login_grace_time 必须大于 0");
        }
        if self.sftp.idle_timeout == 0 {
            bail!("sftp.idle_timeout 必须大于 0");
        }
        if self.sftp.keepalive_interval > 0 && self.sftp.keepalive_max == 0 {
            bail!("sftp.keepalive_interval 大于 0 时 sftp.keepalive_max 必须大于 0");
        }
        validate_ip_list("sftp.allowed_ips", &self.sftp.allowed_ips)?;
        validate_ip_list("sftp.denied_ips", &self.sftp.denied_ips)?;

        let host_key = self.sftp.resolved_host_key_path();
        if !host_key.exists() {
            warn!(
                "SFTP主机密钥不存在: {}，首次启动将自动生成",
                host_key.display()
            );
        }

        Ok(())
    }

    /// 校验 `[security]`
    fn validate_security(&self) -> Result<()> {
        if self.security.max_connections == 0 {
            bail!("security.max_connections 必须大于 0（0 会拒绝全部连接）");
        }
        if self.security.max_connections_per_ip == 0 {
            bail!("security.max_connections_per_ip 必须大于 0（0 会拒绝全部连接）");
        }
        if self.security.max_login_attempts == 0 {
            bail!("security.max_login_attempts 必须大于 0");
        }
        if self.security.fail2ban_enabled {
            if self.security.fail2ban_threshold == 0 {
                bail!("security.fail2ban_threshold 必须大于 0");
            }
            if self.security.fail2ban_ban_time == 0 {
                bail!("security.fail2ban_ban_time 必须大于 0");
            }
            if self.security.fail2ban_find_time == 0 {
                bail!("security.fail2ban_find_time 必须大于 0");
            }
        }

        Ok(())
    }

    /// 静态版本：供非 Config 持有方（如 FTP 认证桥）复用同一套规则
    #[must_use]
    pub fn is_ip_allowed_for(allowed_ips: &[String], denied_ips: &[String], ip: &str) -> bool {
        if denied_ips.iter().any(|cidr| ip_matches_cidr(ip, cidr)) {
            return false;
        }

        if allowed_ips.is_empty() {
            return true;
        }

        allowed_ips.iter().any(|cidr| ip_matches_cidr(ip, cidr))
    }
}

/// 校验一组 IP/CIDR 条目
fn validate_ip_list(label: &str, entries: &[String]) -> Result<()> {
    for entry in entries {
        if !is_valid_ip_or_cidr(entry.trim()) {
            bail!("{label} 含非法 IP/CIDR: {entry}");
        }
    }
    Ok(())
}

fn is_valid_ip_or_cidr(entry: &str) -> bool {
    use ipnet::{Ipv4Net, Ipv6Net};

    entry.parse::<IpAddr>().is_ok()
        || entry.parse::<Ipv4Net>().is_ok()
        || entry.parse::<Ipv6Net>().is_ok()
}

fn ip_matches_cidr(ip: &str, cidr: &str) -> bool {
    use ipnet::{Ipv4Net, Ipv6Net};

    let cidr = cidr.trim();
    if cidr == "0.0.0.0/0" || cidr == "::/0" {
        return true;
    }

    if let Ok(ipv4) = ip.parse::<Ipv4Addr>()
        && let Ok(net) = cidr.parse::<Ipv4Net>()
    {
        return net.contains(&ipv4);
    }

    if let Ok(ipv6) = ip.parse::<Ipv6Addr>()
        && let Ok(net) = cidr.parse::<Ipv6Net>()
    {
        return net.contains(&ipv6);
    }

    ip.trim() == cidr
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- IP 过滤规则 ----

    #[test]
    fn ip_allowed_by_cidr_range() {
        let allowed = vec!["192.168.1.0/24".to_string()];
        assert!(Config::is_ip_allowed_for(&allowed, &[], "192.168.1.5"));
        assert!(!Config::is_ip_allowed_for(&allowed, &[], "192.168.2.5"));
    }

    #[test]
    fn ip_allowed_by_exact_match() {
        let allowed = vec!["10.0.0.7".to_string()];
        assert!(Config::is_ip_allowed_for(&allowed, &[], "10.0.0.7"));
        assert!(!Config::is_ip_allowed_for(&allowed, &[], "10.0.0.8"));
    }

    #[test]
    fn empty_allowed_list_permits_all() {
        assert!(Config::is_ip_allowed_for(&[], &[], "1.2.3.4"));
    }

    #[test]
    fn wildcard_cidr_permits_all() {
        let allowed = vec!["0.0.0.0/0".to_string()];
        assert!(Config::is_ip_allowed_for(&allowed, &[], "8.8.8.8"));
    }

    #[test]
    fn denied_list_overrides_allowed() {
        let allowed = vec!["0.0.0.0/0".to_string()];
        let denied = vec!["10.0.0.1".to_string()];
        assert!(!Config::is_ip_allowed_for(&allowed, &denied, "10.0.0.1"));
        assert!(Config::is_ip_allowed_for(&allowed, &denied, "10.0.0.2"));
    }

    #[test]
    fn protocol_specific_ip_lists_are_independent() {
        let mut config = Config::default();
        config.ftp.allowed_ips = vec!["192.168.0.0/16".to_string()];
        config.ftp.denied_ips = vec!["192.168.0.1".to_string()];
        config.sftp.allowed_ips = vec!["10.0.0.0/8".to_string()];

        assert!(!config.ftp.is_ip_allowed("192.168.0.1"));
        assert!(config.ftp.is_ip_allowed("192.168.5.5"));
        assert!(!config.ftp.is_ip_allowed("10.0.0.1"));
        assert!(config.sftp.is_ip_allowed("10.1.2.3"));
        assert!(!config.sftp.is_ip_allowed("192.168.5.5"));
    }

    #[test]
    fn ipv6_cidr_matching() {
        let allowed = vec!["2001:db8::/32".to_string()];
        assert!(Config::is_ip_allowed_for(&allowed, &[], "2001:db8::1"));
        assert!(!Config::is_ip_allowed_for(&allowed, &[], "2001:db9::1"));
    }

    // ---- 监听地址拼接 ----

    #[test]
    fn bind_addr_formats_ipv4_and_ipv6() {
        assert_eq!(format_bind_addr("0.0.0.0", 21).unwrap(), "0.0.0.0:21");
        assert_eq!(
            format_bind_addr("127.0.0.1", 2121).unwrap(),
            "127.0.0.1:2121"
        );
        assert_eq!(format_bind_addr("::", 21).unwrap(), "[::]:21");
        assert_eq!(format_bind_addr("::1", 2222).unwrap(), "[::1]:2222");
        assert_eq!(format_bind_addr("[::1]", 2222).unwrap(), "[::1]:2222");
        assert!(format_bind_addr("ftp.example.com", 21).is_err());
        assert!(format_bind_addr("", 21).is_err());
    }

    // ---- validate：匿名 FTP 主目录 ----

    #[test]
    fn validate_anonymous_with_existing_home_ok() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.ftp.enabled = true;
        config.ftp.allow_anonymous = true;
        config.ftp.anonymous_home = dir.path().to_string_lossy().into_owned();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_anonymous_without_home_fails() {
        let mut config = Config::default();
        config.ftp.enabled = true;
        config.ftp.allow_anonymous = true;
        config.ftp.anonymous_home = String::new();
        assert!(config.validate().is_err());

        config.ftp.anonymous_home = "   ".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_anonymous_with_missing_home_fails() {
        let mut config = Config::default();
        config.ftp.enabled = true;
        config.ftp.allow_anonymous = true;
        config.ftp.anonymous_home = "/nonexistent/fftpd/test/home".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_anonymous_with_file_home_fails() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut config = Config::default();
        config.ftp.enabled = true;
        config.ftp.allow_anonymous = true;
        config.ftp.anonymous_home = file.path().to_string_lossy().into_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_anonymous_with_shared_root_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.ftp.allow_anonymous = true;
        config.ftp.anonymous_home = dir.path().to_string_lossy().into_owned();
        config.ftp.ftp_root = dir.path().to_string_lossy().into_owned();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("ftp_root"), "错误信息应提示冲突: {err}");
    }

    #[test]
    fn validate_skips_anonymous_check_when_ftp_disabled() {
        let mut config = Config::default();
        config.ftp.enabled = false;
        config.ftp.allow_anonymous = true;
        config.ftp.anonymous_home = String::new();
        assert!(config.validate().is_ok());
    }

    // ---- validate：新增一致性校验 ----

    #[test]
    fn validate_rejects_bad_passive_ports() {
        let mut config = Config::default();
        config.ftp.passive_ports = (50000, 50000);
        assert!(config.validate().is_err());

        config.ftp.passive_ports = (51000, 50000);
        assert!(config.validate().is_err());

        config.ftp.passive_ports = (0, 50000);
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_ipv6_masquerade() {
        let mut config = Config::default();
        config.ftp.masquerade_address = "2001:db8::1".to_string();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("EPSV"), "应提示使用 EPSV: {err}");
    }

    #[test]
    fn validate_rejects_invalid_ip_list() {
        let mut config = Config::default();
        config.ftp.allowed_ips = vec!["not-a-cidr".to_string()];
        assert!(config.validate().is_err());

        config.ftp.allowed_ips = vec!["0.0.0.0/0".to_string()];
        config.sftp.denied_ips = vec!["10.0.0.0/999".to_string()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_requires_at_least_one_sftp_auth_method() {
        let mut config = Config::default();
        config.sftp.password_auth = false;
        config.sftp.public_key_auth = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_timeouts_and_limits() {
        let mut config = Config::default();
        config.sftp.login_grace_time = 0;
        assert!(config.validate().is_err());

        config.sftp.login_grace_time = 60;
        config.sftp.idle_timeout = 0;
        assert!(config.validate().is_err());

        config.sftp.idle_timeout = 3600;
        config.sftp.keepalive_interval = 30;
        config.sftp.keepalive_max = 0;
        assert!(config.validate().is_err());

        config.sftp.keepalive_max = 3;
        config.security.max_connections = 0;
        assert!(config.validate().is_err());

        config.security.max_connections = 100;
        config.security.max_connections_per_ip = 0;
        assert!(config.validate().is_err());

        config.security.max_connections_per_ip = 10;
        config.security.fail2ban_enabled = true;
        config.security.fail2ban_find_time = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_invalid_bind_addr() {
        let mut config = Config::default();
        config.ftp.bind_ip = "not-an-ip".to_string();
        assert!(config.validate().is_err());

        config.ftp.bind_ip = "0.0.0.0".to_string();
        config.sftp.bind_ip = "ftp.example.com".to_string();
        assert!(config.validate().is_err());
    }

    // ---- 空串 = 未设置 的取值辅助 ----

    #[test]
    fn empty_string_options_are_unset() {
        let ftp = FtpConfig::default();
        assert_eq!(ftp.anonymous_home_opt(), None);
        assert_eq!(ftp.masquerade_address_opt(), None);
        assert_eq!(ftp.ftp_root_opt(), None);
        assert_eq!(ftp.ftps.cert_path_opt(), None);
        assert_eq!(ftp.ftps.key_path_opt(), None);

        let ftp = FtpConfig {
            anonymous_home: "/srv/anon".to_string(),
            masquerade_address: "203.0.113.7".to_string(),
            ftp_root: "/srv/ftp".to_string(),
            ..FtpConfig::default()
        };
        assert_eq!(ftp.anonymous_home_opt(), Some("/srv/anon"));
        assert_eq!(ftp.masquerade_address_opt(), Some("203.0.113.7"));
        assert_eq!(ftp.ftp_root_opt(), Some("/srv/ftp"));
    }

    #[test]
    fn empty_paths_resolve_to_defaults() {
        let config = Config::default();
        assert_eq!(
            config.sftp.resolved_host_key_path(),
            paths::default_host_key_path()
        );
        assert_eq!(config.logging.resolved_log_dir(), paths::default_log_dir());
    }

    // ---- 默认值（docs/design.md §5.1）----

    #[test]
    fn defaults_match_design_schema() {
        let config = Config::default();
        assert!(config.ftp.enabled);
        assert_eq!(config.ftp.bind_ip, "0.0.0.0");
        assert_eq!(config.ftp.port, default_ftp_port());
        assert_eq!(config.ftp.welcome_message, "Welcome to fftps");
        assert!(!config.ftp.allow_anonymous);
        assert_eq!(config.ftp.passive_ports, (50000, 51000));
        assert_eq!(config.ftp.idle_timeout, 15);
        assert_eq!(config.ftp.max_sessions_per_user, 5);
        assert!(!config.ftp.allow_symlinks);
        assert_eq!(config.ftp.allowed_ips, vec!["0.0.0.0/0".to_string()]);
        assert!(!config.ftp.ftps.enabled);

        assert!(config.sftp.enabled);
        assert_eq!(config.sftp.port, 2222);
        assert_eq!(config.sftp.max_auth_attempts, 3);
        assert!(config.sftp.password_auth);
        assert!(config.sftp.public_key_auth);
        assert_eq!(config.sftp.login_grace_time, 60);
        assert_eq!(config.sftp.idle_timeout, 3600);
        assert_eq!(config.sftp.keepalive_interval, 30);
        assert_eq!(config.sftp.keepalive_max, 3);
        assert_eq!(config.sftp.max_sessions_per_user, 5);
        assert_eq!(config.sftp.max_speed_kbps, 0);
        assert!(!config.sftp.allow_symlinks);

        assert_eq!(config.security.max_connections, 100);
        assert_eq!(config.security.max_connections_per_ip, 10);
        assert_eq!(config.security.fail2ban_threshold, 5);
        assert_eq!(config.security.fail2ban_ban_time, 3600);
        assert_eq!(config.security.fail2ban_find_time, 600);
        assert_eq!(config.security.max_login_attempts, 5);

        assert_eq!(config.logging.log_level, "info");
        assert_eq!(config.logging.max_log_files, 10);
        assert_eq!(config.logging.max_log_size, 10_485_760);
        assert!(!config.logging.enable_json);
        assert!(config.logging.enable_gui_logging);
    }

    /// 打包示例配置必须可解析，且与内置默认值完全一致（防止文档漂移）
    #[test]
    fn packaged_example_matches_builtin_defaults() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("deploy")
            .join("common")
            .join("config.toml");
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读取 {} 失败: {e}", path.display()));
        let example: Config = toml::from_str(&content).expect("示例配置必须可解析");

        assert_eq!(
            serde_json::to_value(&example).unwrap(),
            serde_json::to_value(Config::default()).unwrap(),
            "deploy/common/config.toml 与内置默认值不一致"
        );
    }

    #[test]
    fn partial_toml_falls_back_to_defaults() {
        let config: Config = toml::from_str("[ftp]\nenabled = false\n").unwrap();
        assert!(!config.ftp.enabled);
        assert_eq!(config.ftp.port, default_ftp_port());
        assert_eq!(config.sftp.port, 2222);
    }

    /// 旧配置里的已删除字段应被忽略（向后兼容，不阻断升级）
    #[test]
    fn legacy_fields_are_ignored() {
        let config: Config = toml::from_str(
            "[ftp]\nconnection_mode = \"active_only\"\npooled_listener_mode = true\n\
             [ftp.ftps]\nrequire_ssl = false\n[sftp]\nauth_timeout = 60\n\
             host_key_rotation_days = 30\n",
        )
        .unwrap();
        assert_eq!(config.ftp.port, default_ftp_port());
        assert!(!config.ftp.ftps.enabled);
        assert!(config.sftp.password_auth);
    }

    // ---- 持久化 ----

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let mut config = Config::default();
        config.ftp.port = 2121;
        config.ftp.max_sessions_per_user = 7;
        config.ftp.allowed_ips = vec!["10.0.0.0/8".to_string()];
        config.sftp.enabled = false;
        config.sftp.password_auth = false;
        config.security.max_login_attempts = 7;
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.ftp.port, 2121);
        assert_eq!(loaded.ftp.max_sessions_per_user, 7);
        assert_eq!(loaded.ftp.allowed_ips, vec!["10.0.0.0/8".to_string()]);
        assert!(!loaded.sftp.enabled);
        assert!(!loaded.sftp.password_auth);
        assert_eq!(loaded.security.max_login_attempts, 7);
        assert_eq!(loaded.logging.log_dir, config.logging.log_dir);
    }

    #[test]
    fn load_missing_file_writes_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        assert!(!path.exists());

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.ftp.port, Config::default().ftp.port);
        assert!(path.exists(), "加载缺失配置时应落盘一份默认配置");
    }

    #[test]
    fn load_invalid_toml_fails() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "not a valid toml {{{{").unwrap();
        assert!(Config::load(file.path()).is_err());
    }

    #[test]
    fn save_is_atomic_no_temp_file_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        Config::default().save(&path).unwrap();
        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());
    }
}

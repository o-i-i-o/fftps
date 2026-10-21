//! 统一配置 schema（docs/design.md §5.1 的 config.toml）
//!
//! 以 Windows 侧实现的字段全集为基础，并补 Linux 侧的 logging 增量字段；
//! 前后端共用同一份类型定义，避免格式漂移。
//!
//! 可选值语义：`masquerade_address` / `anonymous_home` / `ftp_root` 与
//! `cert_path` / `key_path` / `host_key_path` / `log_dir` 在 TOML 里为
//! `String`，空串表示未设置（比 `Option<String>` 对配置文件更友好），
//! 用对应的 `*_opt()` / `resolved_*()` 辅助方法取值。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::paths;

/// 空串（含全空白）视为未设置，返回原始字符串
fn non_empty(s: &str) -> Option<&str> {
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub ftp: FtpConfig,
    pub sftp: SftpConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

/// FTP 连接模式（`connection_mode`）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    #[default]
    PassiveOnly,
    ActiveOnly,
    ActiveAndPassive,
}

impl ConnectionMode {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionMode::PassiveOnly => "passive_only",
            ConnectionMode::ActiveOnly => "active_only",
            ConnectionMode::ActiveAndPassive => "active_and_passive",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FtpConfig {
    pub enabled: bool,
    pub bind_ip: String,
    pub port: u16,
    pub welcome_message: String,
    pub encoding: String,
    /// 传输模式（`binary` / `ascii`）
    pub default_transfer_mode: String,
    pub connection_mode: ConnectionMode,
    pub allow_anonymous: bool,
    /// 匿名用户主目录，空串 = 未设置
    pub anonymous_home: String,
    /// 被动模式端口区间（含端点）
    pub passive_ports: (u16, u16),
    /// 单连接限速（KB/s），0 = 不限速
    pub max_speed_kbps: u64,
    /// 被动模式对外通告地址，空串 = 使用实际连接地址
    pub masquerade_address: String,
    /// 连接建立超时（秒）
    pub connection_timeout: u64,
    /// 空闲超时（秒）
    pub idle_timeout: u64,
    pub hide_version_info: bool,
    pub pooled_listener_mode: bool,
    pub allow_nat_clients: bool,
    /// FTP 根目录，空串 = 各用户 home
    pub ftp_root: String,
    pub ftps: FtpsConfig,
}

impl Default for FtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_ip: "0.0.0.0".to_string(),
            port: 21,
            welcome_message: "Welcome to fftpd".to_string(),
            encoding: "UTF-8".to_string(),
            default_transfer_mode: "binary".to_string(),
            connection_mode: ConnectionMode::PassiveOnly,
            allow_anonymous: false,
            anonymous_home: String::new(),
            passive_ports: (50000, 51000),
            max_speed_kbps: 0,
            masquerade_address: String::new(),
            connection_timeout: 15,
            idle_timeout: 15,
            hide_version_info: false,
            pooled_listener_mode: true,
            allow_nat_clients: true,
            ftp_root: String::new(),
            ftps: FtpsConfig::default(),
        }
    }
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
}

/// FTPS（显式 TLS）子表 `[ftp.ftps]`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FtpsConfig {
    pub enabled: bool,
    /// 拒绝未升级到 TLS 的客户端
    pub require_ssl: bool,
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
    /// 认证超时（秒）
    pub auth_timeout: u64,
    pub log_level: String,
    pub max_sessions_per_user: u32,
    /// 主机密钥轮换周期（天），0 = 不轮换
    pub host_key_rotation_days: u32,
}

impl Default for SftpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_ip: "0.0.0.0".to_string(),
            port: 2222,
            host_key_path: String::new(),
            max_auth_attempts: 3,
            auth_timeout: 60,
            log_level: "info".to_string(),
            max_sessions_per_user: 5,
            host_key_rotation_days: 0,
        }
    }
}

impl SftpConfig {
    /// 解析后的主机密钥路径（空串时回退 [`paths::default_host_key_path`]）
    #[must_use]
    pub fn resolved_host_key_path(&self) -> PathBuf {
        non_empty(&self.host_key_path)
            .map_or_else(paths::default_host_key_path, PathBuf::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// 全局最大并发连接数
    pub max_connections: usize,
    /// 单 IP 最大并发连接数
    pub max_connections_per_ip: usize,
    /// IP 白名单（CIDR），空表 = 全部放行
    pub allowed_ips: Vec<String>,
    /// IP 黑名单（CIDR），优先于白名单
    pub denied_ips: Vec<String>,
    pub fail2ban_enabled: bool,
    /// 触发封禁的失败次数
    pub fail2ban_threshold: u32,
    /// 封禁时长（秒）
    pub fail2ban_ban_time: u64,
    /// 是否允许跟随符号链接
    pub allow_symlinks: bool,
    pub max_login_attempts: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            max_connections_per_ip: 10,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            denied_ips: vec![],
            fail2ban_enabled: false,
            fail2ban_threshold: 5,
            fail2ban_ban_time: 3600,
            allow_symlinks: false,
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

    /// 校验配置自身的一致性（匿名 FTP 主目录、SFTP 主机密钥）
    ///
    /// # Errors
    /// FTP 匿名访问已启用但 `anonymous_home` 未配置、不存在或不是目录时返回错误
    pub fn validate(&self) -> Result<()> {
        if self.ftp.enabled && self.ftp.allow_anonymous {
            match self.ftp.anonymous_home_opt() {
                Some(home) => {
                    let home_path = Path::new(home);
                    if !home_path.exists() {
                        return Err(anyhow::anyhow!(
                            "FTP匿名访问已启用，但匿名用户主目录不存在: {home}"
                        ));
                    }
                    if !home_path.is_dir() {
                        return Err(anyhow::anyhow!(
                            "FTP匿名访问已启用，但匿名用户主目录路径不是目录: {home}"
                        ));
                    }
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "FTP匿名访问已启用，但未配置匿名用户主目录(anonymous_home)"
                    ));
                }
            }
        }

        if self.sftp.enabled {
            let host_key = self.sftp.resolved_host_key_path();
            if !host_key.exists() {
                warn!(
                    "SFTP主机密钥不存在: {}，请运行安装脚本生成",
                    host_key.display()
                );
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

    #[must_use]
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self
            .security
            .denied_ips
            .iter()
            .any(|cidr| ip_matches_cidr(ip, cidr))
        {
            return false;
        }

        if self.security.allowed_ips.is_empty() {
            return true;
        }

        self.security
            .allowed_ips
            .iter()
            .any(|cidr| ip_matches_cidr(ip, cidr))
    }
}

fn ip_matches_cidr(ip: &str, cidr: &str) -> bool {
    use ipnet::{Ipv4Net, Ipv6Net};
    use std::net::{Ipv4Addr, Ipv6Addr};

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

    ip == cidr
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
    fn instance_is_ip_allowed_matches_static() {
        let mut config = Config::default();
        config.security.allowed_ips = vec!["192.168.0.0/16".to_string()];
        config.security.denied_ips = vec!["192.168.0.1".to_string()];
        assert!(!config.is_ip_allowed("192.168.0.1"));
        assert!(config.is_ip_allowed("192.168.5.5"));
        assert!(!config.is_ip_allowed("10.0.0.1"));
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
    fn validate_skips_anonymous_check_when_ftp_disabled() {
        let mut config = Config::default();
        config.ftp.enabled = false;
        config.ftp.allow_anonymous = true;
        config.ftp.anonymous_home = String::new();
        assert!(config.validate().is_ok());
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
        assert_eq!(config.ftp.port, 21);
        assert_eq!(config.ftp.welcome_message, "Welcome to fftpd");
        assert_eq!(config.ftp.encoding, "UTF-8");
        assert_eq!(config.ftp.default_transfer_mode, "binary");
        assert_eq!(config.ftp.connection_mode, ConnectionMode::PassiveOnly);
        assert_eq!(config.ftp.connection_mode.as_str(), "passive_only");
        assert!(!config.ftp.allow_anonymous);
        assert_eq!(config.ftp.passive_ports, (50000, 51000));
        assert_eq!(config.ftp.connection_timeout, 15);
        assert_eq!(config.ftp.idle_timeout, 15);
        assert!(config.ftp.pooled_listener_mode);
        assert!(config.ftp.allow_nat_clients);
        assert!(!config.ftp.ftps.enabled);

        assert!(config.sftp.enabled);
        assert_eq!(config.sftp.port, 2222);
        assert_eq!(config.sftp.max_auth_attempts, 3);
        assert_eq!(config.sftp.auth_timeout, 60);
        assert_eq!(config.sftp.max_sessions_per_user, 5);
        assert_eq!(config.sftp.host_key_rotation_days, 0);

        assert_eq!(config.security.max_connections, 100);
        assert_eq!(config.security.max_connections_per_ip, 10);
        assert_eq!(config.security.allowed_ips, vec!["0.0.0.0/0".to_string()]);
        assert_eq!(config.security.fail2ban_threshold, 5);
        assert_eq!(config.security.fail2ban_ban_time, 3600);
        assert_eq!(config.security.max_login_attempts, 5);

        assert_eq!(config.logging.log_level, "info");
        assert_eq!(config.logging.max_log_files, 10);
        assert_eq!(config.logging.max_log_size, 10_485_760);
        assert!(!config.logging.enable_json);
        assert!(config.logging.enable_gui_logging);
    }

    #[test]
    fn partial_toml_falls_back_to_defaults() {
        let config: Config = toml::from_str("[ftp]\nenabled = false\n").unwrap();
        assert!(!config.ftp.enabled);
        assert_eq!(config.ftp.port, 21);
        assert_eq!(config.sftp.port, 2222);
    }

    // ---- 持久化 ----

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let mut config = Config::default();
        config.ftp.port = 2121;
        config.ftp.connection_mode = ConnectionMode::ActiveAndPassive;
        config.sftp.enabled = false;
        config.security.max_login_attempts = 7;
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.ftp.port, 2121);
        assert_eq!(loaded.ftp.connection_mode, ConnectionMode::ActiveAndPassive);
        assert!(!loaded.sftp.enabled);
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

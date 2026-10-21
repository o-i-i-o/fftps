//! fftp-http 自身配置（fftp-http.toml）
//!
//! 与 fftpd 的 config.toml 完全隔离：监听地址/端口、TLS、IP 黑白名单、
//! 管理员用户都在本文件；fftpd 不读取、fftpd 的 IPC 命令面也不涉及本文件。
//! 口令哈希经 `fftp-http hash <口令>` 生成（Argon2id PHC，复用
//! `UserManager::hash_password` 的策略参数）。

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// 缺省配置模板（首次启动写入；含填写指引注释）
const DEFAULT_CONFIG: &str = r#"# fftp-http 配置（Web 管理前端专用，fftpd 不读取本文件）
# 管理员口令哈希生成：fftp-http hash <口令> ，将输出的 $argon2id$... 填入下方

[listen]
address = "127.0.0.1"   # 绑定非回环地址（如 0.0.0.0）必须启用 TLS 或配置 api_token
port = 8080

[tls]
enabled = false
cert_path = ""          # PEM 证书链路径
key_path = ""           # PEM 私钥路径

[ip_filter]
whitelist = []          # 空 = 不限制；支持单 IP 与 CIDR（如 "192.168.1.0/24"）
blacklist = []

[auth]
session_ttl_secs = 43200
api_token = ""          # 可选；配置后可用 Authorization: Bearer <token> 认证

# 管理员账户（至少一条，否则启动失败）
#[[admin_users]]
#username = "admin"
#password_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
"#;

/// 顶层配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpConfig {
    /// 监听地址与端口
    #[serde(default)]
    pub listen: ListenConfig,
    /// TLS（证书/私钥）
    #[serde(default)]
    pub tls: TlsConfig,
    /// IP 黑白名单（复用 fftp-common 的 CIDR 匹配规则）
    #[serde(default)]
    pub ip_filter: IpFilterConfig,
    /// 会话与 API token
    #[serde(default)]
    pub auth: AuthConfig,
    /// 管理员账户（至少一条）
    #[serde(default)]
    pub admin_users: Vec<AdminUser>,
}

/// 监听配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    /// 绑定地址（IPv4/IPv6 字面量；非回环地址受强制保护规则约束）
    #[serde(default = "default_address")]
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            address: default_address(),
            port: default_port(),
        }
    }
}

/// TLS 配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
}

/// IP 过滤配置（语义与 fftp-common 安全配置一致：黑名单优先，白名单非空即白名单制）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpFilterConfig {
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub blacklist: Vec<String>,
}

/// 认证配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// 会话 TTL（秒）
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    /// 可选静态 API token（Bearer 认证，脚本/程序化访问）
    #[serde(default)]
    pub api_token: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_ttl_secs: default_session_ttl(),
            api_token: String::new(),
        }
    }
}

/// 管理员账户
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub username: String,
    pub password_hash: String,
}

fn default_address() -> String {
    "127.0.0.1".into()
}

fn default_port() -> u16 {
    8080
}

fn default_session_ttl() -> u64 {
    43_200 // 12 小时
}

impl HttpConfig {
    /// 加载配置；文件缺失时生成默认模板（随后 [`Self::validate`] 会因
    /// 无管理员账户拒绝启动，引导用户填写）
    ///
    /// # Errors
    /// 模板写入失败或 TOML 解析失败时返回错误
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            std::fs::write(path, DEFAULT_CONFIG)
                .with_context(|| format!("写入默认配置模板失败: {}", path.display()))?;
            tracing::warn!("已生成默认配置模板: {}（请补充管理员账户后重启）", path.display());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置失败: {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("解析配置失败: {}", path.display()))
    }

    /// 绑定地址是否仅回环（解析失败按 false 处理，由 [`Self::validate`] 报错）
    #[must_use]
    pub fn is_loopback_only(&self) -> bool {
        self.listen
            .address
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    }

    /// 启动校验：fail fast，错误信息给出修复指引
    ///
    /// # Errors
    /// 监听地址非法、非回环绑定未启用 TLS 且未配置 api_token、TLS 文件缺失、
    /// 管理员账户缺失或口令哈希格式非法、会话 TTL 为 0 时返回错误
    pub fn validate(&self) -> Result<()> {
        if self.listen.address.parse::<std::net::IpAddr>().is_err() {
            anyhow::bail!(
                "listen.address 非法: {:?}（需 IPv4/IPv6 字面量，如 127.0.0.1 / 0.0.0.0 / ::）",
                self.listen.address
            );
        }
        if let Some(msg) = self.missing_network_protection() {
            anyhow::bail!("{msg}");
        }
        if self.tls.enabled {
            for (label, p) in [("tls.cert_path", &self.tls.cert_path), ("tls.key_path", &self.tls.key_path)] {
                if p.is_empty() || !Path::new(p).is_file() {
                    anyhow::bail!("{label} 指向的文件不存在或未配置: {:?}（TLS 已启用）", p);
                }
            }
        }
        if self.admin_users.is_empty() {
            anyhow::bail!(
                "未配置管理员账户：请在 {} 中添加 [[admin_users]]，口令哈希用 `fftp-http hash <口令>` 生成",
                fftp_common::paths::http_config_path().display()
            );
        }
        let mut seen = std::collections::HashSet::new();
        for u in &self.admin_users {
            if u.username.is_empty() || u.password_hash.is_empty() {
                anyhow::bail!("admin_users 存在空用户名或空口令哈希");
            }
            if !u.password_hash.starts_with("$argon2id$") {
                anyhow::bail!(
                    "管理员 {:?} 的口令哈希格式非法（应为 $argon2id$... PHC 字符串，用 `fftp-http hash <口令>` 生成）",
                    u.username
                );
            }
            if !seen.insert(u.username.as_str()) {
                anyhow::bail!("管理员用户名重复: {:?}", u.username);
            }
        }
        if self.auth.session_ttl_secs == 0 {
            anyhow::bail!("auth.session_ttl_secs 必须大于 0");
        }
        Ok(())
    }

    /// 非回环绑定的强制保护规则：必须启用 TLS 或配置 api_token
    fn missing_network_protection(&self) -> Option<String> {
        if self.is_loopback_only() || self.tls.enabled || !self.auth.api_token.is_empty() {
            return None;
        }
        Some(format!(
            "监听地址 {:?} 为非回环地址，必须启用 TLS（[tls].enabled）或配置 api_token（[auth].api_token），否则拒绝启动",
            self.listen.address
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> HttpConfig {
        HttpConfig {
            listen: ListenConfig::default(),
            tls: TlsConfig::default(),
            ip_filter: IpFilterConfig::default(),
            auth: AuthConfig::default(),
            admin_users: vec![AdminUser {
                username: "admin".into(),
                password_hash: "$argon2id$v=19$m=65536,t=3,p=4$dummy".into(),
            }],
        }
    }

    #[test]
    fn loopback_allows_plain_http() {
        let cfg = base();
        assert!(cfg.is_loopback_only());
        assert!(cfg.missing_network_protection().is_none());
    }

    #[test]
    fn non_loopback_requires_tls_or_token() {
        let mut cfg = base();
        cfg.listen.address = "0.0.0.0".into();
        assert!(cfg.missing_network_protection().is_some());

        cfg.auth.api_token = "secret".into();
        assert!(cfg.missing_network_protection().is_none());

        let mut cfg = base();
        cfg.listen.address = "::".into();
        assert!(cfg.missing_network_protection().is_some());

        let mut cfg = base();
        cfg.listen.address = "0.0.0.0".into();
        cfg.tls.enabled = true;
        assert!(cfg.missing_network_protection().is_none());
    }

    #[test]
    fn validate_rejects_bad_entries() {
        let mut cfg = base();
        cfg.listen.address = "not-an-ip".into();
        assert!(cfg.validate().is_err());

        let mut cfg = base();
        cfg.admin_users.clear();
        assert!(cfg.validate().is_err());

        let mut cfg = base();
        cfg.admin_users[0].password_hash = "plaintext".into();
        assert!(cfg.validate().is_err());

        let mut cfg = base();
        cfg.admin_users.push(AdminUser {
            username: "admin".into(),
            password_hash: "$argon2id$v=19$m=65536,t=3,p=4$dummy".into(),
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn default_template_parses_and_defaults_apply() {
        let cfg: HttpConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(cfg.listen.address, "127.0.0.1");
        assert_eq!(cfg.listen.port, 8080);
        assert_eq!(cfg.auth.session_ttl_secs, 43_200);
        assert!(cfg.admin_users.is_empty());
        assert!(cfg.validate().is_err()); // 模板缺管理员账户
    }

    #[test]
    fn config_roundtrip_preserves_admin_users() {
        let cfg = base();
        let raw = toml::to_string(&cfg).unwrap();
        let parsed: HttpConfig = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.admin_users.len(), 1);
        assert_eq!(parsed.admin_users[0].username, "admin");
    }
}

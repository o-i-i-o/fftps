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

[idle]
enabled = false         # 无操作自动关闭 fftp-http（不关闭 fftpd）
timeout_secs = 1800     # 空闲时长（秒，最小 30）
mode = "no_page"        # no_page = 无可见页面；no_activity = 无用户操作
warn_secs = 60          # 页面倒计时提示（秒，0 = 不提示）

# 管理员账户：首次启动未配置时会进入本机 setup 引导页，
# 也可预先添加（口令哈希用 `fftp-http hash <口令>` 生成）。
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
    /// 空闲自动关闭（仅关闭 fftp-http 自身）
    #[serde(default)]
    pub idle: IdleConfig,
    /// 管理员账户（可为空：仅回环地址下进入 setup 引导）
    #[serde(default)]
    pub admin_users: Vec<AdminUser>,
}

/// 将内容原子写入配置文件，并在 Unix 下收紧为 0600
///
/// 配置文件含 `api_token` 与口令哈希，直接 `fs::write` 会以 umask 默认权限
/// 落盘且回写非原子（中途失败会留下截断文件）。这里先写同目录私有临时文件，
/// 再 `rename` 覆盖。
fn write_config(path: &Path, contents: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().map_or_else(
        || "http.toml".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = parent.join(format!(".{file_name}.{}.{unique}.tmp", std::process::id()));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("创建临时配置文件失败: {}", tmp.display()))?;
        if let Err(e) = file
            .write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
        {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("写入临时配置文件失败: {}", tmp.display()));
        }
        // create_new + mode 在部分文件系统上仍可能被 umask 影响，显式收紧
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, contents)
            .with_context(|| format!("写入临时配置文件失败: {}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!("写入配置失败: {}", path.display())
    })
}

/// Unix 下把既有配置文件的权限收紧到 0600（首次加载时补齐历史遗留的宽权限）
#[cfg(unix)]
fn tighten_config_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(meta) = std::fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "配置文件权限过宽且收紧失败，请手动执行 chmod 600"
            );
        } else {
            tracing::warn!(
                path = %path.display(),
                "配置文件权限过宽，已自动收紧为 0600"
            );
        }
    }
}

#[cfg(not(unix))]
fn tighten_config_permissions(_path: &Path) {}

/// 空闲判定模式
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdleMode {
    /// 没有可见页面心跳（关闭浏览器/隐藏标签页后计时）
    #[default]
    NoPage,
    /// 没有真实用户操作（只看页面不操作也会计时）
    NoActivity,
}

impl IdleMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            IdleMode::NoPage => "no_page",
            IdleMode::NoActivity => "no_activity",
        }
    }
}

/// 空闲自动关闭配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_idle_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub mode: IdleMode,
    #[serde(default = "default_idle_warn")]
    pub warn_secs: u64,
}

impl Default for IdleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: default_idle_timeout(),
            mode: IdleMode::NoPage,
            warn_secs: default_idle_warn(),
        }
    }
}

fn default_idle_timeout() -> u64 {
    1800
}

fn default_idle_warn() -> u64 {
    60
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
    /// 加载配置；文件缺失时生成默认模板（空管理员账户仅允许回环绑定，
    /// 首次启动会进入本机 setup 引导页）
    ///
    /// # Errors
    /// 模板写入失败或 TOML 解析失败时返回错误
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("创建配置目录失败: {}", parent.display()))?;
            }
            write_config(path, DEFAULT_CONFIG)
                .with_context(|| format!("写入默认配置模板失败: {}", path.display()))?;
            tracing::warn!(
                "已生成默认配置模板: {}（首次启动将进入本机 setup 引导）",
                path.display()
            );
        }
        tighten_config_permissions(path);
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置失败: {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("解析配置失败: {}", path.display()))
    }

    /// 将管理员账户写回配置文件：仅替换 `[[admin_users]]` 段，保留文件其余
    /// 内容与注释；写入前对完整新内容做解析 + 启动校验，避免落盘非法配置
    ///
    /// # Errors
    /// 读取/解析失败或生成的新内容解析/校验失败时返回错误
    pub fn save_admin_users(path: &Path, users: &[AdminUser]) -> Result<()> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置失败: {}", path.display()))?;
        let mut doc: toml_edit::DocumentMut = raw
            .parse()
            .with_context(|| format!("解析配置 TOML 失败: {}", path.display()))?;

        if users.is_empty() {
            // 清空管理员：直接移除整个段（下次启动重新进入 setup 引导）
            doc.remove("admin_users");
        } else {
            let mut tables = toml_edit::ArrayOfTables::new();
            for user in users {
                let mut table = toml_edit::Table::new();
                table["username"] = toml_edit::value(user.username.as_str());
                table["password_hash"] = toml_edit::value(user.password_hash.as_str());
                tables.push(table);
            }
            doc["admin_users"] = toml_edit::Item::ArrayOfTables(tables);
        }

        let out = doc.to_string();

        // 写入前校验：解析新内容并复用启动校验规则
        let parsed: HttpConfig = toml::from_str(&out)
            .with_context(|| format!("生成的新配置解析失败: {}", path.display()))?;
        parsed
            .validate()
            .context("生成的新配置未通过启动校验（未写入文件）")?;

        write_config(path, &out).with_context(|| format!("写入配置失败: {}", path.display()))?;
        Ok(())
    }

    /// 将空闲设置写回配置文件：仅替换 `[idle]` 段，保留其余内容与注释
    ///
    /// # Errors
    /// 读取/解析失败、生成的新内容解析/校验失败或写入失败时返回错误
    pub fn save_idle(path: &Path, idle: &IdleConfig) -> Result<()> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置失败: {}", path.display()))?;
        let mut doc: toml_edit::DocumentMut = raw
            .parse()
            .with_context(|| format!("解析配置 TOML 失败: {}", path.display()))?;

        let mut table = toml_edit::Table::new();
        table["enabled"] = toml_edit::value(idle.enabled);
        table["timeout_secs"] = toml_edit::value(
            i64::try_from(idle.timeout_secs).context("空闲超时超出 TOML 整数范围")?,
        );
        table["mode"] = toml_edit::value(idle.mode.as_str());
        table["warn_secs"] = toml_edit::value(
            i64::try_from(idle.warn_secs).context("空闲告警时长超出 TOML 整数范围")?,
        );
        doc["idle"] = toml_edit::Item::Table(table);

        let out = doc.to_string();

        let parsed: HttpConfig = toml::from_str(&out)
            .with_context(|| format!("生成的新配置解析失败: {}", path.display()))?;
        parsed
            .validate_launch()
            .context("生成的新配置未通过启动校验（未写入文件）")?;

        write_config(path, &out).with_context(|| format!("写入配置失败: {}", path.display()))?;
        Ok(())
    }

    /// 绑定地址是否仅回环（解析失败按 false 处理，由 [`Self::validate`] 报错）
    #[must_use]
    pub fn is_loopback_only(&self) -> bool {
        self.listen
            .address
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    }

    /// 与管理员账户无关的启动校验（`launch` 子命令也使用）
    ///
    /// # Errors
    /// 监听地址非法、非回环绑定未启用 TLS 且未配置 `api_token`、TLS 文件缺失、
    /// 会话 TTL 为 0、空闲配置非法时返回错误
    pub fn validate_launch(&self) -> Result<()> {
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
            for (label, p) in [
                ("tls.cert_path", &self.tls.cert_path),
                ("tls.key_path", &self.tls.key_path),
            ] {
                if p.is_empty() || !Path::new(p).is_file() {
                    anyhow::bail!("{label} 指向的文件不存在或未配置: {p:?}（TLS 已启用）");
                }
            }
        }
        if self.auth.session_ttl_secs == 0 {
            anyhow::bail!("auth.session_ttl_secs 必须大于 0");
        }
        if self.idle.enabled {
            if self.idle.timeout_secs < 30 {
                anyhow::bail!("idle.timeout_secs 不能小于 30 秒");
            }
            if self.idle.warn_secs > self.idle.timeout_secs {
                anyhow::bail!("idle.warn_secs 不能大于 idle.timeout_secs");
            }
        }
        Ok(())
    }

    /// 启动校验：fail fast，错误信息给出修复指引
    ///
    /// # Errors
    /// 监听地址非法、非回环绑定未启用 TLS 且未配置 `api_token`、TLS 文件缺失、
    /// 非回环地址下管理员账户缺失、口令哈希格式非法、会话 TTL 为 0、
    /// 空闲配置非法时返回错误
    pub fn validate(&self) -> Result<()> {
        self.validate_launch()?;
        if self.admin_users.is_empty() {
            // 空管理员只允许本机 setup 引导；非回环绑定在 validate_launch 中已拒绝
            if !self.is_loopback_only() {
                anyhow::bail!(
                    "未配置管理员账户时只能绑定回环地址（当前 {}）",
                    self.listen.address
                );
            }
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
        Ok(())
    }

    /// 非回环绑定的强制保护规则
    ///
    /// 存在管理员账户即意味着开放浏览器登录（口令 + Cookie）；此时只配置
    /// `api_token` 不能替代 TLS，否则登录凭据会以明文经过网络。
    fn missing_network_protection(&self) -> Option<String> {
        if self.is_loopback_only() || self.tls.enabled {
            return None;
        }
        if !self.admin_users.is_empty() {
            return Some(format!(
                "监听地址 {:?} 为非回环地址且已配置管理员账户，必须启用 TLS（[tls].enabled），否则 Web 登录口令与 Cookie 将以明文传输",
                self.listen.address
            ));
        }
        if !self.auth.api_token.is_empty() {
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
            idle: IdleConfig::default(),
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
    fn non_loopback_requires_tls_when_admin_login_enabled() {
        let mut cfg = base();
        cfg.listen.address = "0.0.0.0".into();
        assert!(cfg.missing_network_protection().is_some());

        // api_token 不能替代 TLS：浏览器登录仍会走明文
        cfg.auth.api_token = "secret".into();
        assert!(cfg.missing_network_protection().is_some());

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

        // 回环地址允许空管理员（进入 setup 引导）；非回环地址仍拒绝
        let mut cfg = base();
        cfg.admin_users.clear();
        assert!(cfg.validate().is_ok());
        cfg.listen.address = "0.0.0.0".into();
        cfg.auth.api_token = "secret".into();
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
        assert!(!cfg.idle.enabled);
        assert_eq!(cfg.idle.timeout_secs, 1800);
        assert!(cfg.admin_users.is_empty());
        assert!(cfg.validate().is_ok()); // 回环地址下允许空管理员，进入 setup 引导
    }

    #[test]
    fn example_file_parses_with_documented_defaults() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../deploy/common/fftp-http.toml");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读取示例配置失败 {}: {e}", path.display()));
        let cfg: HttpConfig = toml::from_str(&raw).expect("示例配置应为合法 TOML 且字段有效");

        assert_eq!(cfg.listen.address, "127.0.0.1");
        assert_eq!(cfg.listen.port, 8080);
        assert!(!cfg.tls.enabled);
        assert_eq!(cfg.ip_filter.whitelist, [] as [std::string::String; 0]);
        assert_eq!(cfg.ip_filter.blacklist, [] as [std::string::String; 0]);
        assert_eq!(cfg.auth.session_ttl_secs, 43_200);
        assert_eq!(cfg.auth.api_token, "");
        assert!(!cfg.idle.enabled);
        assert_eq!(cfg.idle.mode, IdleMode::NoPage);
        // 管理员段在示例中默认注释：回环地址下允许启动并进入 setup 引导
        assert!(cfg.admin_users.is_empty());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_roundtrip_preserves_admin_users() {
        let cfg = base();
        let raw = toml::to_string(&cfg).unwrap();
        let parsed: HttpConfig = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.admin_users.len(), 1);
        assert_eq!(parsed.admin_users[0].username, "admin");
    }

    #[test]
    fn save_admin_users_replaces_block_and_preserves_rest() {
        let dir = std::env::temp_dir().join(format!("fftp-http-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("http.toml");
        let hash = "$argon2id$v=19$m=65536,t=3,p=4$dummy";
        std::fs::write(
            &path,
            format!(
                "# 头部注释\n[listen]\naddress = \"127.0.0.1\"\nport = 8080\n\n\
                 [[admin_users]]\nusername = \"old\"\npassword_hash = \"{hash}\"\n"
            ),
        )
        .unwrap();

        let users = vec![
            AdminUser {
                username: "a".into(),
                password_hash: hash.into(),
            },
            AdminUser {
                username: "b".into(),
                password_hash: hash.into(),
            },
        ];
        HttpConfig::save_admin_users(&path, &users).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("# 头部注释"));
        assert!(raw.contains("[listen]"));
        assert!(!raw.contains("old"));
        let cfg: HttpConfig = toml::from_str(&raw).unwrap();
        assert_eq!(cfg.admin_users.len(), 2);
        assert_eq!(cfg.admin_users[1].username, "b");

        // 回环地址下允许清空管理员（下次启动会重新进入 setup 引导）
        HttpConfig::save_admin_users(&path, &[]).unwrap();
        let cfg: HttpConfig = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(cfg.admin_users.is_empty());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn save_idle_replaces_block_and_preserves_rest() {
        let dir = std::env::temp_dir().join(format!("fftp-http-idle-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("http.toml");
        std::fs::write(
            &path,
            "# 注释\n[listen]\naddress = \"127.0.0.1\"\nport = 8080\n\n\
             [idle]\nenabled = false\ntimeout_secs = 1800\non = \"old\"\n\n[ip_filter]\nwhitelist = []\n",
        )
        .unwrap();

        let idle = IdleConfig {
            enabled: true,
            timeout_secs: 600,
            mode: IdleMode::NoActivity,
            warn_secs: 30,
        };
        HttpConfig::save_idle(&path, &idle).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("# 注释"));
        assert!(raw.contains("[listen]"));
        assert!(raw.contains("[ip_filter]"));
        assert!(!raw.contains("on = \"old\""));
        let cfg: HttpConfig = toml::from_str(&raw).unwrap();
        assert!(cfg.idle.enabled);
        assert_eq!(cfg.idle.timeout_secs, 600);
        assert_eq!(cfg.idle.mode, IdleMode::NoActivity);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}

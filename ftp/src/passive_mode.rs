//! FTP 被动模式地址选择（迁移自 wftpd-windows `ftp_server/passive_mode.rs`）
//!
//! PASV 响应通告地址优先级：`masquerade_address` > FromConnection（TCP 目的地址）。
//!
//! ## PASV 与 EPSV
//! - PASV（RFC 959）在响应中返回 IP 与端口；
//! - EPSV（RFC 2428）只返回端口；
//! - 使用哪种命令由客户端决定。
//!
//! 本机地址探测改为跨平台的 UDP connect 技巧（不发送数据包，仅让内核选出
//! 路由源地址），替代旧实现的 `ipconfig` / sysfs 平台分支。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};

use crate::ip_utils::{is_private_ipv4, is_private_ipv6};

/// 监听地址类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindAddressType {
    /// 通配监听（0.0.0.0 / ::）
    Wildcard,
    /// 指定 IPv4 地址
    SpecificIpv4,
    /// 指定 IPv6 地址
    SpecificIpv6,
}

/// 客户端来源网络分类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionSource {
    /// 回环
    Loopback,
    /// 私有网络
    PrivateNetwork,
    /// 公网
    PublicNetwork,
}

/// 本机地址集合
#[derive(Debug, Clone)]
pub struct LocalIpAddress {
    /// 本机 IPv4 地址
    pub ipv4: Vec<Ipv4Addr>,
    /// 本机 IPv6 地址
    pub ipv6: Vec<Ipv6Addr>,
}

impl LocalIpAddress {
    /// 是否没有任何地址
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    /// 日志展示格式
    #[must_use]
    pub fn format_for_log(&self) -> String {
        let mut parts = Vec::new();

        if !self.ipv4.is_empty() {
            let ipv4_strs: Vec<String> = self.ipv4.iter().map(ToString::to_string).collect();
            parts.push(format!("IPv4: [{}]", ipv4_strs.join(", ")));
        }

        if !self.ipv6.is_empty() {
            let ipv6_strs: Vec<String> = self.ipv6.iter().map(|ip| format!("[{ip}]")).collect();
            parts.push(format!("IPv6: [{}]", ipv6_strs.join(", ")));
        }

        if parts.is_empty() {
            "无地址".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// 分类监听地址
#[must_use]
pub fn classify_bind_address(bind_addr: &IpAddr) -> BindAddressType {
    match bind_addr {
        IpAddr::V4(ip) if ip.is_unspecified() => BindAddressType::Wildcard,
        IpAddr::V6(ip) if ip.is_unspecified() => BindAddressType::Wildcard,
        IpAddr::V4(_) => BindAddressType::SpecificIpv4,
        IpAddr::V6(_) => BindAddressType::SpecificIpv6,
    }
}

/// 分类客户端来源
#[must_use]
pub fn classify_connection_source(client_ip: &IpAddr) -> ConnectionSource {
    match client_ip {
        IpAddr::V4(ip) => {
            if ip.is_loopback() {
                ConnectionSource::Loopback
            } else if is_private_ipv4(ip) {
                ConnectionSource::PrivateNetwork
            } else {
                ConnectionSource::PublicNetwork
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback() {
                ConnectionSource::Loopback
            } else if is_private_ipv6(ip) {
                ConnectionSource::PrivateNetwork
            } else {
                ConnectionSource::PublicNetwork
            }
        }
    }
}

/// 推导实际监听地址（通配地址保持原样）
#[must_use]
pub fn determine_listen_address(bind_addr: &IpAddr) -> IpAddr {
    match bind_addr {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        other => *other,
    }
}

/// 是否通配监听
#[must_use]
pub fn is_wildcard_bind(bind_addr: &IpAddr) -> bool {
    matches!(classify_bind_address(bind_addr), BindAddressType::Wildcard)
}

/// 是否指定 IPv6 地址监听
#[must_use]
pub fn is_ipv6_bind(bind_addr: &IpAddr) -> bool {
    matches!(
        classify_bind_address(bind_addr),
        BindAddressType::SpecificIpv6
    )
}

/// 通过 UDP connect 探测内核为指定目标选择的本机源地址（不发送数据）
fn probe_local_ip(remote: &str) -> Option<IpAddr> {
    let bind = if remote.contains(':') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(remote).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// 探测本机 IPv4/IPv6 地址（用于日志与监听地址展示；探测失败回退回环地址）
#[must_use]
pub fn get_local_ip_addresses() -> LocalIpAddress {
    let mut result = LocalIpAddress {
        ipv4: Vec::new(),
        ipv6: Vec::new(),
    };

    // TEST-NET-1（192.0.2.1）/ TEST-NET-3（2001:db8::1）仅作路由探测目标
    if let Some(ip) = probe_local_ip("192.0.2.1:53")
        && let IpAddr::V4(v4) = ip
        && !v4.is_unspecified()
    {
        result.ipv4.push(v4);
    }
    if let Some(ip) = probe_local_ip("[2001:db8::1]:53")
        && let IpAddr::V6(v6) = ip
        && !v6.is_unspecified()
    {
        result.ipv6.push(v6);
    }

    if result.ipv4.is_empty() {
        result.ipv4.push(Ipv4Addr::LOCALHOST);
    }
    if result.ipv6.is_empty() {
        result.ipv6.push(Ipv6Addr::LOCALHOST);
    }

    result
}

/// 把绑定地址与端口格式化为人类可读的监听地址描述
#[must_use]
pub fn format_listen_addresses(bind_ip: &str, port: u16) -> String {
    let bind_addr: IpAddr = bind_ip
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    if is_wildcard_bind(&bind_addr) {
        let local_ips = get_local_ip_addresses();
        let mut addresses = Vec::new();

        for ip in &local_ips.ipv4 {
            addresses.push(format!("{ip}:{port}"));
        }
        for ip in &local_ips.ipv6 {
            addresses.push(format!("[{ip}]:{port}"));
        }

        format!("0.0.0.0:{port} / [::]:{port}（全部接口: {}）", addresses.join(", "))
    } else {
        match bind_addr {
            IpAddr::V4(ip) => format!("{ip}:{port}"),
            IpAddr::V6(ip) => format!("[{ip}]:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_bind_address_wildcard_v4() {
        assert_eq!(
            classify_bind_address(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            BindAddressType::Wildcard
        );
    }

    #[test]
    fn test_classify_bind_address_wildcard_v6() {
        assert_eq!(
            classify_bind_address(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            BindAddressType::Wildcard
        );
    }

    #[test]
    fn test_classify_bind_address_specific_ipv4() {
        assert_eq!(
            classify_bind_address(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            BindAddressType::SpecificIpv4
        );
    }

    #[test]
    fn test_classify_bind_address_specific_ipv6() {
        assert_eq!(
            classify_bind_address(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            BindAddressType::SpecificIpv6
        );
    }

    #[test]
    fn test_classify_connection_source_loopback() {
        assert_eq!(
            classify_connection_source(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            ConnectionSource::Loopback
        );
        assert_eq!(
            classify_connection_source(&IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ConnectionSource::Loopback
        );
    }

    #[test]
    fn test_classify_connection_source_private() {
        assert_eq!(
            classify_connection_source(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            ConnectionSource::PrivateNetwork
        );
        assert_eq!(
            classify_connection_source(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            ConnectionSource::PrivateNetwork
        );
        assert_eq!(
            classify_connection_source(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            ConnectionSource::PrivateNetwork
        );
    }

    #[test]
    fn test_classify_connection_source_public() {
        assert_eq!(
            classify_connection_source(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            ConnectionSource::PublicNetwork
        );
    }

    #[test]
    fn test_is_wildcard_bind() {
        assert!(is_wildcard_bind(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_wildcard_bind(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_wildcard_bind(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
    }

    #[test]
    fn test_is_ipv6_bind() {
        assert!(is_ipv6_bind(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_ipv6_bind(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_ipv6_bind(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_determine_listen_address() {
        assert_eq!(
            determine_listen_address(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        let specific = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(determine_listen_address(&specific), specific);
    }

    #[test]
    fn test_local_ip_addresses_non_empty() {
        let ips = get_local_ip_addresses();
        assert!(!ips.is_empty());
        assert!(!ips.ipv4.is_empty());
        assert!(!ips.format_for_log().is_empty());
    }

    #[test]
    fn test_format_listen_addresses_specific() {
        assert_eq!(
            format_listen_addresses("192.168.1.1", 21),
            "192.168.1.1:21"
        );
        assert_eq!(format_listen_addresses("::1", 21), "[::1]:21");
    }

    #[test]
    fn test_format_listen_addresses_wildcard() {
        let formatted = format_listen_addresses("0.0.0.0", 2121);
        assert!(formatted.starts_with("0.0.0.0:2121"));
        assert!(formatted.contains("2121"));
    }

    #[test]
    fn test_local_ip_address_format_empty() {
        let empty = LocalIpAddress {
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        };
        assert!(empty.is_empty());
        assert_eq!(empty.format_for_log(), "无地址");
    }
}

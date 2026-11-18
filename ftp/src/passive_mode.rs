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

/// 本机地址集合
#[derive(Debug, Clone)]
pub struct LocalIpAddress {
    /// 本机 IPv4 地址
    pub ipv4: Vec<Ipv4Addr>,
    /// 本机 IPv6 地址
    pub ipv6: Vec<Ipv6Addr>,
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

/// 是否通配监听
#[must_use]
pub fn is_wildcard_bind(bind_addr: &IpAddr) -> bool {
    matches!(classify_bind_address(bind_addr), BindAddressType::Wildcard)
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
    let bind_addr: IpAddr = bind_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    if is_wildcard_bind(&bind_addr) {
        let local_ips = get_local_ip_addresses();
        let mut addresses = Vec::new();

        for ip in &local_ips.ipv4 {
            addresses.push(format!("{ip}:{port}"));
        }
        for ip in &local_ips.ipv6 {
            addresses.push(format!("[{ip}]:{port}"));
        }

        format!(
            "0.0.0.0:{port} / [::]:{port}（全部接口: {}）",
            addresses.join(", ")
        )
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
            classify_bind_address(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
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
    fn test_is_wildcard_bind() {
        assert!(is_wildcard_bind(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_wildcard_bind(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_wildcard_bind(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
    }

    #[test]
    fn test_local_ip_addresses_non_empty() {
        let ips = get_local_ip_addresses();
        assert_ne!(ips.ipv4, [] as [Ipv4Addr; 0]);
        assert_ne!(ips.ipv6, [] as [Ipv6Addr; 0]);
    }

    #[test]
    fn test_format_listen_addresses_specific() {
        assert_eq!(format_listen_addresses("192.168.1.1", 21), "192.168.1.1:21");
        assert_eq!(format_listen_addresses("::1", 21), "[::1]:21");
    }

    #[test]
    fn test_format_listen_addresses_wildcard() {
        let formatted = format_listen_addresses("0.0.0.0", 2121);
        assert!(formatted.starts_with("0.0.0.0:2121"));
        assert!(formatted.contains("2121"));
    }
}

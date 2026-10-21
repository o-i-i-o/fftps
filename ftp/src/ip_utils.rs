//! IP 地址分类工具（迁移自 wftpd-windows `ftp_server/ip_utils.rs`）
//!
//! 为 FTP 服务端提供内网/公网/回环地址判定，供主动模式 NAT 判定与
//! 被动模式地址选择复用。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP 地址归属分类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddressClass {
    /// 回环地址
    Loopback,
    /// 私有/链路本地地址
    Private,
    /// 公网地址
    Public,
}

/// 是否为私有 IPv4（10/8、172.16/12、192.168/16、169.254/16 链路本地）
#[must_use]
pub fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    if octets[0] == 10 {
        return true;
    }
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    false
}

/// 是否为私有 IPv6（fc00::/7 唯一本地、fe80::/10 链路本地）
#[must_use]
pub fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    if segments[0] == 0xfc00 || segments[0] == 0xfd00 {
        return true;
    }
    if segments[0] == 0xfe80 {
        return true;
    }
    false
}

/// 是否为私有地址（IPv4/IPv6 泛化）
#[must_use]
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// 是否为回环地址
#[must_use]
pub fn is_loopback_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

/// 分类 IP 地址：回环 > 私有 > 公网
#[must_use]
pub fn classify_ip_address(ip: &IpAddr) -> IpAddressClass {
    if is_loopback_ip(ip) {
        IpAddressClass::Loopback
    } else if is_private_ip(ip) {
        IpAddressClass::Private
    } else {
        IpAddressClass::Public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 0, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 32, 0, 1)));
    }

    #[test]
    fn test_is_private_ipv6() {
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_private_ipv6(&Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
    }

    #[test]
    fn test_is_private_ip_and_loopback() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
        assert!(is_loopback_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_loopback_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_loopback_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_classify_ip_address() {
        assert_eq!(
            classify_ip_address(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            IpAddressClass::Loopback
        );
        assert_eq!(
            classify_ip_address(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            IpAddressClass::Private
        );
        assert_eq!(
            classify_ip_address(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            IpAddressClass::Public
        );
    }
}

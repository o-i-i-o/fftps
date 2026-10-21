//! FTP 主动模式 NAT 判定（迁移自 wftpd-windows `ftp_server/active_mode.rs`）
//!
//! 通过比较 PORT 命令携带的 IP 与客户端实际 TCP 连接 IP，判定客户端是否位于
//! NAT 之后。libunftp 0.23 未开放 PORT 命令钩子，因此本模块保留为纯判定函数，
//! 由 [`crate::service`] 的 `allow_nat_clients` 配置驱动，便于后续接入命令钩子。

use std::net::IpAddr;

/// 客户端 NAT 状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientNatStatus {
    /// 直连（PORT IP 与 TCP 连接 IP 一致）
    Direct,
    /// 位于 NAT 之后
    BehindNat,
}

/// 主动模式连接分析结果
#[derive(Debug, Clone)]
pub struct ActiveModeInfo {
    /// PORT 命令中的 IP
    pub port_ip: IpAddr,
    /// TCP 连接对端 IP
    pub tcp_ip: IpAddr,
    /// 判定的 NAT 状态
    pub nat_status: ClientNatStatus,
}

/// 主动模式策略配置
#[derive(Debug, Clone)]
pub struct ActiveModeConfig {
    /// 是否接受 NAT 客户端的 PORT 命令
    pub allow_nat_clients: bool,
    /// 是否校验 PORT IP 可达性（预留）
    pub validate_port_ip_reachable: bool,
}

impl Default for ActiveModeConfig {
    fn default() -> Self {
        ActiveModeConfig {
            allow_nat_clients: true,
            validate_port_ip_reachable: false,
        }
    }
}

/// 判定客户端是否位于 NAT 之后
#[must_use]
pub fn detect_client_nat(port_command_ip: IpAddr, tcp_connection_ip: IpAddr) -> ClientNatStatus {
    if port_command_ip == tcp_connection_ip {
        ClientNatStatus::Direct
    } else {
        ClientNatStatus::BehindNat
    }
}

/// 是否接受 PORT 命令：直连放行；NAT 客户端按 `allow_nat_clients` 策略处理
#[must_use]
pub fn should_accept_port_command(port_ip: IpAddr, tcp_ip: IpAddr, allow_nat_clients: bool) -> bool {
    let nat_status = detect_client_nat(port_ip, tcp_ip);

    match nat_status {
        ClientNatStatus::Direct => true,
        ClientNatStatus::BehindNat => {
            if allow_nat_clients {
                tracing::info!(
                    port_ip = %port_ip,
                    tcp_ip = %tcp_ip,
                    "主动模式：检测到 NAT 客户端，按策略放行"
                );
                true
            } else {
                tracing::warn!(
                    port_ip = %port_ip,
                    tcp_ip = %tcp_ip,
                    "主动模式：检测到 NAT 客户端，按策略拒绝"
                );
                false
            }
        }
    }
}

/// 分析主动模式连接并记录 NAT 策略命中情况
#[must_use]
pub fn analyze_active_mode_connection(
    port_ip: IpAddr,
    tcp_ip: IpAddr,
    config: &ActiveModeConfig,
) -> ActiveModeInfo {
    let nat_status = detect_client_nat(port_ip, tcp_ip);

    if nat_status == ClientNatStatus::BehindNat && !config.allow_nat_clients {
        tracing::warn!(
            port_ip = %port_ip,
            tcp_ip = %tcp_ip,
            "主动模式：NAT 客户端被策略拒绝"
        );
    }

    ActiveModeInfo {
        port_ip,
        tcp_ip,
        nat_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::ip_utils::{IpAddressClass, classify_ip_address, is_private_ipv4, is_private_ipv6};

    #[test]
    fn test_detect_client_nat_direct() {
        let port_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let tcp_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(detect_client_nat(port_ip, tcp_ip), ClientNatStatus::Direct);
    }

    #[test]
    fn test_detect_client_nat_behind_nat() {
        let port_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let tcp_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        assert_eq!(
            detect_client_nat(port_ip, tcp_ip),
            ClientNatStatus::BehindNat
        );
    }

    #[test]
    fn test_should_accept_port_command() {
        let port_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let tcp_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));

        assert!(should_accept_port_command(port_ip, tcp_ip, true));
        assert!(!should_accept_port_command(port_ip, tcp_ip, false));
    }

    #[test]
    fn test_analyze_active_mode_connection() {
        let port_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let tcp_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));

        let info = analyze_active_mode_connection(port_ip, tcp_ip, &ActiveModeConfig::default());
        assert_eq!(info.nat_status, ClientNatStatus::BehindNat);
        assert_eq!(info.port_ip, port_ip);
        assert_eq!(info.tcp_ip, tcp_ip);
    }

    #[test]
    fn test_default_active_mode_config() {
        let config = ActiveModeConfig::default();
        assert!(config.allow_nat_clients);
        assert!(!config.validate_port_ip_reachable);
    }

    // 复用 ip_utils 判定的回归用例（迁移自旧 active_mode 测试）
    #[test]
    fn test_ip_utils_regression() {
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 32, 0, 1)));

        assert!(is_private_ipv6(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_private_ipv6(&Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));

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

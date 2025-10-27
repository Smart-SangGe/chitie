use crate::{Category, Finding, Severity};
use std::fs;

///  Network Information - Network Neighbours
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Get routing and ARP information
///
///  Checks for:
///  - Routing table from /proc/net/route
///  - ARP table from /proc/net/arp
///  - IPv6 neighbors from /proc/net/ipv6_neigh
///
///  References:
///  - Based on LinPEAS NT_Network_neighbours
///
///  Execution Mode:
///  - Default: no
///  - Stealth (-s): no
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let config = crate::config::config();

    // 只在extra模式下运行
    if !config.extra && !config.all_checks {
        return None;
    }

    let mut finding = Finding::new(
        Category::Network,
        Severity::Info,
        "Network Neighbours",
        "Routing and ARP information",
    );

    let mut details = Vec::new();

    // 解析路由表
    if let Ok(route_content) = fs::read_to_string("/proc/net/route") {
        details.push("=== ROUTING TABLE ===".to_string());
        details.push(format!(
            "{:<18} {:<15} {:<15} {:<6} {:<6} {:<6} {:<6} {}",
            "Destination", "Gateway", "Genmask", "Flags", "Metric", "Ref", "Use", "Iface"
        ));

        for line in route_content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 8 {
                let iface = parts[0];
                let dest = parse_hex_ip_le(parts[1]).unwrap_or_else(|| parts[1].to_string());
                let gateway = parse_hex_ip_le(parts[2]).unwrap_or_else(|| parts[2].to_string());
                let flags = parts[3];
                let metric = parts[6];
                let ref_count = parts[7];
                let use_count = parts[8];
                let mask = if parts.len() > 7 {
                    parse_hex_ip_le(parts[7]).unwrap_or_else(|| "0.0.0.0".to_string())
                } else {
                    "0.0.0.0".to_string()
                };

                details.push(format!(
                    "{:<18} {:<15} {:<15} {:<6} {:<6} {:<6} {:<6} {}",
                    dest, gateway, mask, flags, metric, ref_count, use_count, iface
                ));
            }
        }
        details.push(String::new());
    }

    // 解析ARP表
    if let Ok(arp_content) = fs::read_to_string("/proc/net/arp") {
        details.push("=== ARP TABLE ===".to_string());
        details.push(format!(
            "{:<15} {:<11} {:<9} {:<18} {:<8} {}",
            "IP address", "HW type", "Flags", "HW address", "Mask", "Device"
        ));

        for line in arp_content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let ip = parts[0];
                let hwtype = parts[1];
                let flags = parts[2];
                let hwaddr = parts[3];
                let mask = parts[4];
                let device = parts[5];

                details.push(format!(
                    "{:<15} {:<11} {:<9} {:<18} {:<8} {}",
                    ip, hwtype, flags, hwaddr, mask, device
                ));
            }
        }
        details.push(String::new());
    }

    // 解析IPv6邻居
    if let Ok(ipv6_content) = fs::read_to_string("/proc/net/ipv6_neigh") {
        let neighbors: Vec<&str> = ipv6_content.lines().skip(1).collect();
        if !neighbors.is_empty() {
            details.push("=== IPV6 NEIGHBOURS ===".to_string());
            for line in neighbors {
                if !line.trim().is_empty() {
                    details.push(format!("  {}", line.trim()));
                }
            }
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

/// 解析十六进制IP地址（小端序）
fn parse_hex_ip_le(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }

    let bytes = (0..4)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;

    // 小端序反转
    Some(format!(
        "{}.{}.{}.{}",
        bytes[3], bytes[2], bytes[1], bytes[0]
    ))
}

use crate::{Category, Finding, Severity};
use std::fs;

///  Network Information - Open Ports
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Enumerate listening network ports
///
///  Checks for:
///  - TCP listening ports from /proc/net/tcp
///  - UDP listening ports from /proc/net/udp
///  - Process information for each port
///  - Ports bound to all interfaces (security risk)
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports
///  - Based on LinPEAS NT_Open_ports
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Network,
        Severity::Info,
        "Open Ports",
        "Listening network ports",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports",
    );

    let mut details = Vec::new();

    // Parse TCP ports
    details.push("=== TCP LISTENING PORTS ===".to_string());
    if let Some(tcp_ports) = parse_proc_net_ports("/proc/net/tcp", "TCP") {
        if tcp_ports.is_empty() {
            details.push("  No TCP listening ports found".to_string());
        } else {
            details.extend(tcp_ports);
        }
    }
    details.push(String::new());

    // Parse UDP ports
    details.push("=== UDP LISTENING PORTS ===".to_string());
    if let Some(udp_ports) = parse_proc_net_ports("/proc/net/udp", "UDP") {
        if udp_ports.is_empty() {
            details.push("  No UDP listening ports found".to_string());
        } else {
            details.extend(udp_ports);
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

/// Parse /proc/net/tcp or /proc/net/udp for listening ports
fn parse_proc_net_ports(path: &str, proto: &str) -> Option<Vec<String>> {
    let content = fs::read_to_string(path).ok()?;
    let mut ports = Vec::new();

    for line in content.lines().skip(1) {
        // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        // Parse state (TCP state 0A = LISTEN, UDP state 07 = CLOSE/listening)
        let state = parts.get(3)?;
        let is_listening = if proto == "TCP" {
            *state == "0A" // LISTEN state
        } else {
            *state == "07" // UDP "CLOSE" actually means listening
        };

        if !is_listening {
            continue;
        }

        // Parse local address (format: HEXIP:HEXPORT)
        let local_addr = parts.get(1)?;
        if let Some((hex_ip, hex_port)) = local_addr.split_once(':') {
            if let (Some(ip), Some(port)) = (parse_hex_ip(hex_ip), parse_hex_port(hex_port)) {
                let inode = parts.get(9).unwrap_or(&"");

                // Find process by inode
                let process = find_process_by_inode(inode);

                // Check if bound to all interfaces (potential security issue)
                let bind_warning = if ip == "0.0.0.0" || ip == "0:0:0:0:0:0:0:0" {
                    " [BOUND TO ALL INTERFACES]"
                } else {
                    ""
                };

                ports.push(format!(
                    "  {:<5} {}:{:<6} {}{}",
                    proto, ip, port, process, bind_warning
                ));
            }
        }
    }

    Some(ports)
}

/// Parse hex IP address to dotted decimal format
fn parse_hex_ip(hex: &str) -> Option<String> {
    if hex.len() == 8 {
        // IPv4 (little-endian)
        let bytes = (0..4)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        Some(format!(
            "{}.{}.{}.{}",
            bytes[3], bytes[2], bytes[1], bytes[0]
        ))
    } else if hex.len() == 32 {
        // IPv6 (little-endian by 4-byte groups)
        let parts: Vec<String> = (0..8)
            .map(|i| {
                let start = i * 4;
                let group = &hex[start..start + 4];
                // Reverse byte order within each 4-char group
                let b1 = &group[2..4];
                let b2 = &group[0..2];
                format!("{}{}", b1, b2)
            })
            .collect();
        Some(parts.join(":"))
    } else {
        None
    }
}

/// Parse hex port to decimal
fn parse_hex_port(hex: &str) -> Option<u16> {
    u16::from_str_radix(hex, 16).ok()
}

/// Find process information by socket inode
fn find_process_by_inode(inode: &str) -> String {
    if inode.is_empty() || inode == "0" {
        return "-".to_string();
    }

    // Search /proc/*/fd/* for matching socket inode
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Only process numeric directories (PIDs)
            if let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) {
                if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                let fd_path = path.join("fd");
                if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                    for fd_entry in fd_entries.filter_map(Result::ok) {
                        let fd_link = fd_entry.path();
                        if let Ok(link_target) = fs::read_link(&fd_link) {
                            let target = link_target.to_string_lossy();
                            if target.contains(&format!("socket:[{}]", inode)) {
                                // Found the process, get its name
                                let cmdline_path = path.join("cmdline");
                                if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                                    let program = cmdline
                                        .split('\0')
                                        .next()
                                        .unwrap_or("")
                                        .split('/')
                                        .last()
                                        .unwrap_or("");
                                    if !program.is_empty() {
                                        return format!("{}/{}", pid_str, program);
                                    }
                                }
                                return format!("{}", pid_str);
                            }
                        }
                    }
                }
            }
        }
    }

    "-".to_string()
}

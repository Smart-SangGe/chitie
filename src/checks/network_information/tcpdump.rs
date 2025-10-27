use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;

///  Network Information - Network Traffic Analysis
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Check network traffic analysis capabilities
///
///  Checks for:
///  - Sniffing tools (tcpdump, tshark, wireshark)
///  - Sniffable network interfaces
///  - Promiscuous mode on interfaces
///  - Network monitoring tools
///
///  References:
///  - Based on LinPEAS NT_Tcpdump
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
        "Network Traffic Analysis",
        "Network sniffing capabilities",
    );

    let mut details = Vec::new();

    // 检查嗅探工具
    details.push("=== SNIFFING TOOLS ===".to_string());
    let mut found_tools = false;

    for tool in &["tcpdump", "tshark", "wireshark", "dumpcap"] {
        if let Ok(output) = Command::new("command").args(["-v", tool]).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                details.push(format!("{} -> {}", tool, path));
                found_tools = true;

                // 尝试获取版本
                if *tool == "tcpdump" || *tool == "tshark" {
                    if let Ok(ver_output) = Command::new(tool).arg("--version").output() {
                        let version = String::from_utf8_lossy(&ver_output.stderr);
                        if let Some(first_line) = version.lines().next() {
                            details.push(format!("  Version: {}", first_line.trim()));
                        }
                    }
                }
            }
        }
    }

    if !found_tools {
        details.push("No sniffing tools found".to_string());
    } else {
        finding.severity = Severity::Medium;
        finding.description = "Network sniffing tools available".to_string();
    }
    details.push(String::new());

    // 检查网络接口嗅探能力
    details.push("=== SNIFFABLE INTERFACES ===".to_string());
    let mut sniffable_interfaces = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.filter_map(Result::ok) {
            let iface = entry.file_name();
            let iface_str = iface.to_string_lossy();

            // 跳过loopback
            if iface_str == "lo" {
                continue;
            }

            // 检查接口是否启用
            let operstate_path = format!("/sys/class/net/{}/operstate", iface_str);
            if let Ok(state) = fs::read_to_string(&operstate_path) {
                let state_str = state.trim();

                // 检查是否处于混杂模式
                let flags_path = format!("/sys/class/net/{}/flags", iface_str);
                let is_promisc = if let Ok(flags_hex) = fs::read_to_string(&flags_path) {
                    if let Ok(flags) =
                        u32::from_str_radix(flags_hex.trim().trim_start_matches("0x"), 16)
                    {
                        (flags & 0x100) != 0 // IFF_PROMISC
                    } else {
                        false
                    }
                } else {
                    false
                };

                sniffable_interfaces.push(format!(
                    "Interface: {} (state: {}){}",
                    iface_str,
                    state_str,
                    if is_promisc {
                        " [PROMISCUOUS MODE]"
                    } else {
                        ""
                    }
                ));

                if is_promisc {
                    finding.severity = Severity::High;
                }
            }
        }
    }

    if sniffable_interfaces.is_empty() {
        details.push("No sniffable interfaces found".to_string());
    } else {
        details.extend(sniffable_interfaces);
    }
    details.push(String::new());

    // 在extra模式下检查其他网络监控工具
    let config = crate::config::config();
    if config.extra || config.all_checks {
        details.push("=== NETWORK MONITORING TOOLS ===".to_string());
        let mut found_monitoring = false;

        for tool in &["nethogs", "iftop", "iotop", "nload", "bmon", "vnstat"] {
            if let Ok(output) = Command::new("command").args(["-v", tool]).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    details.push(format!("{} -> {}", tool, path));
                    found_monitoring = true;
                }
            }
        }

        if !found_monitoring {
            details.push("No additional monitoring tools found".to_string());
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

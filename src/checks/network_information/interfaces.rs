use crate::{Category, Finding, Severity};
use std::fs;

///  Network Information - Network Interfaces
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Enumerate network interfaces and their configuration
///
///  Checks for:
///  - Network interfaces from /proc/net/dev
///  - MAC addresses from /sys/class/net
///  - Interface states (up/down)
///  - IP addresses
///
///  References:
///  - Based on LinPEAS NT_Network_interfaces
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
        "Network Interfaces",
        "Network interface configuration",
    );

    let mut interface_info = Vec::new();

    // Read /proc/net/dev to get interface list
    if let Ok(dev_content) = fs::read_to_string("/proc/net/dev") {
        for line in dev_content.lines().skip(2) {
            // Skip header lines
            if let Some((iface_part, _)) = line.split_once(':') {
                let iface = iface_part.trim();
                if iface.is_empty() {
                    continue;
                }

                interface_info.push(format!("Interface: {}", iface));

                // Get MAC address from /sys/class/net/{iface}/address
                let mac_path = format!("/sys/class/net/{}/address", iface);
                if let Ok(mac) = fs::read_to_string(&mac_path) {
                    interface_info.push(format!("  MAC: {}", mac.trim()));
                }

                // Get interface state from /sys/class/net/{iface}/operstate
                let state_path = format!("/sys/class/net/{}/operstate", iface);
                if let Ok(state) = fs::read_to_string(&state_path) {
                    interface_info.push(format!("  State: {}", state.trim()));
                }

                // Try to get IP address from /proc/net/fib_trie
                if let Ok(fib_content) = fs::read_to_string("/proc/net/fib_trie") {
                    let mut found_ip = false;
                    for fib_line in fib_content.lines() {
                        if fib_line.contains("/32 host LOCAL")
                            && let Some(prev_line) =
                                fib_content.lines().take_while(|l| l != &fib_line).last()
                            && let Some(ip) = prev_line.split_whitespace().last()
                            && !ip.starts_with("127.")
                            && !ip.starts_with("0.0.0.0")
                            && !found_ip
                        {
                            interface_info.push(format!("  IP: {}", ip));
                            found_ip = true;
                        }
                    }
                }

                interface_info.push(String::new());
            }
        }
    }

    if interface_info.is_empty() {
        return None;
    }

    finding.details = interface_info;
    Some(finding)
}

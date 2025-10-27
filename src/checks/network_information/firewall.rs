use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;

///  Network Information - Firewall Rules
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Analyze firewall rules and configurations
///
///  Checks for:
///  - Iptables rules and saved configurations
///  - Nftables rules
///  - UFW (Uncomplicated Firewall) status
///  - Firewalld configuration
///
///  References:
///  - Based on LinPEAS NT_Iptables
///
///  Execution Mode:
///  - Default: no
///  - Stealth (-s): no
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Network,
        Severity::Info,
        "Firewall Rules",
        "Firewall configuration and rules",
    );

    let mut details = Vec::new();

    // Check iptables
    if let Some(iptables_info) = check_iptables() {
        details.push("=== IPTABLES ===".to_string());
        details.extend(iptables_info);
        details.push(String::new());
    }

    // Check nftables
    if let Some(nftables_info) = check_nftables() {
        details.push("=== NFTABLES ===".to_string());
        details.extend(nftables_info);
        details.push(String::new());
    }

    // Check UFW
    if let Some(ufw_info) = check_ufw() {
        details.push("=== UFW ===".to_string());
        details.extend(ufw_info);
        details.push(String::new());
    }

    // Check firewalld
    if let Some(firewalld_info) = check_firewalld() {
        details.push("=== FIREWALLD ===".to_string());
        details.extend(firewalld_info);
        details.push(String::new());
    }

    if details.is_empty() {
        details.push("No firewall configuration detected".to_string());
    }

    finding.details = details;
    Some(finding)
}

/// Check iptables configuration
fn check_iptables() -> Option<Vec<String>> {
    let mut info = Vec::new();

    // Check if iptables command exists
    if Command::new("command")
        .args(["-v", "iptables"])
        .output()
        .ok()?
        .status
        .success()
    {
        // Try to list iptables rules
        if let Ok(output) = Command::new("iptables").args(["-L", "-n"]).output() {
            if output.status.success() {
                let rules = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = rules.lines().take(20).collect();
                if !lines.is_empty() {
                    info.push("Iptables rules (filter table):".to_string());
                    for line in lines {
                        info.push(format!("  {}", line));
                    }
                } else {
                    info.push("Iptables is present but no rules found".to_string());
                }
            } else {
                info.push("Iptables installed but no permission to list rules".to_string());
            }
        }

        // Check for saved rules
        let saved_rules_paths = [
            "/etc/iptables/rules.v4",
            "/etc/iptables/rules.v6",
            "/etc/sysconfig/iptables",
            "/etc/sysconfig/ip6tables",
        ];

        let mut found_saved = false;
        for path in &saved_rules_paths {
            if fs::metadata(path).is_ok() {
                if !found_saved {
                    info.push(String::new());
                    info.push("Saved iptables rules found:".to_string());
                    found_saved = true;
                }
                info.push(format!("  {}", path));
            }
        }
    }

    if info.is_empty() { None } else { Some(info) }
}

/// Check nftables configuration
fn check_nftables() -> Option<Vec<String>> {
    let mut info = Vec::new();

    // Check if nft command exists
    if Command::new("command")
        .args(["-v", "nft"])
        .output()
        .ok()?
        .status
        .success()
    {
        // Try to list nftables rules
        if let Ok(output) = Command::new("nft").args(["list", "ruleset"]).output() {
            if output.status.success() {
                let rules = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = rules.lines().take(30).collect();
                if !lines.is_empty() && lines.len() > 1 {
                    info.push("Nftables ruleset:".to_string());
                    for line in lines {
                        info.push(format!("  {}", line));
                    }
                } else {
                    info.push("Nftables is present but no rules configured".to_string());
                }
            } else {
                info.push("Nftables installed but no permission to list rules".to_string());
            }
        }

        // Check for saved configuration
        let config_paths = ["/etc/nftables.conf", "/etc/sysconfig/nftables.conf"];
        let mut found_config = false;
        for path in &config_paths {
            if fs::metadata(path).is_ok() {
                if !found_config {
                    info.push(String::new());
                    info.push("Nftables configuration found:".to_string());
                    found_config = true;
                }
                info.push(format!("  {}", path));
            }
        }
    }

    if info.is_empty() { None } else { Some(info) }
}

/// Check UFW (Uncomplicated Firewall) status
fn check_ufw() -> Option<Vec<String>> {
    let mut info = Vec::new();

    // Check if ufw command exists
    if Command::new("command")
        .args(["-v", "ufw"])
        .output()
        .ok()?
        .status
        .success()
    {
        // Get UFW status
        if let Ok(output) = Command::new("ufw").arg("status").output() {
            if output.status.success() {
                let status = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = status.lines().take(20).collect();
                info.push("UFW status:".to_string());
                for line in lines {
                    info.push(format!("  {}", line));
                }
            } else {
                info.push("UFW installed but no permission to check status".to_string());
            }
        }

        // Check for UFW rules files
        if fs::metadata("/etc/ufw/user.rules").is_ok() {
            info.push(String::new());
            info.push("UFW configuration files found in /etc/ufw/".to_string());
        }
    }

    if info.is_empty() { None } else { Some(info) }
}

/// Check firewalld status
fn check_firewalld() -> Option<Vec<String>> {
    let mut info = Vec::new();

    // Check if firewall-cmd command exists
    if Command::new("command")
        .args(["-v", "firewall-cmd"])
        .output()
        .ok()?
        .status
        .success()
    {
        // Check if firewalld is running
        if let Ok(output) = Command::new("systemctl")
            .args(["is-active", "firewalld"])
            .output()
        {
            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            info.push(format!("Firewalld status: {}", status));

            if status == "active" {
                // Get active zones
                if let Ok(zones_output) = Command::new("firewall-cmd")
                    .arg("--get-active-zones")
                    .output()
                    && zones_output.status.success()
                {
                    let zones = String::from_utf8_lossy(&zones_output.stdout);
                    info.push(String::new());
                    info.push("Active zones:".to_string());
                    for line in zones.lines().take(10) {
                        info.push(format!("  {}", line));
                    }
                }

                // Get default zone
                if let Ok(default_output) = Command::new("firewall-cmd")
                    .arg("--get-default-zone")
                    .output()
                    && default_output.status.success()
                {
                    let default_zone = String::from_utf8_lossy(&default_output.stdout);
                    info.push(String::new());
                    info.push(format!("Default zone: {}", default_zone.trim()));
                }
            }
        }
    }

    if info.is_empty() { None } else { Some(info) }
}

use crate::{Category, Finding, Severity};
use std::fs;

///  Network Information - Hostname, Hosts and DNS
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Enumerate hostname and DNS configuration
///
///  Checks for:
///  - System hostname from /proc/sys/kernel/hostname
///  - /etc/hostname contents
///  - /etc/hosts entries
///  - DNS servers from /etc/resolv.conf
///  - systemd-resolved configuration
///
///  References:
///  - Based on LinPEAS NT_Hostname_hosts_dns
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
        "Hostname and DNS",
        "Hostname and DNS configuration",
    );

    let mut details = Vec::new();

    // Get hostname from /proc/sys/kernel/hostname
    if let Ok(hostname) = fs::read_to_string("/proc/sys/kernel/hostname") {
        details.push("=== HOSTNAME ===".to_string());
        details.push(format!("System hostname: {}", hostname.trim()));
    }

    // Get hostname from /etc/hostname as fallback
    if let Ok(hostname) = fs::read_to_string("/etc/hostname") {
        details.push(format!("From /etc/hostname: {}", hostname.trim()));
    }

    details.push(String::new());

    // Get hosts file information
    if let Ok(hosts_content) = fs::read_to_string("/etc/hosts") {
        details.push("=== HOSTS FILE ===".to_string());
        let mut hosts_entries = Vec::new();
        for line in hosts_content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                hosts_entries.push(format!("  {}", trimmed));
            }
        }
        if !hosts_entries.is_empty() {
            details.extend(hosts_entries);
        } else {
            details.push("  No custom entries".to_string());
        }
        details.push(String::new());
    }

    // Get DNS configuration from /etc/resolv.conf
    if let Ok(resolv_content) = fs::read_to_string("/etc/resolv.conf") {
        details.push("=== DNS CONFIGURATION ===".to_string());
        let mut nameservers = Vec::new();
        let mut other_settings = Vec::new();

        for line in resolv_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("nameserver") {
                if let Some(ns) = trimmed.split_whitespace().nth(1) {
                    nameservers.push(format!("  Nameserver: {}", ns));
                }
            } else if trimmed.starts_with("search") || trimmed.starts_with("domain") {
                other_settings.push(format!("  {}", trimmed));
            }
        }

        if !nameservers.is_empty() {
            details.extend(nameservers);
        }
        if !other_settings.is_empty() {
            details.extend(other_settings);
        }
        details.push(String::new());
    }

    // Check systemd-resolved configuration (if extra mode)
    let config = crate::config::config();
    if (config.extra || config.all_checks)
        && let Ok(resolved_content) = fs::read_to_string("/etc/systemd/resolved.conf")
    {
        details.push("=== SYSTEMD-RESOLVED ===".to_string());
        let mut resolved_settings = Vec::new();
        for line in resolved_content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with('[') {
                resolved_settings.push(format!("  {}", trimmed));
            }
        }
        if !resolved_settings.is_empty() {
            details.extend(resolved_settings);
        } else {
            details.push("  No custom settings".to_string());
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;
use std::path::Path;
use walkdir::WalkDir;

///  Processes & Services - D-Bus Analysis
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Comprehensive D-Bus analysis for privilege escalation vectors
///  Corresponds to LinPEAS: 14_DBus_analysis.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Process,
        Severity::Info,
        "D-Bus Analysis",
        "Analyzing D-Bus services and policy configurations for privilege escalation",
    );

    let mut details = Vec::new();

    // 1. List D-Bus services via busctl
    if let Ok(output) = Command::new("busctl").arg("list").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut dangerous_found = Vec::new();
        
        // Known dangerous services
        let dangerous_services = vec![
            "org.freedesktop.systemd1", "org.freedesktop.PolicyKit1", "org.freedesktop.Accounts",
            "org.freedesktop.login1", "org.freedesktop.hostname1", "org.gnome.SettingsDaemon"
        ];

        for line in stdout.lines() {
            for ds in &dangerous_services {
                if line.contains(ds) {
                    dangerous_found.push(format!("  [!] HIGH: Dangerous service active: {}", line.trim()));
                    finding.severity = Severity::High;
                }
            }
        }

        if !dangerous_found.is_empty() {
            details.push("=== Active Dangerous D-Bus Services ===".to_string());
            details.extend(dangerous_found);
        }
    }

    // 2. Policy File Audit
    let policy_dir = "/etc/dbus-1/system.d/";
    if Path::new(policy_dir).exists() {
        details.push("\n=== D-Bus Policy Audit ===".to_string());
        
        for entry in WalkDir::new(policy_dir)
            .max_depth(2)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() { continue; }

            // Check for writable policy files
            if nix::unistd::access(path, nix::unistd::AccessFlags::W_OK).is_ok() {
                details.push(format!("  [!] CRITICAL: Writable D-Bus policy file: {}", path.display()));
                finding.severity = Severity::Critical;
            }

            // Simple XML grep for weak policies
            if let Ok(content) = fs::read_to_string(path) {
                if content.contains("allow_any=\"true\"") || content.contains("allow_all=\"true\"") {
                    details.push(format!("  [!] HIGH: Weak 'allow_any' policy found in {}", path.display()));
                    if finding.severity < Severity::High {
                        finding.severity = Severity::High;
                    }
                }
                
                // Check for user-specific allow rules
                if content.contains("<policy user=\"") && !content.contains("user=\"root\"") {
                    if content.contains("send_destination") {
                        details.push(format!("  [!] WARNING: User-specific allow rule in {}", path.display()));
                        if finding.severity < Severity::Medium {
                            finding.severity = Severity::Medium;
                        }
                    }
                }
            }
        }
    }

    // 3. Session Bus access
    if let Ok(output) = Command::new("dbus-send")
        .args(&["--session", "--dest=org.freedesktop.DBus", "--type=method_call", "--print-reply", "/org/freedesktop/DBus", "org.freedesktop.DBus.ListNames"])
        .output() 
    {
        if output.status.success() {
            details.push("\n[+] Access to D-Bus SESSION bus available".to_string());
            if finding.severity < Severity::Medium {
                finding.severity = Severity::Medium;
            }
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}
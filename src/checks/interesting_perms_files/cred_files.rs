use crate::{Category, Finding, Severity};
use regex::Regex;
use std::fs;
use std::os::unix::fs::PermissionsExt;

///  Interesting Permissions - Credential Files
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Check for hashes in passwd, readable shadow files, etc.
///
///  Checks for:
///  - Password hashes in /etc/passwd
///  - Writable /etc/passwd
///  - Credentials in /etc/fstab, /etc/mtab
///  - Readable shadow files (/etc/shadow, etc.)
///  - Readable /etc/security/opasswd
///  - Readable /root/ directory
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credential-files
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "Credential Files",
        "Check for sensitive files that might contain credentials or are misconfigured",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credential-files");

    let mut details = Vec::new();
    let mut high_severity = false;

    // 1. Hashes in /etc/passwd
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 1 {
                let pwd_field = parts[1];
                if pwd_field != "x" && pwd_field != "*" && pwd_field != "!" && !pwd_field.is_empty()
                {
                    details.push(format!(
                        "CRITICAL: Password hash found in /etc/passwd: {}",
                        line
                    ));
                    high_severity = true;
                    finding.severity = Severity::Critical;
                }
            }
        }
    }

    // 2. Writable passwd file
    let passwd_paths = ["/etc/passwd", "/etc/pwd.db", "/etc/master.passwd"];
    for p in passwd_paths {
        if let Ok(metadata) = fs::metadata(p) {
            if is_writable(&metadata) {
                details.push(format!("CRITICAL: {} is writable", p));
                high_severity = true;
                finding.severity = Severity::Critical;
            }
        }
    }

    // 3. Credentials in fstab/mtab
    let fstab_paths = ["/etc/fstab", "/etc/mtab"];
    let cred_regex =
        Regex::new(r"(?i)(user|username|login|pass|password|pw|credentials)[=:]").unwrap();
    for p in fstab_paths {
        if let Ok(content) = fs::read_to_string(p) {
            for line in content.lines() {
                if cred_regex.is_match(line) {
                    details.push(format!("HIGH: Possible credentials in {}: {}", p, line));
                    high_severity = true;
                }
            }
        }
    }

    // 4. Readable shadow files
    let shadow_files = [
        "/etc/shadow",
        "/etc/shadow-",
        "/etc/shadow~",
        "/etc/gshadow",
        "/etc/gshadow-",
        "/etc/master.passwd",
        "/etc/spwd.db",
    ];
    for p in shadow_files {
        if fs::read(p).is_ok() {
            details.push(format!("CRITICAL: Can read shadow file: {}", p));
            high_severity = true;
            finding.severity = Severity::Critical;
        }
    }

    // 5. Readable opasswd
    if fs::read("/etc/security/opasswd").is_ok() {
        details.push("HIGH: Can read /etc/security/opasswd".to_string());
        high_severity = true;
    }

    // 6. Readable /root/
    if let Ok(entries) = fs::read_dir("/root") {
        details.push("HIGH: Can read /root/ directory content".to_string());
        high_severity = true;
        for entry in entries.take(5).filter_map(|e| e.ok()) {
            details.push(format!("  - {}", entry.path().display()));
        }
    }

    // 7. Writable network-scripts
    let net_scripts = "/etc/sysconfig/network-scripts/";
    if Path::new(net_scripts).exists() {
        let mut writable_net = Vec::new();
        if let Ok(metadata) = fs::metadata(net_scripts) {
            if is_writable(&metadata) {
                writable_net.push(net_scripts.to_string());
            }
        }

        // Also check files inside
        if let Ok(entries) = fs::read_dir(net_scripts) {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Ok(m) = entry.metadata() {
                    if is_writable(&m) {
                        writable_net.push(entry.path().display().to_string());
                    }
                }
            }
        }

        if !writable_net.is_empty() {
            details.push("CRITICAL: You have write privileges over network-scripts:".to_string());
            for p in writable_net.iter().take(5) {
                details.push(format!("  - {}", p));
            }
            high_severity = true;
            finding.severity = Severity::Critical;
        }
    }

    if high_severity && finding.severity < Severity::High {
        finding.severity = Severity::High;
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

use nix::unistd::{getgroups, getuid};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

fn is_writable(metadata: &fs::Metadata) -> bool {
    let mode = metadata.permissions().mode();
    let current_uid = getuid().as_raw();

    // World writable
    if mode & 0o002 != 0 {
        return true;
    }

    // Owned by user
    if metadata.uid() == current_uid && (mode & 0o200 != 0) {
        return true;
    }

    // Group writable
    let current_groups: std::collections::HashSet<u32> = getgroups()
        .unwrap_or_default()
        .into_iter()
        .map(|g| g.as_raw())
        .collect();

    if current_groups.contains(&metadata.gid()) && (mode & 0o020 != 0) {
        return true;
    }

    false
}

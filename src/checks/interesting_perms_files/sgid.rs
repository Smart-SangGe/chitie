use crate::{Category, Finding, Severity};
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

///  Interesting Permissions - SGID Files
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Find and analyze SGID binaries for privilege escalation
///
///  Checks for:
///  - SGID binaries on the system
///  - Owned/writable SGID files
///  - Known vulnerable SGID binaries
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes (limit search)
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let config = crate::config::config();

    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "SGID Files",
        "SGID binaries that could be exploited",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid");

    // Known dangerous SGID binaries (often overlap with SUID)
    let dangerous_sgids = [
        "nmap", "vim", "vi", "nano", "find", "bash", "sh", "more", "less", "man", "awk", "gawk",
        "perl", "python", "ruby", "lua", "php", "tclsh", "wish", "rvim", "rview", "emacs", "git",
        "ftp", "socat", "taskset", "strace", "gdb", "docker", "kubectl", "exim4-config_files",
    ];

    let mut sgid_files = Vec::new();
    let mut dangerous_found = Vec::new();
    let mut writable_found = Vec::new();

    // Limit search path and depth
    let search_paths = if config.stealth {
        vec!["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    } else {
        vec!["/usr", "/bin", "/sbin", "/opt"]
    };

    let max_depth = if config.stealth { 3 } else { 10 };

    for search_path in search_paths {
        for entry in WalkDir::new(search_path)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if let Ok(metadata) = entry.metadata() {
                let mode = metadata.permissions().mode();

                // Check SGID bit (mode & 0o2000)
                if mode & 0o2000 != 0 {
                    let path_str = path.display().to_string();

                    // Check if writable
                    if mode & 0o002 != 0 || mode & 0o020 != 0 {
                        writable_found.push(format!("CRITICAL: Writable SGID: {}", path_str));
                        finding.severity = Severity::Critical;
                        continue;
                    }

                    // Check if dangerous
                    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                    if dangerous_sgids.iter().any(|&d| filename.contains(d)) {
                        dangerous_found.push(format!(
                            "DANGEROUS: {} (mode: {:o})",
                            path_str,
                            mode & 0o7777
                        ));
                        if finding.severity < Severity::High {
                            finding.severity = Severity::High;
                        }
                    } else {
                        sgid_files.push(format!("{} (mode: {:o})", path_str, mode & 0o7777));
                    }
                }
            }
        }
    }

    if writable_found.is_empty() && dangerous_found.is_empty() && sgid_files.is_empty() {
        finding.details.push("No SGID files found".to_string());
        return Some(finding);
    }

    if !writable_found.is_empty() {
        finding
            .details
            .push("=== WRITABLE SGID FILES ===".to_string());
        finding.details.extend(writable_found);
        finding.details.push("".to_string());
    }

    if !dangerous_found.is_empty() {
        finding
            .details
            .push("=== DANGEROUS SGID FILES ===".to_string());
        finding
            .details
            .extend(dangerous_found.iter().take(20).cloned());
        if dangerous_found.len() > 20 {
            finding
                .details
                .push(format!("... and {} more", dangerous_found.len() - 20));
        }
        finding.details.push("".to_string());
    }

    if !sgid_files.is_empty() {
        finding.details.push("=== OTHER SGID FILES ===".to_string());
        finding.details.extend(sgid_files.iter().take(30).cloned());
        if sgid_files.len() > 30 {
            finding
                .details
                .push(format!("... and {} more", sgid_files.len() - 30));
        }
    }

    Some(finding)
}

use crate::{Category, Finding, Severity};
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

///  Interesting Permissions - SUID Files
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Find and analyze SUID binaries for privilege escalation
///
///  Checks for:
///  - SUID binaries on the system
///  - Owned/writable SUID files
///  - Known vulnerable SUID binaries
///  - Unknown SUID binaries
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
        "SUID Files",
        "SUID binaries that could be exploited",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid");

    // 已知的危险 SUID 二进制文件
    let dangerous_suids = [
        "nmap", "vim", "vi", "nano", "find", "bash", "sh", "more", "less", "man", "awk", "gawk",
        "perl", "python", "ruby", "lua", "php", "tclsh", "wish", "rvim", "rview", "emacs", "git",
        "ftp", "socat", "taskset", "strace", "gdb", "docker", "kubectl",
    ];

    let mut suid_files = Vec::new();
    let mut dangerous_found = Vec::new();
    let mut writable_found = Vec::new();

    // 限制搜索路径和深度
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

                // 检查 SUID 位 (mode & 0o4000)
                if mode & 0o4000 != 0 {
                    let path_str = path.display().to_string();

                    // 检查是否可写
                    if mode & 0o002 != 0 || mode & 0o020 != 0 {
                        writable_found.push(format!("CRITICAL: Writable SUID: {}", path_str));
                        finding.severity = Severity::Critical;
                        continue;
                    }

                    // 检查是否是已知危险二进制
                    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                    if dangerous_suids.iter().any(|&d| filename.contains(d)) {
                        dangerous_found.push(format!(
                            "DANGEROUS: {} (mode: {:o})",
                            path_str,
                            mode & 0o7777
                        ));
                        if finding.severity < Severity::High {
                            finding.severity = Severity::High;
                        }
                    } else {
                        suid_files.push(format!("{} (mode: {:o})", path_str, mode & 0o7777));
                    }
                }
            }
        }
    }

    if writable_found.is_empty() && dangerous_found.is_empty() && suid_files.is_empty() {
        finding.details.push("No SUID files found".to_string());
        return Some(finding);
    }

    if !writable_found.is_empty() {
        finding
            .details
            .push("=== WRITABLE SUID FILES ===".to_string());
        finding.details.extend(writable_found);
        finding.details.push("".to_string());
    }

    if !dangerous_found.is_empty() {
        finding
            .details
            .push("=== DANGEROUS SUID FILES ===".to_string());
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

    if !suid_files.is_empty() {
        finding.details.push("=== OTHER SUID FILES ===".to_string());
        finding.details.extend(suid_files.iter().take(30).cloned());
        if suid_files.len() > 30 {
            finding
                .details
                .push(format!("... and {} more", suid_files.len() - 30));
        }
    }

    Some(finding)
}

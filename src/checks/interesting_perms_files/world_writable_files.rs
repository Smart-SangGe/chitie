use crate::{Category, Finding, Severity};
use std::env;
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

///  Interesting Permissions - World Writable Files
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Find files that are writable by everyone (world-writable)
///
///  Checks for:
///  - Files writable by 'others' (chmod o+w)
///  - Excludes /proc, /sys, /tmp, /var/tmp, /run, /dev and user's home directory
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
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
        Severity::Medium,
        "World Writable Files",
        "Files that are writable by any user on the system",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files");

    let mut writable_files = Vec::new();

    // Directories to exclude
    let home_dir = env::var("HOME").unwrap_or_default();
    let exclude_dirs = vec![
        "/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/lib/docker", "/snap",
    ];

    // Directories to search
    let search_paths = if config.stealth {
        vec!["/etc", "/usr", "/bin", "/sbin", "/opt", "/var"]
    } else {
        vec!["/"]
    };

    let max_depth = if config.stealth { 5 } else { 15 };

    for search_path in search_paths {
        for entry in WalkDir::new(search_path)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            let path_str = path.display().to_string();

            // Skip directories/files in excluded paths
            if exclude_dirs.iter().any(|&d| path_str.starts_with(d)) {
                continue;
            }
            if !home_dir.is_empty() && path_str.starts_with(&home_dir) {
                continue;
            }

            if !path.is_file() {
                continue;
            }

            // Skip symbolic links (they are usually 777, we care about the target which 'find -type f' handles by checking the file itself)
            if entry.path_is_symlink() {
                continue;
            }

            if let Ok(metadata) = entry.metadata() {
                let mode = metadata.permissions().mode();

                // Check world writable bit (mode & 0o002)
                // Also ensure it's not a symlink (WalkDir follows_links(false) handles traversal, but we check metadata of the link itself usually)
                // But metadata() follows links by default unless we use symlink_metadata().
                // However, WalkDir entry.metadata() calls symlink_metadata() if follow_links is false?
                // WalkDir documentation says entry.metadata() is roughly fs::metadata(entry.path()).
                // If we want the link's metadata, we verify.
                // But wait, if it's a symlink, we usually don't care if the LINK is writable (it usually is 777), we care if the target is.
                // But `follow_links(false)` means we don't recurse INTO it.
                // Let's rely on standard logic: check if the FILE is writable.

                if mode & 0o002 != 0 {
                     // Check if it's a critical file (High/Critical)
                    let severity = if path_str.starts_with("/etc/shadow")
                        || path_str.starts_with("/etc/passwd")
                        || path_str.starts_with("/etc/sudoers")
                    {
                        finding.severity = Severity::Critical;
                        "CRITICAL"
                    } else if path_str.starts_with("/etc/") || path_str.starts_with("/usr/bin/") {
                         if finding.severity < Severity::High {
                            finding.severity = Severity::High;
                         }
                         "HIGH"
                    } else {
                        "MEDIUM"
                    };
                    
                    writable_files.push(format!("[{}] {} (mode: {:o})", severity, path_str, mode & 0o777));
                }
            }
        }
    }

    if writable_files.is_empty() {
        finding.details.push("No world writable files found in interesting directories".to_string());
        return Some(finding);
    }

    // Limit output to avoid flooding
    finding.details.push(format!("Found {} world writable files (showing top 50):", writable_files.len()));
    finding.details.extend(writable_files.iter().take(50).cloned());
     if writable_files.len() > 50 {
        finding
            .details
            .push(format!("... and {} more", writable_files.len() - 50));
    }

    Some(finding)
}

use crate::{Category, Finding, Severity};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use walkdir::WalkDir;

///  Interesting Permissions - Critical Root Paths
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Check for write privileges over critical root paths and files
///
///  Checks for:
///  - Writable /etc/profile, /etc/profile.d/, /etc/init.d/, etc.
///  - Files in these directories not owned by root or writable by the current user
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "Critical Root Paths",
        "Check for write privileges over critical root paths and files",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files");

    let mut details = Vec::new();
    let mut high_severity = false;

    let critical_paths = [
        "/etc/profile",
        "/etc/profile.d",
        "/etc/init.d",
        "/etc/update-motd.d",
        "/etc/bash.bashrc",
        "/etc/bash_completion.d",
        "/etc/zsh",
        "/etc/bash",
        "/etc/sudoers.d",
        "/etc/logrotate.d",
        "/etc/systemd/system",
        "/lib/systemd/system",
    ];

    for path_str in critical_paths {
        let path = Path::new(path_str);
        if !path.exists() {
            continue;
        }

        if let Ok(metadata) = fs::metadata(path) {
            if is_writable(&metadata) {
                details.push(format!(
                    "CRITICAL: You have write privileges over {}",
                    path_str
                ));
                high_severity = true;
            }

            if path.is_dir() {
                for entry in WalkDir::new(path)
                    .max_depth(2)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let entry_path = entry.path();
                    if let Ok(m) = entry.metadata() {
                        if is_writable(&m) {
                            details.push(format!(
                                "HIGH: You have write privileges over {}",
                                entry_path.display()
                            ));
                            high_severity = true;
                        }

                        // Check ownership (simplified: check if UID is not 0)
                        // In a real scenario we'd check if it matches current user UID
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            if m.uid() != 0 {
                                details.push(format!(
                                    "WARNING: {} is not owned by root (UID: {})",
                                    entry_path.display(),
                                    m.uid()
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    if high_severity {
        finding.severity = Severity::High;
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

fn is_writable(metadata: &fs::Metadata) -> bool {
    let mode = metadata.permissions().mode();
    // World writable
    if mode & 0o002 != 0 {
        return true;
    }
    // Group writable
    if mode & 0o020 != 0 {
        return true;
    }
    false
}

use crate::{Category, Finding, Severity};
use nix::unistd::getuid;
use std::env;
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

///  Interesting Files - Others Homes
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for files and directory permissions in other users' home directories
///  Corresponds to LinPEAS: 10_Others_homes.sh
pub async fn check() -> Option<Finding> {
    let current_uid = getuid().as_raw();
    let home_dir = env::var("HOME").unwrap_or_else(|_| "/home".to_string());

    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Others Homes",
        "Exploring files and permissions in other users' home directories",
    );

    let mut results = Vec::new();

    // Scan /home directory
    let home_base = "/home";
    if !std::path::Path::new(home_base).exists() {
        return None;
    }

    if let Ok(entries) = std::fs::read_dir(home_base) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let path_str = path.display().to_string();

            // Skip current user's home
            if path_str == home_dir {
                continue;
            }

            if path.is_dir() {
                if let Ok(metadata) = entry.metadata() {
                    let mode = metadata.permissions().mode();
                    let is_readable =
                        nix::unistd::access(&path, nix::unistd::AccessFlags::R_OK).is_ok();
                    let is_writable =
                        nix::unistd::access(&path, nix::unistd::AccessFlags::W_OK).is_ok();

                    if is_writable {
                        results.push(format!(
                            "[!] WRITABLE: {} (mode: {:o})",
                            path_str,
                            mode & 0o777
                        ));
                        finding.severity = Severity::High;
                    } else if is_readable {
                        results.push(format!(
                            "[!] READABLE: {} (mode: {:o})",
                            path_str,
                            mode & 0o777
                        ));
                        if finding.severity < Severity::Medium {
                            finding.severity = Severity::Medium;
                        }
                    }

                    // If readable, list some files inside (to match LinPEAS limit 20)
                    if is_readable {
                        for sub_entry in WalkDir::new(&path)
                            .max_depth(2)
                            .follow_links(false)
                            .into_iter()
                            .filter_map(|e| e.ok())
                            .take(5)
                        // Limit sub-files per home to keep output clean
                        {
                            if sub_entry.path().is_file() {
                                results.push(format!("    - {}", sub_entry.path().display()));
                            }
                        }
                    }
                }
            }
        }
    }

    if results.is_empty() {
        return None;
    }

    finding.details = results;
    Some(finding)
}

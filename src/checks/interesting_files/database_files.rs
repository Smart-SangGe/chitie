use crate::{Category, Finding, Severity};
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

///  Interesting Files - Database Files
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for readable .db/.sql/.sqlite files
///  Corresponds to LinPEAS: 15_Db_files.sh
pub async fn check() -> Option<Finding> {
    let config = crate::config::config();

    let mut finding = Finding::new(
        Category::File,
        Severity::Medium,
        "Database Files",
        "Readable database files that might contain sensitive information",
    );

    let mut results = Vec::new();
    let exclude_dirs = vec![
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/var/tmp",
        "/var/lib/docker",
        "/snap",
    ];

    let search_paths = if config.stealth {
        vec!["/var/www", "/opt", "/home"]
    } else {
        vec!["/"]
    };

    let max_depth = if config.stealth { 5 } else { 12 };

    for search_path in search_paths {
        for entry in WalkDir::new(search_path)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            let path_str = path.display().to_string();

            if exclude_dirs.iter().any(|&d| path_str.starts_with(d)) {
                continue;
            }

            if path.is_file() {
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext == "db" || ext == "sql" || ext == "sqlite" || ext == "sqlite3" {
                    if let Ok(metadata) = entry.metadata() {
                        let mode = metadata.permissions().mode();
                        // If readable by current user
                        let is_readable =
                            nix::unistd::access(path, nix::unistd::AccessFlags::R_OK).is_ok();

                        if is_readable {
                            results.push(format!(
                                "READABLE: {} (mode: {:o})",
                                path_str,
                                mode & 0o777
                            ));
                            finding.severity = Severity::High;
                        } else {
                            results.push(format!("FOUND: {} (mode: {:o})", path_str, mode & 0o777));
                        }
                    }
                }
            }

            if results.len() >= 100 {
                break;
            }
        }
        if results.len() >= 100 {
            break;
        }
    }

    if results.is_empty() {
        return None;
    }

    finding.details = results;
    Some(finding)
}

use crate::{Category, Finding, Severity};
use nix::unistd::getuid;
use std::fs;
use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

///  Interesting Permissions - Others files in my dirs
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching folders owned by me containing others files on it
///  Corresponds to LinPEAS: 12_Others_files_in_my_dirs.sh
pub async fn check() -> Option<Finding> {
    let current_uid = getuid().as_raw();
    if current_uid == 0 {
        return None;
    }

    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "Others files in my dirs",
        "Folders owned by me containing files owned by others (limit 100)",
    );

    let mut results = Vec::new();
    let mut dir_count = 0;

    // We only search in some common areas to avoid full disk scan if possible, 
    // but LinPEAS uses $ROOT_FOLDER. Let's use / as well but with some limits.
    // For performance, we'll avoid /proc, /sys etc.
    let exclude_dirs = vec!["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/lib/docker"];

    for entry in WalkDir::new("/")
        .max_depth(10)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let path_str = path.display().to_string();

        if exclude_dirs.iter().any(|&d| path_str.starts_with(d)) {
            continue;
        }

        if path.is_dir() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.uid() == current_uid {
                    // This directory is owned by me, now check its children
                    if let Ok(entries) = fs::read_dir(path) {
                        let mut others_files = Vec::new();
                        for child_entry in entries.filter_map(|e| e.ok()) {
                            if let Ok(child_metadata) = child_entry.metadata() {
                                if child_metadata.uid() != current_uid {
                                    others_files.push(format!(
                                        "{} (owner: {})", 
                                        child_entry.file_name().to_string_lossy(),
                                        child_metadata.uid()
                                    ));
                                }
                            }
                            if others_files.len() >= 5 { break; } // Limit child display
                        }

                        if !others_files.is_empty() {
                            results.push(format!("Folder: {}", path_str));
                            for file in others_files {
                                results.push(format!("  |_ {}", file));
                            }
                            dir_count += 1;
                        }
                    }
                }
            }
        }

        if dir_count >= 100 {
            break;
        }
    }

    if results.is_empty() {
        return None;
    }

    finding.details = results;
    Some(finding)
}

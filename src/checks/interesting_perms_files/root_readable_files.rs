use crate::{Category, Finding, Severity};
use nix::unistd::{access, getuid, AccessFlags};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use walkdir::WalkDir;

///  Interesting Permissions - Root readable files not world readable
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Readable files belonging to root and readable by me but not world readable
///  Corresponds to LinPEAS: 13_Root_readable_files_notworld_readeble.sh
pub async fn check() -> Option<Finding> {
    let current_uid = getuid().as_raw();
    if current_uid == 0 {
        return None;
    }

    let mut finding = Finding::new(
        Category::Permission,
        Severity::Medium,
        "Root-owned files readable by me (non-world-readable)",
        "Readable files belonging to root and readable by me but not world readable",
    );

    let mut results = Vec::new();
    let exclude_dirs = vec!["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"];

    for entry in WalkDir::new("/")
        .max_depth(12)
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
            if let Ok(metadata) = entry.metadata() {
                // Owned by root AND not world-readable
                if metadata.uid() == 0 && (metadata.permissions().mode() & 0o004 == 0) {
                    // Check if actually readable by current user
                    if access(path, AccessFlags::R_OK).is_ok() {
                        results.push(format!(
                            "{} (mode: {:o}, uid: {}, gid: {})",
                            path_str,
                            metadata.permissions().mode() & 0o777,
                            metadata.uid(),
                            metadata.gid()
                        ));
                    }
                }
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

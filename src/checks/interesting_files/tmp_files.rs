use crate::{Category, Finding, Severity};
use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

///  Interesting Files - Readable files in /tmp, /var/tmp, etc.
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for readable files in /tmp and backup locations
///  Corresponds to LinPEAS: 19_Readable_files_tmp_backups.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Readable files in /tmp and backups",
        "Files in /tmp, /var/tmp and other temporary or backup locations that are readable",
    );

    let mut results = Vec::new();
    let tmp_dirs = vec![
        "/tmp", "/var/tmp", "/dev/shm", "/var/backups", "/var/spool/cron", "/var/spool/anacron"
    ];

    for dir in tmp_dirs {
        if !std::path::Path::new(dir).exists() {
            continue;
        }

        for entry in WalkDir::new(dir)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = entry.metadata() {
                    let is_readable = nix::unistd::access(path, nix::unistd::AccessFlags::R_OK).is_ok();
                    
                    if is_readable {
                        let uid = metadata.uid();
                        let path_str = path.display().to_string();
                        
                        // Exclude common noise
                        if path_str.contains("dpkg.statoverride") || path_str.contains("dpkg.status") {
                            continue;
                        }

                        if uid == 0 { // Owned by root
                            results.push(format!("[!] ROOT-OWNED & READABLE: {}", path_str));
                            if finding.severity < Severity::Medium {
                                finding.severity = Severity::Medium;
                            }
                        } else {
                            results.push(format!("Readable: {}", path_str));
                        }
                    }
                }
            }
            if results.len() >= 70 { break; }
        }
        if results.len() >= 70 { break; }
    }

    if results.is_empty() {
        return None;
    }

    finding.details = results;
    Some(finding)
}

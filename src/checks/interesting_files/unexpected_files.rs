use crate::{Category, Finding, Severity};
use regex::Regex;
use std::fs;
use std::os::unix::fs::MetadataExt;

///  Interesting Files - Unexpected Files in /opt and /
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Unexpected files in /opt (usually empty) and unexpected folders in root
///  Corresponds to LinPEAS: 5_Unexpected_in_opt.sh and 6_Unexpected_in_root.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Unexpected Files in /opt and /",
        "Non-standard files and directories in /opt and the root directory",
    );

    let mut details = Vec::new();

    // 1. Check /opt
    if let Ok(entries) = fs::read_dir("/opt") {
        let mut opt_files = Vec::new();
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Ok(metadata) = entry.metadata() {
                opt_files.push(format!(
                    "  {} (mode: {:o}, owner: {})",
                    path.display(),
                    metadata.mode() & 0o777,
                    metadata.uid()
                ));
            }
        }
        if !opt_files.is_empty() {
            details.push("=== Unexpected in /opt (usually empty) ===".to_string());
            details.extend(opt_files);
        }
    }

    // 2. Check /root (Unexpected folders in root /)
    // Common root directories regex
    let common_root_re = Regex::new(r"(?i)^/$|/bin$|/boot$|/.cache$|/cdrom|/dev$|/etc$|/home$|/lost\+found$|/lib$|/lib32$|libx32$|/lib64$|/media$|/mnt$|/opt$|/proc$|/root$|/run$|/sbin$|/snap$|/srv$|/sys$|/tmp$|/usr$|/var$").unwrap();

    if let Ok(entries) = fs::read_dir("/") {
        let mut unexpected_root = Vec::new();
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let path_str = path.display().to_string();

            if !common_root_re.is_match(&path_str) {
                if let Ok(metadata) = entry.metadata() {
                    unexpected_root.push(format!(
                        "  {} (mode: {:o}, owner: {})",
                        path_str,
                        metadata.mode() & 0o777,
                        metadata.uid()
                    ));
                    if finding.severity < Severity::Medium {
                        finding.severity = Severity::Medium;
                    }
                }
            }
        }
        if !unexpected_root.is_empty() {
            details.push("=== Unexpected in root / ===".to_string());
            details.extend(unexpected_root);
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

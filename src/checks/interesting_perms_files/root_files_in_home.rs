use crate::{Category, Finding, Severity};
use nix::unistd::getuid;
use std::env;
use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

///  Interesting Permissions - Root files in home dirs
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching root files in home dirs
///  Corresponds to LinPEAS: 11_Root_files_home_dir.sh
pub async fn check() -> Option<Finding> {
    // LinPEAS logic: searching root files in home dirs
    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "Root files in home dirs",
        "Searching root files in home dirs (limit 30)",
    );

    let current_uid = getuid().as_raw();
    if current_uid == 0 {
        return None; // If we are root, this check is less relevant
    }

    let home_search_path = env::var("HOME").unwrap_or_else(|_| "/home".to_string());
    let mut results = Vec::new();

    // LinPEAS: find $HOMESEARCH -user root 2>/dev/null | head -n 30
    for entry in WalkDir::new(&home_search_path)
        .max_depth(10)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        if let Ok(metadata) = entry.metadata() {
            if metadata.uid() == 0 {
                // Owned by root
                results.push(path.display().to_string());
            }
        }

        if results.len() >= 30 {
            break;
        }
    }

    if results.is_empty() {
        return None;
    }

    finding.details = results;
    Some(finding)
}

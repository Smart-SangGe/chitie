use crate::{Category, Finding, Severity};
use walkdir::WalkDir;

///  Interesting Files - Mail Files
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for mail files in common locations
///  Corresponds to LinPEAS: 12_Mails.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Mail Files",
        "Local mail files that might contain sensitive communications",
    );

    let mut results = Vec::new();
    let mail_dirs = vec!["/var/mail", "/var/spool/mail"];

    for dir in mail_dirs {
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
                    let path_str = path.display().to_string();
                    
                    if is_readable {
                        results.push(format!("READABLE: {}", path_str));
                        finding.severity = Severity::Medium;
                    } else {
                        results.push(format!("FOUND: {}", path_str));
                    }
                }
            }
            if results.len() >= 50 { break; }
        }
    }

    if results.is_empty() {
        return None;
    }

    finding.details = results;
    Some(finding)
}

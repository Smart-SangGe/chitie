use crate::{Category, Finding, Severity};
use walkdir::WalkDir;

///  Interesting Files - Backup Files
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Find backup files (*.bak, *.old, *.backup, etc.)
///
///  Checks for:
///  - Files with backup extensions in interesting directories
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#backup-files
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes (limited path)
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let config = crate::config::config();

    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Backup Files",
        "Backup files might contain source code, credentials or configuration",
    );

    // Extensions to search for
    let extensions = [
        ".bak", ".old", ".backup", ".bck", ".bk", ".save", ".swp", ".copy", ".orig", "~",
    ];

    // Directories to search
    let search_paths = if config.stealth {
        vec!["/etc", "/var/www", "/home", "/opt", "/tmp"]
    } else {
        vec!["/etc", "/var", "/home", "/opt", "/usr/local", "/tmp", "/root"]
    };

    let mut backup_files = Vec::new();

    for search_path in search_paths {
        if !std::path::Path::new(search_path).exists() {
            continue;
        }

        for entry in WalkDir::new(search_path)
            .max_depth(10)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let path_str = path.to_string_lossy();
            let name_lower = path.file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            // Check if file name matches backup patterns
            let mut is_backup = false;
            
            // Check extensions (ends with)
            if extensions.iter().any(|ext| name_lower.ends_with(ext)) {
                is_backup = true;
            }
            
            // Check contains "backup"
            if name_lower.contains("backup") {
                is_backup = true;
            }

            if is_backup {
                // Filter out some noise
                if path_str.contains("/.git/") || path_str.contains("/node_modules/") || path_str.contains("/.cargo/") {
                    continue;
                }

                backup_files.push(path_str.to_string());
            }
        }
    }

    if backup_files.is_empty() {
        return None;
    }

    // Limit output
    finding.details.push(format!("Found {} potential backup files (showing top 50):", backup_files.len()));
    finding.details.extend(backup_files.iter().take(50).cloned());
    
    if backup_files.len() > 50 {
        finding.details.push(format!("... and {} more", backup_files.len() - 50));
    }

    Some(finding)
}

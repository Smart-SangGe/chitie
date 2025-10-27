use crate::{Category, Finding, Severity};
use std::fs;
use std::time::{Duration, SystemTime};
use walkdir::WalkDir;

///  Interesting Files - Modified Last 5 Minutes
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Find files modified in the last 5 minutes
///
///  Checks for:
///  - Recently modified files in key directories
///  - Potential ongoing attacks or changes
///
///  References:
///  - Based on LinPEAS IF_Modified_last_5mins
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Medium,
        "Recently Modified Files",
        "Files modified in the last 5 minutes",
    );

    let mut modified_files = Vec::new();
    let five_mins_ago = SystemTime::now() - Duration::from_secs(5 * 60);

    // 搜索关键目录
    let search_paths = vec!["/etc", "/usr", "/opt", "/home", "/tmp", "/var/tmp", "/root"];

    for search_path in search_paths {
        for entry in WalkDir::new(search_path)
            .max_depth(5)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // 排除特殊目录
            let path_str = path.display().to_string();
            if path_str.starts_with("/proc/")
                || path_str.starts_with("/sys/")
                || path_str.starts_with("/run/")
                || path_str.starts_with("/dev/")
                || path_str.starts_with("/var/lib/")
                || path_str.contains("/linpeas")
                || path_str.contains("/chitie")
            {
                continue;
            }

            if !path.is_file() {
                continue;
            }

            // 检查修改时间
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    if modified > five_mins_ago {
                        // 标记可写目录中的文件为高危
                        if path_str.contains("/tmp/")
                            || path_str.contains("/var/tmp/")
                            || path_str.contains("/.ssh/")
                            || path_str.contains("/etc/")
                        {
                            finding.severity = Severity::High;
                            modified_files.push(format!("CRITICAL: {}", path_str));
                        } else {
                            modified_files.push(path_str);
                        }
                    }
                }
            }
        }
    }

    if modified_files.is_empty() {
        return None;
    }

    finding.details = modified_files.iter().take(100).cloned().collect();

    if modified_files.len() > 100 {
        finding
            .details
            .push(format!("... and {} more", modified_files.len() - 100));
    }

    Some(finding)
}

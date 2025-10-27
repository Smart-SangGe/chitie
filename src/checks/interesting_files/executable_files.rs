use crate::{Category, Finding, Severity};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::SystemTime;
use walkdir::WalkDir;

///  Interesting Files - Executable Files by User
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Find recently modified executable files
///
///  Checks for:
///  - Executable files sorted by modification time
///  - Potentially user-added executables
///
///  References:
///  - Based on LinPEAS IF_Executable_files_by_user
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Executable Files",
        "Recently modified executable files",
    );

    let mut executables = Vec::new();

    // 搜索路径（排除常见系统目录）
    let search_paths = vec!["/usr", "/opt", "/home", "/tmp", "/var", "/etc"];

    for search_path in search_paths {
        for entry in WalkDir::new(search_path)
            .max_depth(5)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // 检查是否可执行
            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.permissions().mode();

                if mode & 0o111 != 0 {
                    // 可执行位被设置
                    let path_str = path.display().to_string();

                    // 过滤掉常见的系统路径
                    if path_str.contains("/site-packages/")
                        || path_str.contains("/python")
                        || path_str.contains("/node_modules/")
                        || path_str.contains(".sample")
                        || path_str.contains("/gems/")
                        || path_str.contains("/cgroup/")
                    {
                        continue;
                    }

                    // 获取修改时间
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH) {
                            executables.push((duration.as_secs(), path_str));
                        }
                    }
                }
            }
        }
    }

    if executables.is_empty() {
        return None;
    }

    // 按修改时间倒序排序
    executables.sort_by(|a, b| b.0.cmp(&a.0));

    // 转换为可读的输出
    finding.details = executables
        .iter()
        .take(70)
        .map(|(timestamp, path)| {
            let datetime = chrono::DateTime::from_timestamp(*timestamp as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| timestamp.to_string());
            format!("{} {}", datetime, path)
        })
        .collect();

    if executables.len() > 70 {
        finding
            .details
            .push(format!("... and {} more", executables.len() - 70));
    }

    Some(finding)
}

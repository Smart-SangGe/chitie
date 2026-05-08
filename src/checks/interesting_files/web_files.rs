use crate::{Category, Finding, Severity};
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

///  Interesting Files - Web Files
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for web files in common locations
///  Corresponds to LinPEAS: 17_Web_files.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Web Files",
        "Interesting web-related files and directories",
    );

    let mut results = Vec::new();
    let web_dirs = vec![
        "/var/www",
        "/srv/www/htdocs",
        "/usr/local/www/apache22/data",
        "/opt/lampp/htdocs",
        "/var/www/html",
    ];

    let mut found_any_dir = false;

    for dir in web_dirs {
        if !std::path::Path::new(dir).exists() {
            continue;
        }
        found_any_dir = true;
        results.push(format!("Listing {}:", dir));

        // Use a small depth to match LinPEAS's limited output
        for entry in WalkDir::new(dir)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            let path_str = path.display().to_string();

            if let Ok(metadata) = entry.metadata() {
                let mode = metadata.permissions().mode();

                // Identify interesting web files (config, .env, etc.)
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let is_interesting = name.contains("config")
                    || name.starts_with(".env")
                    || name.starts_with(".ht")
                    || name.contains("secret")
                    || name.contains("pwd");

                if is_interesting {
                    results.push(format!(
                        "  [!] INTERESTING: {} (mode: {:o})",
                        path_str,
                        mode & 0o777
                    ));
                    if finding.severity < Severity::Medium {
                        finding.severity = Severity::Medium;
                    }
                } else if results.len() < 100 {
                    // Regular listing limited
                    results.push(format!("  {} (mode: {:o})", path_str, mode & 0o777));
                }
            }
            if results.len() >= 150 {
                break;
            }
        }
    }

    if !found_any_dir {
        return None;
    }

    finding.details = results;
    Some(finding)
}

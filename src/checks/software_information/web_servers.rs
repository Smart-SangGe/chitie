use crate::utils::command::Command;
use crate::{Category, Finding, Severity};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

///  Software Information - Apache and Nginx Audit
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Auditing Apache and Nginx configurations, permissions, and sensitive info
///  Corresponds to LinPEAS: SI_Apache_nginx
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Software,
        Severity::Info,
        "Apache & Nginx Audit",
        "Auditing Web server configurations, document roots, and permissions",
    );

    let mut details = Vec::new();

    // 1. Process & Version check
    let processes = vec!["apache2", "httpd", "nginx"];
    for proc in processes {
        if let Ok(output) = Command::new("ps").arg("aux").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains(proc) && !stdout.contains("grep") {
                details.push(format!("Active Web server process found: {}", proc));

                // Try version
                if let Ok(ver_out) = Command::new(proc).arg("-v").output() {
                    let v = String::from_utf8_lossy(&ver_out.stdout);
                    let v_err = String::from_utf8_lossy(&ver_out.stderr);
                    let full_v = if v.is_empty() { v_err } else { v };
                    details.push(format!(
                        "  Version: {}",
                        full_v.lines().next().unwrap_or("unknown")
                    ));
                }
            }
        }
    }

    // 2. Config Audit
    let config_paths = vec![
        "/etc/apache2",
        "/etc/httpd",
        "/etc/nginx",
        "/usr/local/apache2/conf",
        "/etc/apache2/sites-enabled",
        "/etc/nginx/sites-enabled",
    ];

    for base_dir in config_paths {
        if !Path::new(base_dir).exists() {
            continue;
        }

        details.push(format!("=== Auditing {} ===", base_dir));

        for entry in WalkDir::new(base_dir)
            .max_depth(4)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let path_str = path.display().to_string();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Check if readable
            let is_readable = nix::unistd::access(path, nix::unistd::AccessFlags::R_OK).is_ok();
            let is_writable = nix::unistd::access(path, nix::unistd::AccessFlags::W_OK).is_ok();

            if is_writable {
                details.push(format!("[!] CRITICAL: Writable config file: {}", path_str));
                finding.severity = Severity::Critical;
            }

            if is_readable {
                if let Ok(content) = fs::read_to_string(path) {
                    // Check for credentials
                    for (line_num, line) in content.lines().enumerate() {
                        let l = line.to_lowercase();
                        if (l.contains("pass")
                            || l.contains("secret")
                            || l.contains("key")
                            || l.contains("token"))
                            && !l.contains("#")
                        {
                            details.push(format!(
                                "  [!] SENSITIVE in {}:{}: {}",
                                path_str,
                                line_num + 1,
                                line.trim()
                            ));
                            if finding.severity < Severity::High {
                                finding.severity = Severity::High;
                            }
                        }

                        // Check for DocumentRoot or root (Nginx)
                        if l.contains("documentroot")
                            || (name.contains("nginx") && l.trim().starts_with("root"))
                        {
                            let root_path = line
                                .split_whitespace()
                                .last()
                                .unwrap_or("")
                                .trim_matches(';');
                            if !root_path.is_empty() && Path::new(root_path).exists() {
                                if nix::unistd::access(root_path, nix::unistd::AccessFlags::W_OK)
                                    .is_ok()
                                {
                                    details.push(format!(
                                        "  [!] HIGH: Writable DocumentRoot: {}",
                                        root_path
                                    ));
                                    if finding.severity < Severity::High {
                                        finding.severity = Severity::High;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

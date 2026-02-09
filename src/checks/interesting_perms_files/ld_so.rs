use crate::{Category, Finding, Severity};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

///  Interesting Permissions - Misconfigured ld.so
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Checking misconfigurations of ld.so (conf and preload)
///
///  Checks for:
///  - Write permissions over /etc/ld.so.conf
///  - Write permissions over included files in /etc/ld.so.conf
///  - Write permissions over directories and files mentioned in ld.so.conf
///  - Write permissions over /etc/ld.so.preload and its contents
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "Misconfigured ld.so",
        "Misconfigurations in ld.so could lead to privilege escalation",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso");

    let mut details = Vec::new();
    let mut high_severity = false;

    // 1. Check /etc/ld.so.conf
    let ld_so_conf = "/etc/ld.so.conf";
    if let Ok(metadata) = fs::metadata(ld_so_conf) {
        if is_writable(&metadata) {
            details.push(format!("CRITICAL: You have write privileges over {}", ld_so_conf));
            high_severity = true;
        }

        if let Ok(content) = fs::read_to_string(ld_so_conf) {
            process_ld_so_content(&content, &mut details, &mut high_severity);
        }
    }

    // 2. Check /etc/ld.so.preload
    let ld_so_preload = "/etc/ld.so.preload";
    if let Ok(metadata) = fs::metadata(ld_so_preload) {
        if is_writable(&metadata) {
            details.push(format!("CRITICAL: You have write privileges over {}", ld_so_preload));
            high_severity = true;
        }

        if let Ok(content) = fs::read_to_string(ld_so_preload) {
            for line in content.lines() {
                let path = line.trim();
                if path.is_empty() || path.starts_with('#') {
                    continue;
                }
                check_path_writable(path, &mut details, &mut high_severity);
            }
        }
    }

    if high_severity {
        finding.severity = Severity::High;
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

fn process_ld_so_content(content: &str, details: &mut Vec<String>, high_severity: &mut bool) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("include ") {
            let pattern = &line[8..].trim();
            handle_include(pattern, details, high_severity);
        } else {
            // It's a directory path
            check_path_writable(line, details, high_severity);
        }
    }
}

fn handle_include(pattern: &str, details: &mut Vec<String>, high_severity: &mut bool) {
    // Simple handling for /path/*.conf or /path/file
    if let Some(star_idx) = pattern.find('*') {
        let dir_part = &pattern[..star_idx];
        let dir_path = Path::new(dir_part);
        
        let parent = if dir_path.is_dir() {
            dir_path
        } else {
            dir_path.parent().unwrap_or(Path::new("/"))
        };

        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                let path_str = path.to_str().unwrap_or("");
                // Very simple suffix matching for *.conf
                if pattern.ends_with(".conf") && path_str.ends_with(".conf") {
                    check_path_writable(path_str, details, high_severity);
                    if let Ok(content) = fs::read_to_string(&path) {
                        process_ld_so_content(&content, details, high_severity);
                    }
                }
            }
        }
    } else {
        check_path_writable(pattern, details, high_severity);
        if let Ok(content) = fs::read_to_string(pattern) {
            process_ld_so_content(&content, details, high_severity);
        }
    }
}

fn check_path_writable(path_str: &str, details: &mut Vec<String>, high_severity: &mut bool) {
    let path = Path::new(path_str);
    if let Ok(metadata) = fs::metadata(path) {
        if is_writable(&metadata) {
            details.push(format!("HIGH: You have write privileges over {}", path_str));
            *high_severity = true;
        }
    }
}

fn is_writable(metadata: &fs::Metadata) -> bool {
    let mode = metadata.permissions().mode();
    // World writable
    if mode & 0o002 != 0 {
        return true;
    }
    // Group writable
    if mode & 0o020 != 0 {
        return true;
    }
    false
}


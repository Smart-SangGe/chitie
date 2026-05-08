use crate::{Category, Finding, Severity};
use regex::Regex;
use std::fs;
use std::os::unix::fs::MetadataExt;

///  Processes & Services - Processes with credentials inside memory or files
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for processes that might have credentials in memory or open sensitive files
///  Corresponds to LinPEAS: 2_Process_cred_in_memory.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Process,
        Severity::Info,
        "Processes Credential Audit",
        "Auditing processes for open credential files and memory mappings",
    );

    let mut details = Vec::new();

    // 1. Common credential-storing processes
    let cred_procs = vec![
        "gdm-password",
        "gnome-keyring",
        "lightdm",
        "vsftpd",
        "sshd",
        "mysql",
        "postgres",
        "redis",
        "mongod",
        "memcached",
        "jenkins",
        "tomcat",
        "nginx",
        "php-fpm",
    ];

    let mut found_procs = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.filter_map(|e| e.ok()) {
            let name_os = entry.file_name();
            let name = name_os.to_string_lossy();

            if name.chars().all(|c| c.is_ascii_digit()) {
                let pid = name.to_string();
                let cmdline_path = entry.path().join("cmdline");
                if let Ok(cmdline) = fs::read_to_string(cmdline_path) {
                    let cmd = cmdline.replace('\0', " ");
                    for cp in &cred_procs {
                        if cmd.contains(cp) {
                            found_procs.push(format!(
                                "  [!] PID {}: {} (potential creds in memory)",
                                pid, cp
                            ));
                            break;
                        }
                    }
                }

                // 2. Check open FDs for sensitive files
                let fd_dir = entry.path().join("fd");
                if let Ok(fds) = fs::read_dir(&fd_dir) {
                    let mut sensitive_fds = Vec::new();
                    for fd in fds.filter_map(|e| e.ok()) {
                        if let Ok(target) = fs::read_link(fd.path()) {
                            let target_str = target.to_string_lossy();
                            if is_sensitive_path(&target_str) {
                                sensitive_fds.push(target_str.to_string());
                            }
                        }
                    }
                    if !sensitive_fds.is_empty() {
                        let uid = entry.metadata().map(|m| m.uid()).unwrap_or(999);
                        details.push(format!(
                            "Process PID {} (UID: {}) has open sensitive files:",
                            pid, uid
                        ));
                        for f in sensitive_fds {
                            details.push(format!("  └─ {}", f));
                        }
                        if finding.severity < Severity::High {
                            finding.severity = Severity::High;
                        }
                    }
                }

                // 3. Check memory maps
                let maps_path = entry.path().join("maps");
                if let Ok(content) = fs::read_to_string(maps_path) {
                    let mut sensitive_maps = Vec::new();
                    for line in content.lines() {
                        if let Some(path_idx) = line.find('/') {
                            let path = &line[path_idx..];
                            if is_sensitive_path(path) {
                                sensitive_maps.push(path.to_string());
                            }
                        }
                    }
                    sensitive_maps.sort();
                    sensitive_maps.dedup();
                    if !sensitive_maps.is_empty() {
                        details.push(format!(
                            "Process PID {} has sensitive memory-mapped files:",
                            pid
                        ));
                        for m in sensitive_maps {
                            details.push(format!("  └─ {}", m));
                        }
                    }
                }
            }
        }
    }

    if !found_procs.is_empty() {
        details.push("\n=== Potential Credential-Storing Processes ===".to_string());
        details.extend(found_procs);
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

fn is_sensitive_path(path: &str) -> bool {
    let re = Regex::new(
        r"(?i)\.(pem|key|cred|db|sqlite|conf|cnf|ini|env|secret|token|auth|passwd|shadow)$",
    )
    .unwrap();
    re.is_match(path)
        || path.contains("/.ssh/")
        || path.contains("/etc/shadow")
        || path.contains("/etc/passwd")
}

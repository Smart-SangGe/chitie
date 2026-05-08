use crate::{Category, Finding, Severity};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

///  Interesting Files - Writable log files
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Writable log files (logrotten) and syslog/auditd configuration
///  Corresponds to LinPEAS: 8_Writable_log_files.sh
pub async fn check() -> Option<Finding> {
    let _config = crate::config::config();

    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Log Files and Configuration",
        "Writable log files, logrotate version, and syslog/auditd configuration",
    );

    let mut details = Vec::new();

    // 1. Check logrotate version
    let mut is_vuln_logrotate = false;
    if let Ok(output) = Command::new("logrotate").arg("--version").output() {
        let version_str = String::from_utf8_lossy(&output.stdout);
        let version_err = String::from_utf8_lossy(&output.stderr);
        let full_version = if version_str.is_empty() {
            version_err
        } else {
            version_str
        };

        details.push(format!(
            "logrotate version: {}",
            full_version.lines().next().unwrap_or("unknown")
        ));

        // Check for vulnerable versions: 3.18.0 and below
        if full_version.contains(" 1.")
            || full_version.contains(" 2.")
            || full_version.contains(" 3.0")
            || full_version.contains(" 3.1")
        {
            if !full_version.contains(" 3.18.1") && !full_version.contains(" 3.19") {
                is_vuln_logrotate = true;
                details.push(
                    "[!] logrotate version might be vulnerable to logrotten (CVE-2019-11599)"
                        .to_string(),
                );
            }
        }
    }

    // 2. Writable log files
    let mut writable_logs = Vec::new();
    for entry in WalkDir::new("/var/log")
        .max_depth(5)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if (name.contains(".log") || name.contains(".log.")) && path.is_file() {
            if nix::unistd::access(path, nix::unistd::AccessFlags::W_OK).is_ok() {
                writable_logs.push(path.display().to_string());
            }
        }
        if writable_logs.len() >= 50 {
            break;
        }
    }

    if !writable_logs.is_empty() {
        details.push("=== Writable Log Files ===".to_string());
        for log in &writable_logs {
            if is_vuln_logrotate {
                details.push(format!(
                    "[!] CRITICAL: Writable log (vuln logrotate): {}",
                    log
                ));
                finding.severity = Severity::Critical;
            } else {
                details.push(format!("Writable: {}", log));
                if finding.severity < Severity::High {
                    finding.severity = Severity::High;
                }
            }
        }
    }

    // 3. Syslog configuration
    for conf in &["/etc/rsyslog.conf", "/etc/syslog.conf"] {
        if Path::new(conf).exists() {
            details.push(format!("=== {} ===", conf));
            if let Ok(content) = fs::read_to_string(conf) {
                for line in content.lines().take(20) {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        details.push(format!("  {}", trimmed));
                    }
                }
            }
        }
    }

    // 4. Auditd configuration
    let audit_conf = "/etc/audit/auditd.conf";
    if Path::new(audit_conf).exists() {
        details.push("=== auditd.conf ===".to_string());
        if let Ok(content) = fs::read_to_string(audit_conf) {
            for line in content.lines().take(20) {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    details.push(format!("  {}", trimmed));
                }
            }
        }
    }

    // 5. Weak perms in /var/log
    let mut weak_logs = Vec::new();
    for entry in WalkDir::new("/var/log")
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if let Ok(metadata) = entry.metadata() {
            let uid = metadata.uid();
            if uid != 0 && entry.path().is_file() {
                weak_logs.push(format!("{} (UID: {})", entry.path().display(), uid));
            }
        }
        if weak_logs.len() >= 20 {
            break;
        }
    }

    if !weak_logs.is_empty() {
        details.push("=== Logs with non-root ownership ===".to_string());
        details.extend(weak_logs);
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

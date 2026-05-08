use crate::{Category, Finding, Severity};
use std::fs;

///  Processes - Cron Jobs
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Enumerate cron jobs and check for privilege escalation vectors
///
///  Checks for:
///  - System crontab files
///  - User crontab files
///  - Writable cron files/directories
///  - Cron jobs with wildcards or path hijacking risks
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs
///  - Based on LinPEAS PR_Cron_jobs
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Process,
        Severity::Info,
        "Cron Jobs",
        "Scheduled tasks and cron jobs",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs",
    );

    let mut details = Vec::new();

    // 检查系统crontab文件
    let cron_files = vec!["/etc/crontab", "/etc/anacrontab"];

    for file in &cron_files {
        if let Ok(content) = fs::read_to_string(file) {
            details.push(format!("=== {} ===", file));
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    // 检查是否包含通配符
                    if trimmed.contains('*') && !trimmed.starts_with('*') {
                        details.push(format!("WILDCARD: {}", trimmed));
                        finding.severity = Severity::Medium;
                    } else {
                        details.push(format!("  {}", trimmed));
                    }
                }
            }
            details.push(String::new());
        }
    }

    // 检查cron目录
    let cron_dirs = vec![
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
    ];

    details.push("=== CRON DIRECTORIES ===".to_string());
    for dir in &cron_dirs {
        if let Ok(metadata) = fs::metadata(dir) {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();

            // 检查是否可写
            if mode & 0o022 != 0 {
                details.push(format!("WRITABLE: {} (mode: {:o})", dir, mode & 0o7777));
                finding.severity = Severity::High;
            } else if let Ok(entries) = fs::read_dir(dir) {
                let count = entries.count();
                if count > 0 {
                    details.push(format!("{}: {} files", dir, count));
                }
            }
        }
    }

    if details.is_empty() {
        details.push("No cron jobs found".to_string());
    }

    finding.details = details;
    Some(finding)
}

use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;

///  Users Information - Sudo Permissions
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Check sudo -l and sudoers files
///
///  Checks for:
///  - sudo -l permissions
///  - /etc/sudoers configuration
///  - /etc/sudoers.d/* files
///  - Dangerous sudo configurations (NOPASSWD, ALL, etc.)
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "Sudo Permissions",
        "Sudo configuration and permissions",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid");

    let mut has_content = false;

    // 尝试 sudo -l
    if let Ok(output) = Command::new("sudo").args(["-n", "-l"]).output()
        && output.status.success()
    {
        let sudo_output = String::from_utf8_lossy(&output.stdout);
        if !sudo_output.is_empty() && !sudo_output.contains("may not run sudo") {
            finding.details.push("sudo -l output:".to_string());
            for line in sudo_output.lines().take(20) {
                finding.details.push(format!("  {}", line));

                // 检查危险配置
                if line.contains("NOPASSWD") || line.contains("(ALL)") {
                    finding.severity = Severity::High;
                }
            }
            has_content = true;
        }
    }

    // 读取 /etc/sudoers
    if let Ok(sudoers) = fs::read_to_string("/etc/sudoers") {
        finding.details.push("".to_string());
        finding.details.push("/etc/sudoers:".to_string());

        for line in sudoers.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            finding.details.push(format!("  {}", line));

            // 检查危险配置
            if line.contains("NOPASSWD") || line.contains("pwfeedback") {
                finding.severity = Severity::High;
            }
        }
        has_content = true;
    }

    // 检查 /etc/sudoers.d/
    if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
        let mut sudoers_d_files = Vec::new();

        for entry in entries.flatten() {
            if let Ok(path) = entry.path().canonicalize()
                && let Ok(content) = fs::read_to_string(&path)
            {
                sudoers_d_files.push(format!("File: {}", path.display()));
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    sudoers_d_files.push(format!("  {}", line));

                    if line.contains("NOPASSWD") {
                        finding.severity = Severity::High;
                    }
                }
                sudoers_d_files.push("".to_string());
            }
        }

        if !sudoers_d_files.is_empty() {
            finding.details.push("".to_string());
            finding.details.push("/etc/sudoers.d/ files:".to_string());
            finding.details.extend(sudoers_d_files);
            has_content = true;
        }
    }

    // 检查 /etc/sudoers.d/ 是否可写
    if let Ok(metadata) = fs::metadata("/etc/sudoers.d") {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o002 != 0 || mode & 0o020 != 0 {
            finding.details.push("".to_string());
            finding
                .details
                .push("CRITICAL: /etc/sudoers.d/ is writable!".to_string());
            finding
                .details
                .push("You can create a file to escalate privileges".to_string());
            finding.severity = Severity::Critical;
            has_content = true;
        }
    }

    if !has_content {
        return None;
    }

    Some(finding)
}

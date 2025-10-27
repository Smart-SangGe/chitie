use crate::{Category, Finding, Severity};
use std::process::Command;

///  Users Information - My User
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Current user and group information
///
///  Checks for:
///  - Current user ID and groups
///  - Dangerous group memberships (docker, sudo, wheel, etc.)
///  - Root user detection
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users
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
        "My User",
        "Current user information",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users",
    );

    // 运行 id 命令
    if let Ok(output) = Command::new("id").output()
        && output.status.success()
    {
        let id_output = String::from_utf8_lossy(&output.stdout).trim().to_string();
        finding.details.push(format!("ID: {}", id_output));

        // 检查危险组
        let dangerous_groups = [
            "docker", "sudo", "wheel", "admin", "root", "adm", "lxd", "lxc",
        ];

        let mut found_dangerous = Vec::new();
        for group in &dangerous_groups {
            if id_output.contains(group) {
                found_dangerous.push(format!("WARNING: User is in '{}' group", group));
                finding.severity = Severity::High;
            }
        }

        if !found_dangerous.is_empty() {
            finding.details.push("".to_string());
            finding.details.extend(found_dangerous);
        }

        // 检查是否是 root
        if id_output.contains("uid=0(root)") {
            finding.details.push("".to_string());
            finding.details.push("INFO: Running as root".to_string());
        }
    }

    // 备用：whoami + groups
    if finding.details.is_empty() {
        if let Ok(output) = Command::new("whoami").output()
            && output.status.success()
        {
            let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
            finding.details.push(format!("User: {}", user));
        }
        if let Ok(output) = Command::new("groups").output()
            && output.status.success()
        {
            let groups = String::from_utf8_lossy(&output.stdout).trim().to_string();
            finding.details.push(format!("Groups: {}", groups));
        }
    }

    Some(finding)
}

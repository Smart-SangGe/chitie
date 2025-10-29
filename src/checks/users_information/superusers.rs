use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;

///  User Information - Superusers and Privileged Groups
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Check for users with UID 0 and members of privileged groups.
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html
///  - Based on LinPEAS 6_users_information/11_Superusers.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "Superusers and Privileged Group Members",
        "Found users with UID 0 or membership in administrative groups.",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html",
    );

    let mut details = Vec::new();
    let mut found_something = false;

    // 1. Check for users with UID 0
    let mut uid_0_users = Vec::new();
    if let Ok(passwd_content) = fs::read_to_string("/etc/passwd") {
        for line in passwd_content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 2 && parts[2] == "0" {
                uid_0_users.push(line.to_string());
            }
        }
    }

    if !uid_0_users.is_empty() {
        details.push("=== Users with UID 0 ===".to_string());
        // If there is a non-root UID 0 user, it's a high severity finding
        if uid_0_users.iter().any(|u| !u.starts_with("root:")) {
            finding.severity = Severity::High;
            details.push("⚠ Found non-root user(s) with UID 0!".to_string());
        } else if finding.severity < Severity::Medium {
            finding.severity = Severity::Medium;
        }
        details.extend(uid_0_users);
        found_something = true;
    }

    // 2. Check for members of privileged groups
    let privileged_groups = [
        "sudo", "wheel", "adm", "docker", "lxd", "root", "shadow", "disk", "video",
    ];
    let mut group_details = Vec::new();

    for group in &privileged_groups {
        if let Ok(output) = Command::new("getent").arg("group").arg(group).output()
            && output.status.success()
        {
            let group_info = String::from_utf8_lossy(&output.stdout);
            group_details.push(format!("- Members of group '{}':", group));
            group_details.push(group_info.trim().to_string());
            if finding.severity < Severity::Medium {
                finding.severity = Severity::Medium;
            }
            found_something = true;
        }
    }

    if !group_details.is_empty() {
        details.push("\n=== Members of Privileged Groups ===".to_string());
        details.extend(group_details);
    }

    if !found_something {
        return None;
    }

    finding.details = details;
    Some(finding)
}

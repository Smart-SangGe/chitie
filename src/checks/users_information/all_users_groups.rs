use crate::{Category, Finding, Severity};
use std::fs;

///  User Information - All Users and Groups
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Lists all local users and groups from /etc/passwd and /etc/group.
///
///  References:
///  - Based on LinPEAS 6_users_information/13_Users_groups.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "All Local Users and Groups",
        "Full listing of users from /etc/passwd and groups from /etc/group.",
    );

    let mut details = Vec::new();
    let mut found_something = false;

    // 1. List all users from /etc/passwd
    if let Ok(passwd_content) = fs::read_to_string("/etc/passwd") {
        let user_count = passwd_content.lines().count();
        details.push(format!("=== All Users ({}) ===", user_count));
        details.push(passwd_content);
        found_something = true;
    }

    // 2. List all groups from /etc/group
    if let Ok(group_content) = fs::read_to_string("/etc/group") {
        let group_count = group_content.lines().count();
        details.push(format!("\n=== All Groups ({}) ===", group_count));
        details.push(group_content);
        found_something = true;
    }

    if !found_something {
        return None;
    }

    finding.details = details;
    Some(finding)
}

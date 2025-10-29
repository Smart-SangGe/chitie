use crate::{Category, Finding, Severity};
use std::fs;

///  User Information - Users with Console/Login Shell
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Finds users that have a valid login shell configured in /etc/passwd.
///
///  References:
///  - Based on LinPEAS 6_users_information/12_Users_with_console.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "Users with Console/Login Shell",
        "Lists users with a valid login shell, indicating they can log into the system.",
    );

    let mut login_users = Vec::new();

    if let Ok(passwd_content) = fs::read_to_string("/etc/passwd") {
        for line in passwd_content.lines() {
            if let Some(shell) = line.rsplit(':').next() {
                // Heuristic used by LinPEAS: check if the shell ends with "sh"
                // Also check for other common shells and exclude common nologin shells.
                let is_login_shell = (shell.ends_with("sh") || shell.ends_with("fish") || shell.ends_with("csh"))
                    && !shell.ends_with("nologin")
                    && !shell.ends_with("false");

                if is_login_shell {
                    login_users.push(line.to_string());
                }
            }
        }
    }

    if login_users.is_empty() {
        return None;
    }

    finding.details = login_users;
    Some(finding)
}

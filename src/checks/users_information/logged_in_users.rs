use crate::{Category, Finding, Severity};
use std::process::Command;

///  User Information - Currently Logged-In Users
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Checks who is currently logged in and what sessions are active (w, screen, tmux).
///
///  References:
///  - Based on LinPEAS 6_users_information/14_Login_now.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "Currently Logged-In Users and Sessions",
        "Information about currently logged-in users and active terminal sessions.",
    );

    let mut details = Vec::new();
    let mut found_something = false;

    // 1. Use `w` for a comprehensive overview
    if let Ok(output) = Command::new("w").output() {
        if output.status.success() {
            let w_output = String::from_utf8_lossy(&output.stdout);
            if !w_output.trim().is_empty() {
                details.push("=== Output of 'w' command ===".to_string());
                details.push(w_output.to_string());
                found_something = true;
            }
        }
    }

    // 2. Check for screen sessions
    if let Ok(output) = Command::new("screen").arg("-ls").output() {
        if output.status.success() {
            let screen_output = String::from_utf8_lossy(&output.stdout);
            if !screen_output.contains("No Sockets found") && !screen_output.trim().is_empty() {
                details.push("\n=== Active 'screen' sessions ===".to_string());
                details.push(screen_output.to_string());
                found_something = true;
            }
        }
    }

    // 3. Check for tmux sessions
    if let Ok(output) = Command::new("tmux").arg("list-sessions").output() {
        if output.status.success() {
            let tmux_output = String::from_utf8_lossy(&output.stdout);
            if !tmux_output.trim().is_empty() {
                details.push("\n=== Active 'tmux' sessions ===".to_string());
                details.push(tmux_output.to_string());
                found_something = true;
            }
        }
    }

    if !found_something {
        return None;
    }

    finding.details = details;
    Some(finding)
}

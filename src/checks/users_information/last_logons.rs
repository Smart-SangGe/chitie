use crate::utils::command::Command;
use crate::{Category, Finding, Severity};
use std::fs;

///  User Information - Last Logons and Login History
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Checks for last logons, failed logins, and login history from logs.
///
///  References:
///  - Based on LinPEAS 6_users_information/15_Last_logons.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "Last Logons and Login History",
        "Shows recent successful and failed logins, and last logon time for users.",
    );

    let mut details = Vec::new();
    let mut found_something = false;

    // 1. Get last 20 logins
    if let Ok(output) = Command::new("last").args(&["-n", "20"]).output() {
        if output.status.success() {
            let last_output = String::from_utf8_lossy(&output.stdout);
            if !last_output.trim().is_empty() {
                details.push("=== Last 20 Logins (from 'last')===".to_string());
                details.push(last_output.to_string());
                found_something = true;
            }
        }
    }

    // 2. Get last 20 failed logins
    if let Ok(output) = Command::new("lastb").args(&["-n", "20"]).output() {
        if output.status.success() {
            let lastb_output = String::from_utf8_lossy(&output.stdout);
            if !lastb_output.trim().is_empty() {
                details.push("\n=== Last 20 Failed Logins (from 'lastb')===".to_string());
                details.push(lastb_output.to_string());
                found_something = true;
            }
        }
    }

    // 3. Get recent logins from auth.log
    if let Ok(auth_log_content) = fs::read_to_string("/var/log/auth.log") {
        let recent_logins: Vec<&str> = auth_log_content
            .lines()
            .filter(|line| {
                let lower_line = line.to_lowercase();
                lower_line.contains("login")
                    || lower_line.contains("authentication")
                    || lower_line.contains("accepted")
            })
            .collect();

        if !recent_logins.is_empty() {
            details.push("\n=== Recent Logins from /var/log/auth.log (last 20) ===".to_string());
            let last_20 = recent_logins.iter().rev().take(20).rev();
            for line in last_20 {
                details.push(line.to_string());
            }
            found_something = true;
        }
    }

    // 4. Get last logon time for each user
    if let Ok(output) = Command::new("lastlog").output() {
        if output.status.success() {
            let lastlog_output = String::from_utf8_lossy(&output.stdout);
            let filtered_log: String = lastlog_output
                .lines()
                .filter(|line| !line.contains("**Never logged in**"))
                .collect::<Vec<&str>>()
                .join("\n");

            if !filtered_log.trim().is_empty() {
                details.push("\n=== Last Logon Time for Each User (from 'lastlog')===".to_string());
                details.push(filtered_log);
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

use crate::{Category, Finding, Severity};
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

///  User Information - Sudo Token Status
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Checks for an active sudo session token and for conditions that might allow sudo token abuse.
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens
///  - Based on LinPEAS 6_users_information/8_Sudo_tokens.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "Sudo Session Token Status",
        "Checks for active sudo tokens and ptrace protection status",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens",
    );

    let mut details = Vec::new();
    let mut found_something = false;

    // 1. Direct check for active sudo token
    if let Ok(output) = Command::new("sudo").args(&["-n", "-l"]).output() {
        if output.status.success() {
            let sudo_list = String::from_utf8_lossy(&output.stdout);
            details.push("⚠ Active sudo session token found! User can run sudo commands without a password.".to_string());
            details.push("Sudo privileges:".to_string());
            details.push(sudo_list.trim().to_string());
            finding.severity = Severity::High;
            found_something = true;
        }
    }

    details.push("".to_string());

    // 2. Ptrace scope check
    details.push("=== Ptrace Protection Status ===".to_string());
    match fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(scope) => {
            let scope = scope.trim();
            if scope == "0" {
                details.push("⚠ ptrace protection is DISABLED (scope=0). Sudo tokens from other processes may be hijackable.".to_string());
                if finding.severity < Severity::Medium {
                    finding.severity = Severity::Medium;
                }
                found_something = true;

                // Check for gdb
                if is_command_in_path("gdb") {
                    details.push("  - gdb is installed, which can be used for ptrace attacks.".to_string());
                }
            } else {
                details.push(format!("ptrace protection is ENABLED (scope={})", scope));
            }
        }
        Err(_) => {
            details.push("Could not read /proc/sys/kernel/yama/ptrace_scope.".to_string());
        }
    }

    details.push("".to_string());

    // 3. .sudo_as_admin_successful check
    if let Ok(home_dir) = env::var("HOME") {
        let sudo_admin_file = Path::new(&home_dir).join(".sudo_as_admin_successful");
        if sudo_admin_file.exists() {
            details.push("=== Sudo History File ===".to_string());
            details.push("⚠ Found ~/.sudo_as_admin_successful. This indicates the user has successfully used sudo at some point.".to_string());
            if finding.severity < Severity::Medium {
                finding.severity = Severity::Medium;
            }
            found_something = true;
        }
    }

    if !found_something {
        return None;
    }

    finding.details = details;
    Some(finding)
}

fn is_command_in_path(command: &str) -> bool {
    if let Ok(path_var) = env::var("PATH") {
        for path in env::split_paths(&path_var) {
            let p_str = path.join(command);
            if p_str.is_file() {
                return true;
            }
        }
    }
    false
}

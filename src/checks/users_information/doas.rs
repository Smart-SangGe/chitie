use crate::{Category, Finding, Severity};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

///  User Information - Doas Configuration
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Check doas configuration and permissions for privilege escalation.
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#doas
///  - Based on LinPEAS 6_users_information/9_Doas.sh
pub async fn check() -> Option<Finding> {
    let doas_bin = if is_command_in_path("doas") {
        Some("doas")
    } else {
        None
    };

    let conf_files = [
        "/etc/doas.conf",
        "/usr/local/etc/doas.conf",
        // Other potential paths could be added here if needed
    ];

    let mut found_conf_files = Vec::new();
    for file in &conf_files {
        if Path::new(file).exists() {
            found_conf_files.push(file.to_string());
        }
    }

    // Only proceed if doas binary or a config file is found
    if doas_bin.is_none() && found_conf_files.is_empty() {
        return None;
    }

    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "Doas Configuration Analysis",
        "Found doas binary or configuration files. Review for privilege escalation vectors.",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#doas",
    );

    let mut details = Vec::new();

    if let Some(bin) = doas_bin {
        details.push(format!("Doas binary found at: {}", bin));
    }

    if !found_conf_files.is_empty() {
        details.push("\n=== Doas Configuration Files ===".to_string());
        for file_path in found_conf_files {
            details.push(format!("\nFound config file: {}", file_path));

            // Check for writability
            if let Ok(metadata) = fs::metadata(&file_path) {
                let perms = metadata.permissions();
                if perms.mode() & 0o002 != 0 { // Writable by others
                    details.push("  ⚠ HIGH: Configuration file is writable by others!".to_string());
                    finding.severity = Severity::High;
                }
            }

            // Analyze content
            if let Ok(content) = fs::read_to_string(&file_path) {
                let mut has_nopass = false;
                for line in content.lines() {
                    if line.trim().starts_with("#") || line.trim().is_empty() {
                        continue;
                    }
                    if line.contains("nopass") {
                        has_nopass = true;
                    }
                }

                if has_nopass {
                    details.push("  ⚠ HIGH: Found 'nopass' rule, allowing passwordless execution.".to_string());
                    finding.severity = Severity::High;
                }

                details.push("  --- File Content ---".to_string());
                details.push(content);
                details.push("  --------------------".to_string());
            }
        }
    }

    if let Some(bin) = doas_bin {
        details.push("\n=== Testing 'doas -l' ===".to_string());
        if let Ok(output) = Command::new(bin).arg("-l").output() {
            if output.status.success() {
                details.push("  'doas -l' command succeeded:".to_string());
                details.push(String::from_utf8_lossy(&output.stdout).to_string());
                if finding.severity < Severity::Medium {
                    finding.severity = Severity::Medium;
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                details.push(format!("  'doas -l' failed: {}", stderr));
            }
        }
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

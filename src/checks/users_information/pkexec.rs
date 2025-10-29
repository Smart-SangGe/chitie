use crate::{Category, Finding, Severity};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

///  User Information - Pkexec/Polkit
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Check Pkexec policy and related files for privilege escalation.
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2
///  - Based on LinPEAS 6_users_information/10_Pkexec.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "Polkit/pkexec Configuration Analysis",
        "Analyzes Polkit policies and pkexec for privilege escalation vectors.",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2",
    );

    let mut details = Vec::new();
    let mut found_something = false;

    // 1. Check pkexec binary
    if let Ok(output) = Command::new("pkexec").arg("--version").output() {
        details.push("=== Pkexec Binary ===".to_string());
        details.push("pkexec binary found".to_string());
        details.push(String::from_utf8_lossy(&output.stdout).trim().to_string());
        found_something = true;
    }

    // 2. Check Polkit policies
    let policy_dirs = [
        "/etc/polkit-1/localauthority.conf.d/",
        "/etc/polkit-1/rules.d/",
        "/usr/share/polkit-1/rules.d/",
    ];

    let mut policy_details = Vec::new();
    for dir_path in &policy_dirs {
        let path = Path::new(dir_path);
        if !path.is_dir() {
            continue;
        }

        policy_details.push(format!("\nChecking directory: {}", dir_path));
        found_something = true;

        // Check if directory is writable
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.permissions().mode() & 0o002 != 0 { // Writable by others
                policy_details.push("  ⚠ HIGH: Directory is writable by others!".to_string());
                finding.severity = Severity::High;
            }
        }

        // Check files within the directory
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.filter_map(Result::ok) {
                let file_path = entry.path();
                if !file_path.is_file() {
                    continue;
                }

                if let Some(file_name) = file_path.to_str() {
                    policy_details.push(format!("  - Analyzing file: {}", file_name));
                }

                // Check if file is writable
                if let Ok(metadata) = fs::metadata(&file_path) {
                    if metadata.permissions().mode() & 0o002 != 0 {
                        policy_details.push("    ⚠ HIGH: File is writable by others!".to_string());
                        finding.severity = Severity::High;
                    }
                }

                // Read and analyze content
                if let Ok(content) = fs::read_to_string(&file_path) {
                    if content.contains("polkit.Result.YES") || content.contains("<allow_any>yes</allow_any>") {
                        policy_details.push("    ⚠ HIGH: File contains rule for unconditional access!".to_string());
                        finding.severity = Severity::High;
                    }
                    policy_details.push("    --- Content ---".to_string());
                    policy_details.push(content.trim().to_string());
                    policy_details.push("    ---------------".to_string());
                }
            }
        }
    }

    if !policy_details.is_empty() {
        details.push("\n=== Polkit Policies ===".to_string());
        details.extend(policy_details);
    }

    // 3. Check for running polkit agent
    if let Ok(output) = Command::new("ps").arg("aux").output() {
        let processes = String::from_utf8_lossy(&output.stdout);
        let mut agent_found = false;
        let mut agent_details = Vec::new();

        for line in processes.lines() {
            if line.to_lowercase().contains("polkit") && !line.contains("grep") && !line.contains("chitie") {
                if !agent_found {
                    agent_details.push("\n=== Running Polkit Agent(s) ===".to_string());
                    agent_found = true;
                    found_something = true;
                }
                agent_details.push(line.to_string());
            }
        }
        details.extend(agent_details);
    }

    if !found_something {
        return None;
    }

    finding.details = details;
    Some(finding)
}

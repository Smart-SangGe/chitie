use crate::{Category, Finding, Severity};
use std::env;
use std::path::Path;
use std::process::Command;

///  User Information - PGP Keys
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Check for PGP keys and related files that might contain sensitive information.
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#pgp-keys
///  - Based on LinPEAS 6_users_information/5_Pgp_keys.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "PGP Keys and Related Files",
        "Found PGP keys or related configuration files",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#pgp-keys",
    );

    let mut details = Vec::new();

    // 1. Check for GPG
    if let Ok(output) = Command::new("gpg").arg("--version").output() {
        if output.status.success() {
            details.push("=== GPG Keys ===".to_string());

            // List public keys
            if let Ok(keys_output) = Command::new("gpg").arg("--list-keys").output() {
                let keys = String::from_utf8_lossy(&keys_output.stdout);
                if !keys.trim().is_empty() && !keys.contains("gpg: directory not found") {
                    details.push("Public keys found:".to_string());
                    details.push(keys.trim().to_string());
                } else {
                    details.push("No public keys found.".to_string());
                }
            }

            // List secret keys (important finding)
            if let Ok(secret_keys_output) = Command::new("gpg").arg("--list-secret-keys").output() {
                let secret_keys = String::from_utf8_lossy(&secret_keys_output.stdout);
                if !secret_keys.trim().is_empty()
                    && !secret_keys.contains("gpg: directory not found")
                {
                    details.push("\n⚠ SECRET KEYS FOUND ⚠".to_string());
                    details.push(secret_keys.trim().to_string());
                    finding.severity = Severity::Medium;
                }
            }
            details.push("".to_string());
        }
    }

    // 2. Check for NetPGP
    if let Ok(output) = Command::new("netpgpkeys").arg("--version").output() {
        if output.status.success() {
            details.push("=== NetPGP Keys ===".to_string());
            if let Ok(keys_output) = Command::new("netpgpkeys").arg("--list-keys").output() {
                let keys = String::from_utf8_lossy(&keys_output.stdout);
                if !keys.trim().is_empty() {
                    details.push("NetPGP keys found:".to_string());
                    details.push(keys.trim().to_string());
                } else {
                    details.push("No NetPGP keys found.".to_string());
                }
            }
            details.push("".to_string());
        }
    }

    // 3. Check for common PGP files
    if let Ok(home_dir) = env::var("HOME") {
        let pgp_related_paths = [
            ".gnupg",
            ".pgp",
            ".openpgp",
            ".ssh/gpg-agent.conf",
            ".config/gpg",
        ];

        let mut found_files = Vec::new();
        for p in &pgp_related_paths {
            let full_path = Path::new(&home_dir).join(p);
            if full_path.exists() {
                found_files.push(format!("Found: {}", full_path.display()));
            }
        }

        if !found_files.is_empty() {
            details.push("=== PGP Related Files/Directories ===".to_string());
            details.extend(found_files);
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

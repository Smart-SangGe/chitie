use crate::{Category, Finding, Severity};
use std::fs;

///  User Information - Password Policy
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Checks for basic password policy settings in /etc/login.defs.
///
///  References:
///  - Based on LinPEAS 6_users_information/17_Password_policy.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Info,
        "Password Policy from /etc/login.defs",
        "Basic password policy settings related to expiration and encryption method.",
    );

    let mut details = Vec::new();

    if let Ok(content) = fs::read_to_string("/etc/login.defs") {
        let keywords = [
            "PASS_MAX_DAYS",
            "PASS_MIN_DAYS",
            "PASS_WARN_AGE",
            "ENCRYPT_METHOD",
        ];

        for line in content.lines() {
            let trimmed_line = line.trim();
            if trimmed_line.starts_with("#") {
                continue;
            }

            if keywords.iter().any(|&kw| trimmed_line.starts_with(kw)) {
                details.push(trimmed_line.to_string());
            }
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

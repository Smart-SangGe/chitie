use crate::{Category, Finding, Severity};
use std::fs;
use std::path::Path;

///  Interesting Permissions - AppArmor Profiles
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Check for AppArmor profiles
///
///  Checks for:
///  - Existence of /etc/apparmor.d/
///  - Lists binary profiles
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-breakout/index.html#apparmor
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "AppArmor Profiles",
        "AppArmor profiles restrict program capabilities",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-breakout/index.html#apparmor");

    let apparmor_dir = Path::new("/etc/apparmor.d/");
    if !apparmor_dir.exists() || !apparmor_dir.is_dir() {
        return None;
    }

    let mut profiles = Vec::new();
    if let Ok(entries) = fs::read_dir(apparmor_dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // LinPEAS checks for files containing a dot, usually indicating a path-based profile
                    if name.contains('.') {
                        profiles.push(format!("{}", path.display()));
                    }
                }
            }
        }
    }

    if profiles.is_empty() {
        finding.details.push("AppArmor directory exists but no profiles found".to_string());
    } else {
        finding.details.push(format!("Found {} AppArmor binary profiles:", profiles.len()));
        finding.details.extend(profiles);
    }

    Some(finding)
}

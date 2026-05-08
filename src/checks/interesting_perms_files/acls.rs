use crate::utils::command::Command;
use crate::{Category, Finding, Severity};

///  Interesting Permissions - Files ACLs
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Find files with Access Control Lists (ACLs) set
///
///  Checks for:
///  - Files with ACLs in interesting directories using getfacl
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "Files with ACLs",
        "Files with Access Control Lists (ACLs) might expose sensitive information or allow privilege escalation",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls");

    // Directories to search for ACLs (limiting scope to avoid long runtime)
    // LinPEAS checks: /bin /etc /home /opt /sbin /usr /tmp /root
    let search_dirs = vec![
        "/bin", "/etc", "/home", "/opt", "/sbin", "/usr", "/tmp", "/root",
    ];

    let mut details = Vec::new();

    // Use getfacl -R -s -p (Recursive, skip files without ACLs, absolute paths)
    // -t is not standard on all getfacl versions? LinPEAS uses -t -s -R -p.
    // -s: skip files that only have the base ACL entries (owner, group, others).
    // -R: recursive
    // -p: do not strip leading slash

    // We check if getfacl exists first
    if Command::new("getfacl").arg("--version").output().is_err() {
        finding
            .details
            .push("getfacl command not found, skipping ACL check".to_string());
        return Some(finding);
    }

    let mut found_acls = Vec::new();

    // Run getfacl for all dirs at once to save process overhead, or one by one?
    // One by one might be safer for argument limits.
    // Also limit output lines to avoid flooding.

    for dir in search_dirs {
        if !std::path::Path::new(dir).exists() {
            continue;
        }

        // We use stderr=null to avoid permission denied errors flooding
        if let Ok(output) = Command::new("getfacl")
            .args(&["-R", "-s", "-p", dir])
            .stderr(std::process::Stdio::null())
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.starts_with("# file: ") {
                        let file_path = line.trim_start_matches("# file: ");
                        found_acls.push(file_path.to_string());
                    }
                }
            }
        }
    }

    // Sort and dedup
    found_acls.sort();
    found_acls.dedup();

    if found_acls.is_empty() {
        return None;
    }

    details.push(format!(
        "Found {} files with ACLs (showing top 50):",
        found_acls.len()
    ));
    details.extend(found_acls.iter().take(50).cloned());

    if found_acls.len() > 50 {
        details.push(format!("... and {} more", found_acls.len() - 50));
    }

    finding.details = details;
    Some(finding)
}

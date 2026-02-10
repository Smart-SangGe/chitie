use crate::{Category, Finding, Severity};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use walkdir::WalkDir;

///  Processes & Cron & Services & Timers - Legacy r-commands and host-based trust
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Detect legacy r-services exposure and dangerous host-based trust
///  Corresponds to LinPEAS: 15_Rcommands_trust.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Process,
        Severity::Info,
        "Legacy r-commands and host-based trust",
        "Detect legacy r-services (rsh/rlogin/rexec) and dangerous host-based trust",
    );

    let mut details = Vec::new();

    // 1. Check for /etc/hosts.equiv and /etc/shosts.equiv
    for f in &["/etc/hosts.equiv", "/etc/shosts.equiv"] {
        let path = Path::new(f);
        if path.exists() {
            if let Ok(metadata) = fs::metadata(path) {
                let perms = metadata.mode() & 0o777;
                details.push(format!("  {} (perm {:o}, owner {})", f, perms, metadata.uid()));
                
                if let Ok(content) = fs::read_to_string(path) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            details.push(format!("    {}", trimmed));
                            if trimmed.contains('+') {
                                details.push("    [!] Wildcard '+' trust found".to_string());
                                finding.severity = Severity::High;
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Per-user .rhosts files
    let mut found_rhosts = false;
    for entry in WalkDir::new("/home")
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.file_name().map_or(false, |n| n == ".rhosts" || n == ".shosts") {
            found_rhosts = true;
            if let Ok(metadata) = entry.metadata() {
                let perms = metadata.mode() & 0o777;
                details.push(format!("  {} (perm {:o}, owner {})", path.display(), perms, metadata.uid()));
                
                // Insecure perms check
                if (perms & 0o022) != 0 {
                    details.push("    [!] Insecure permissions (group/other write)".to_string());
                    if finding.severity < Severity::Medium {
                        finding.severity = Severity::Medium;
                    }
                }
            }
        }
    }
    if !found_rhosts {
        // Check root separately
        let root_rhosts = Path::new("/root/.rhosts");
        if root_rhosts.exists() {
             if let Ok(metadata) = fs::metadata(root_rhosts) {
                details.push(format!("  /root/.rhosts (perm {:o})", metadata.mode() & 0o777));
             }
        }
    }

    // 3. PAM rhosts
    for p in &["/etc/pam.d/rlogin", "/etc/pam.d/rsh"] {
        let path = Path::new(p);
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if content.contains("pam_rhosts") {
                    details.push(format!("  PAM rhosts auth enabled in {}", p));
                    if finding.severity < Severity::Medium {
                        finding.severity = Severity::Medium;
                    }
                }
            }
        }
    }

    // 4. SSH HostbasedAuthentication
    if let Ok(content) = fs::read_to_string("/etc/ssh/sshd_config") {
        if content.lines().any(|l| {
            let l = l.trim();
            !l.starts_with('#') && l.to_lowercase().contains("hostbasedauthentication") && l.to_lowercase().contains("yes")
        }) {
            details.push("  HostbasedAuthentication enabled in /etc/ssh/sshd_config".to_string());
            if finding.severity < Severity::Medium {
                finding.severity = Severity::Medium;
            }
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

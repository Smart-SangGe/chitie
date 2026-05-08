use crate::{Category, Finding, Severity};
use std::fs;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

///  Software Information - PostgreSQL
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for PostgreSQL credentials, config files, and weak access
///  Corresponds to LinPEAS: Postgresql.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Software,
        Severity::Info,
        "PostgreSQL Database",
        "PostgreSQL configuration audit and access discovery",
    );

    let mut details = Vec::new();

    // 1. Process check
    if let Ok(output) = Command::new("ps").arg("aux").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("postgres") && !line.contains("grep") {
                details.push(format!("PostgreSQL process found: {}", line.trim()));
                break;
            }
        }
    }

    // 2. Config files
    let config_dirs = vec!["/etc/postgresql", "/var/lib/pgsql", "/var/lib/postgresql"];
    for dir in config_dirs {
        if !Path::new(dir).exists() {
            continue;
        }
        for entry in WalkDir::new(dir)
            .max_depth(4)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if name == "pg_hba.conf" || name == "postgresql.conf" {
                let is_readable = nix::unistd::access(path, nix::unistd::AccessFlags::R_OK).is_ok();
                if is_readable {
                    details.push(format!(
                        "[!] SENSITIVE: Readable Postgres config: {}",
                        path.display()
                    ));
                    if finding.severity < Severity::High {
                        finding.severity = Severity::High;
                    }
                    // Check for 'trust' in pg_hba.conf
                    if name == "pg_hba.conf" {
                        if let Ok(content) = fs::read_to_string(path) {
                            if content.contains("trust") {
                                details.push("    [!] WARNING: 'trust' authentication enabled in pg_hba.conf".to_string());
                                finding.severity = Severity::High;
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. No-pass login attempts (template0, template1)
    let users = vec!["postgres", "pgsql"];
    let dbs = vec!["template0", "template1", "postgres"];

    for user in users {
        for db in &dbs {
            let mut cmd = Command::new("psql");
            cmd.arg("-U")
                .arg(user)
                .arg("-d")
                .arg(db)
                .arg("-c")
                .arg("SELECT version()");

            if let Ok(output) = cmd.output() {
                if output.status.success() {
                    details.push(format!(
                        "[!] CRITICAL: Successful PostgreSQL login as {} to {} with NOPASS!",
                        user, db
                    ));
                    finding.severity = Severity::Critical;
                    break;
                }
            }
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

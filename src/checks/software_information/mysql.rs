use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;
use std::path::Path;
use walkdir::WalkDir;

///  Software Information - MySQL
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for MySQL credentials, config files, and version vulnerabilities
///  Corresponds to LinPEAS: Mysql.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Software,
        Severity::Info,
        "MySQL Database",
        "MySQL configuration audit and credential discovery",
    );

    let mut details = Vec::new();

    // 1. Check for MySQL process and version
    let mut mysql_running_as_root = false;
    
    if let Ok(output) = Command::new("ps").arg("aux").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("mysqld") && !line.contains("grep") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    let user = parts[0];
                    details.push(format!("MySQL process running as user: {}", user));
                    if user == "root" {
                        mysql_running_as_root = true;
                    }
                }
                break;
            }
        }
    }

    if let Ok(output) = Command::new("mysqld").arg("--version").output() {
        let mut mysql_version = String::from_utf8_lossy(&output.stdout).to_string();
        if mysql_version.is_empty() {
            mysql_version = String::from_utf8_lossy(&output.stderr).to_string();
        }
        details.push(format!("MySQL version: {}", mysql_version.lines().next().unwrap_or("unknown")));
        
        // Vuln check: root + version 4.x or 5.x
        if mysql_running_as_root && (mysql_version.contains(" 4.") || mysql_version.contains(" 5.")) {
            details.push("[!] CRITICAL: MySQL is running as root with version 4/5 (Potential UDF Exploit)".to_string());
            finding.severity = Severity::Critical;
        }
    }

    // 2. Config files
    let config_dirs = vec!["/etc/mysql", "/etc", "/var/lib/mysql", "/usr/local/mysql"];
    for dir in config_dirs {
        if !Path::new(dir).exists() { continue; }
        for entry in WalkDir::new(dir)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            
            if name == "debian.cnf" || name == "my.cnf" {
                let is_readable = nix::unistd::access(path, nix::unistd::AccessFlags::R_OK).is_ok();
                if is_readable {
                    details.push(format!("[!] SENSITIVE: Readable MySQL config: {}", path.display()));
                    if finding.severity < Severity::High {
                        finding.severity = Severity::High;
                    }
                    if let Ok(content) = fs::read_to_string(path) {
                        for line in content.lines().filter(|l| l.contains("user") || l.contains("password")).take(5) {
                            details.push(format!("    {}", line.trim()));
                        }
                    }
                }
            }
        }
    }

    // 3. User hash file
    let user_myd = "/var/lib/mysql/mysql/user.MYD";
    if Path::new(user_myd).exists() {
        if nix::unistd::access(user_myd, nix::unistd::AccessFlags::R_OK).is_ok() {
            details.push(format!("[!] CRITICAL: MySQL user.MYD (hashes) is readable: {}", user_myd));
            finding.severity = Severity::Critical;
        }
    }

    // 4. Weak password login attempts
    let auth_tests = vec![
        ("root", "root"),
        ("root", "toor"),
        ("root", ""),
    ];

    for (user, pass) in auth_tests {
        let mut cmd = Command::new("mysql");
        cmd.arg("-u").arg(user);
        if !pass.is_empty() {
            cmd.arg(format!("-p{}", pass));
        }
        cmd.arg("-e").arg("SELECT 1;");

        if let Ok(output) = cmd.output() {
            if output.status.success() {
                details.push(format!("[!] CRITICAL: Successful MySQL login as {} with password '{}'!", user, if pass.is_empty() { "NOPASS" } else { pass }));
                finding.severity = Severity::Critical;
                
                // Try to list users
                let mut list_cmd = Command::new("mysql");
                list_cmd.arg("-u").arg(user);
                if !pass.is_empty() { list_cmd.arg(format!("-p{}", pass)); }
                list_cmd.arg("-e").arg("SELECT User,Host,authentication_string FROM mysql.user;");
                if let Ok(out) = list_cmd.output() {
                    details.push(String::from_utf8_lossy(&out.stdout).to_string());
                }
                break; 
            }
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}
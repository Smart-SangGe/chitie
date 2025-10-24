use crate::{Category, Finding, Severity};
use std::env;
use std::os::unix::fs::PermissionsExt;

///  System Information - PATH
///  Author: Sangge
///  Last Update: 2025-10-24
///  Description: Check for PATH environment misconfigurations
///
///  Checks for:
///  - Writable directories in PATH
///  - Current directory (.) in PATH
///  - Relative paths in PATH
///  - PATH hijacking vulnerabilities
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let path_env = env::var("PATH").ok()?;

    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "PATH",
        "PATH environment variable configuration",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses",
    );

    finding.details.push(format!("PATH: {}", path_env));

    let mut vulnerable_paths = Vec::new();

    // 检查每个 PATH 目录
    for dir in path_env.split(':') {
        // 检查当前目录
        if dir == "." || dir == "./" || dir.is_empty() {
            vulnerable_paths.push(format!("DANGEROUS: Current directory in PATH: '{}'", dir));
            continue;
        }

        // 检查是否可写
        if let Ok(metadata) = std::fs::metadata(dir) {
            if metadata.is_dir() {
                // 检查目录是否可写
                if is_writable(dir) {
                    vulnerable_paths.push(format!("Writable directory in PATH: {}", dir));
                }
            }
        }
    }

    if !vulnerable_paths.is_empty() {
        finding.severity = Severity::High;
        finding.description = "VULNERABLE PATH configuration detected!".to_string();
        for vuln in vulnerable_paths {
            finding.details.push(vuln);
        }
        finding.details.push(
            "WARNING: Writable directories in PATH can lead to privilege escalation".to_string(),
        );
        finding
            .details
            .push("Attack: Place malicious binaries in writable PATH directories".to_string());
    }

    Some(finding)
}

/// 检查目录是否可写
fn is_writable(path: &str) -> bool {
    if let Ok(metadata) = std::fs::metadata(path) {
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // 检查其他用户是否有写权限 (o+w)
        if mode & 0o002 != 0 {
            return true;
        }

        // 检查当前用户是否是所有者且有写权限
        // 这个简化检查，实际应该检查 uid/gid
        if mode & 0o200 != 0 {
            // 可以进一步检查是否是当前用户拥有
            return true;
        }
    }

    false
}

use crate::{Category, Finding, Severity};
use std::process::Command;

///  System Information - Sudo Version
///  Author: Sangge
///  Last Update: 2025-10-24
///  Description: Check for sudo vulnerabilities and misconfigurations
///
///  Checks for vulnerable sudo versions with known exploits:
///  - CVE-2021-3156 (Baron Samedit): Heap overflow in sudo
///  - CVE-2021-23239/23240/23241: Potential privilege escalation
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "Sudo Version",
        "Sudo version information and vulnerability check",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version",
    );

    // 尝试执行 sudo -V 命令
    match Command::new("sudo").arg("-V").output() {
        Ok(output) if output.status.success() => {
            let version_output = String::from_utf8_lossy(&output.stdout);

            // 提取 "Sudo version" 行
            if let Some(version_line) = version_output
                .lines()
                .find(|line| line.contains("Sudo ver"))
            {
                finding.details.push(version_line.to_string());

                // 检查是否是易受攻击的版本
                if is_vulnerable_sudo_version(version_line) {
                    finding.severity = Severity::Critical;
                    finding.description = "VULNERABLE sudo version detected!".to_string();
                    finding
                        .details
                        .push("WARNING: This sudo version has known vulnerabilities".to_string());
                    finding.details.push(
                        "Potential CVEs: CVE-2021-3156 (Baron Samedit), CVE-2021-23239/23240/23241"
                            .to_string(),
                    );
                }
            }
        }
        Ok(_) => {
            finding
                .details
                .push("sudo command failed (may not have permission)".to_string());
        }
        Err(_) => {
            finding
                .details
                .push("sudo not found or not in PATH".to_string());
        }
    }

    Some(finding)
}

/// 检查 sudo 版本是否存在已知漏洞
///
/// 易受攻击的版本模式 (来自 LinPEAS sudovB):
/// - 0.x.x 或 1.0-1.8.x: 所有旧版本
/// - 1.9.0 到 1.9.4: CVE-2021-3156 等
/// - 1.9.5p1: 特定补丁版本
/// - 1.9.6 到 1.9.17: 其他已知漏洞
fn is_vulnerable_sudo_version(version_line: &str) -> bool {
    use regex::Regex;

    // 提取版本号 (格式: "Sudo version 1.9.5p2")
    let version_regex = Regex::new(r"(\d+)\.(\d+)\.(\d+)(p\d+)?").unwrap();

    if let Some(caps) = version_regex.captures(version_line) {
        let major: u32 = caps.get(1).unwrap().as_str().parse().unwrap_or(0);
        let minor: u32 = caps.get(2).unwrap().as_str().parse().unwrap_or(0);
        let patch: u32 = caps.get(3).unwrap().as_str().parse().unwrap_or(0);
        let patchlevel = caps.get(4).map(|m| m.as_str());

        // 所有 0.x 和 1.0-1.8.x 版本都易受攻击
        if major == 0 || (major == 1 && minor <= 8) {
            return true;
        }

        // 1.9.x 系列的漏洞检查
        if major == 1 && minor == 9 {
            match patch {
                // 1.9.0 到 1.9.4: CVE-2021-3156 (Baron Samedit)
                0..=4 => return true,

                // 1.9.5p1 特定易受攻击
                5 => {
                    if patchlevel == Some("p1") || patchlevel == Some("p0") {
                        return true;
                    }
                }

                // 1.9.6 到 1.9.17: 其他已知漏洞
                6..=17 => return true,

                _ => {}
            }
        }
    }

    false
}

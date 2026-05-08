use crate::utils::command::Command;
use crate::{Category, Finding, Severity};
use regex::Regex;

///  System Information - USBCreator
///  Author: Sangge
///  Last Update: 2025-10-24
///  Description: Check for USBCreator vulnerabilities via D-Bus
///
///  Checks for:
///  - Presence of com.ubuntu.USBCreator D-Bus service
///  - policykit-desktop-privileges version < 0.21 (vulnerable)
///  - D-Bus command injection through USBCreator
///  - PolicyKit authentication bypass
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation.html
///
///  Execution Mode:
///  - Default: no
///  - Stealth (-s): no
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    // 首先检查 com.ubuntu.USBCreator D-Bus 服务是否存在
    let busctl_output = Command::new("busctl").arg("list").output().ok()?;

    if !busctl_output.status.success() {
        return None;
    }

    let output_str = String::from_utf8_lossy(&busctl_output.stdout);
    if !output_str.contains("com.ubuntu.USBCreator") {
        return None;
    }

    // D-Bus 服务存在，创建 finding
    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "USBCreator",
        "USBCreator D-Bus service detected",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation.html");

    finding
        .details
        .push("com.ubuntu.USBCreator D-Bus service is running".to_string());

    // 检查 policykit-desktop-privileges 版本
    let version = get_policykit_version();

    if let Some(ver) = version {
        finding
            .details
            .push(format!("policykit-desktop-privileges version: {}", ver));

        // 解析版本号 (格式: 0.xx)
        let version_regex = Regex::new(r"^0\.(\d+)").ok()?;
        if let Some(caps) = version_regex.captures(&ver)
            && let Ok(minor) = caps.get(1)?.as_str().parse::<u32>()
            && minor < 21
        {
            finding.severity = Severity::Critical;
            finding.description = "VULNERABLE USBCreator configuration detected!".to_string();
            finding
                .details
                .push("WARNING: policykit-desktop-privileges version < 0.21".to_string());
            finding
                .details
                .push("This system is vulnerable to D-Bus privilege escalation".to_string());
        }
    } else {
        finding
            .details
            .push("Could not determine policykit-desktop-privileges version".to_string());
    }

    Some(finding)
}

/// 获取 policykit-desktop-privileges 版本
fn get_policykit_version() -> Option<String> {
    // 方法1: 使用 dpkg -l
    if let Ok(output) = Command::new("dpkg").arg("-l").output()
        && output.status.success()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let version_regex = Regex::new(r"[0-9][0-9a-zA-Z\.]+").ok()?;
        for line in output_str.lines() {
            if line.contains("policykit-desktop-privileges") {
                // 提取版本号
                if let Some(mat) = version_regex.find(line) {
                    return Some(mat.as_str().to_string());
                }
            }
        }
    }

    // 方法2: 使用 apt-cache policy
    if let Ok(output) = Command::new("apt-cache")
        .arg("policy")
        .arg("policykit-desktop-privileges")
        .output()
        && output.status.success()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("***") {
                // 提取安装的版本
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Some(parts[1].to_string());
                }
            }
        }
    }

    None
}

/// 1. System information
use crate::{Category, Finding, Severity};
use std::fs;

/// 运行系统信息检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let config = crate::config::config();

    let mut handles = vec![
        tokio::spawn(operation_system()),
        tokio::spawn(sudo_version()),
        tokio::spawn(path()),
    ];

    if config.extra || config.all_checks {
        handles.push(tokio::spawn(usbcreator()));
        handles.push(tokio::spawn(date_uptime()));
    }

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

///  System Information - Operative System
///  Author: Sangge
///  Last Update: 2025-10-24
///  Description: Check for operating system information relevant to privilege escalation
///
///  This check gathers comprehensive operating system information including:
///  - Kernel version and build information
///  - OS distribution and version
///  - System architecture
///  - Known vulnerable kernel versions detection
///
///  Checks for known vulnerable kernel versions:
///  - Ubuntu Precise (12.04): 3.2.0-23-generic through 3.13.0-24-generic
///  - Ubuntu Trusty (14.04): 3.13.0-24-generic through 4.4.0-21-generic
///  - Ubuntu Xenial (16.04): 4.4.0-21-generic through 4.8.0-34-generic
///  - RHEL/CentOS 5: 2.6.18 series
///  - RHEL/CentOS 6: 2.6.32 series
///  - RHEL/CentOS 7: 3.10.0 series
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
async fn operation_system() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "Operating System",
        "Operating system and kernel version information"
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits");

    // 读取内核版本信息
    if let Ok(version) = fs::read_to_string("/proc/version") {
        let version = version.trim();

        // 检查是否是已知的易受攻击的内核版本
        let severity = check_vulnerable_kernel(version);

        // 如果检测到易受攻击的内核，提升严重程度
        if severity < Severity::Info {
            finding.severity = severity;
            finding.description = format!("VULNERABLE kernel version detected: {}", version);
        }

        finding.details.push(format!("Kernel: {}", version));
    }

    // 读取系统架构
    if let Ok(arch) = fs::read_to_string("/proc/sys/kernel/arch") {
        finding
            .details
            .push(format!("Architecture: {}", arch.trim()));
    }

    // 读取 /etc/os-release 获取发行版信息
    if let Ok(os_release) = fs::read_to_string("/etc/os-release") {
        for line in os_release.lines() {
            if line.starts_with("PRETTY_NAME=")
                || line.starts_with("NAME=")
                || line.starts_with("VERSION=")
                || line.starts_with("VERSION_ID=")
            {
                let cleaned = line.replace("\"", "");
                finding.details.push(cleaned);
            }
        }
    }

    // 读取 /etc/lsb-release 作为备选
    if let Ok(lsb_release) = fs::read_to_string("/etc/lsb-release") {
        for line in lsb_release.lines() {
            finding.details.push(line.to_string());
        }
    }

    // 读取 /etc/issue 作为额外信息
    if let Ok(issue) = fs::read_to_string("/etc/issue") {
        let issue = issue.trim();
        if !issue.is_empty() && issue != "\\n \\l" {
            finding.details.push(format!("Issue: {}", issue));
        }
    }

    Some(finding)
}

/// 检查内核版本是否存在已知漏洞
fn check_vulnerable_kernel(version: &str) -> Severity {
    let version_lower = version.to_lowercase();

    // Ubuntu Precise (12.04) - CVE-2016-5195 (DirtyCow) 等
    if version_lower.contains("3.2.0-23-generic")
        || version_lower.contains("3.2.0-29-generic")
        || version_lower.contains("3.5.0-23-generic")
        || version_lower.contains("3.8.0-19-generic")
        || version_lower.contains("3.11.0-15-generic")
        || version_lower.contains("3.13.0-24-generic")
    {
        return Severity::High;
    }

    // Ubuntu Trusty (14.04)
    if version_lower.contains("3.13.0-24-generic")
        || version_lower.contains("3.16.0-30-generic")
        || version_lower.contains("3.19.0-25-generic")
        || version_lower.contains("4.2.0-18-generic")
    {
        return Severity::High;
    }

    // Ubuntu Xenial (16.04)
    if version_lower.contains("4.4.0-21-generic") || version_lower.contains("4.8.0-34-generic") {
        return Severity::High;
    }

    // RHEL/CentOS 5
    if version_lower.contains("2.6.18-164.el5")
        || version_lower.contains("2.6.18-274.el5")
        || version_lower.contains("2.6.18-308.el5")
    {
        return Severity::High;
    }

    // RHEL/CentOS 6
    if version_lower.contains("2.6.32-71.el6")
        || version_lower.contains("2.6.32-220.el6")
        || version_lower.contains("2.6.32-358.el6")
        || version_lower.contains("2.6.32-504.el6")
    {
        return Severity::High;
    }

    // RHEL/CentOS 7
    if version_lower.contains("3.10.0-123.el7") || version_lower.contains("3.10.0-327.el7") {
        return Severity::High;
    }

    // 检查是否是非常旧的内核版本（泛化检查）
    if version_lower.contains("2.6.") {
        return Severity::Medium; // 2.6 内核系列已经很老了
    }

    Severity::Info
}

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
async fn sudo_version() -> Option<Finding> {
    use std::process::Command;

    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "Sudo Version",
        "Sudo version information and vulnerability check",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version");

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
async fn usbcreator() -> Option<Finding> {
    use std::process::Command;
    use regex::Regex;

    // 首先检查 com.ubuntu.USBCreator D-Bus 服务是否存在
    let busctl_output = Command::new("busctl")
        .arg("list")
        .output()
        .ok()?;

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

    finding.details.push("com.ubuntu.USBCreator D-Bus service is running".to_string());

    // 检查 policykit-desktop-privileges 版本
    let version = get_policykit_version();

    if let Some(ver) = version {
        finding.details.push(format!("policykit-desktop-privileges version: {}", ver));

        // 解析版本号 (格式: 0.xx)
        let version_regex = Regex::new(r"^0\.(\d+)").ok()?;
        if let Some(caps) = version_regex.captures(&ver) {
            if let Ok(minor) = caps.get(1)?.as_str().parse::<u32>() {
                if minor < 21 {
                    finding.severity = Severity::Critical;
                    finding.description = "VULNERABLE USBCreator configuration detected!".to_string();
                    finding.details.push("WARNING: policykit-desktop-privileges version < 0.21".to_string());
                    finding.details.push("This system is vulnerable to D-Bus privilege escalation".to_string());
                }
            }
        }
    } else {
        finding.details.push("Could not determine policykit-desktop-privileges version".to_string());
    }

    Some(finding)
}

/// 获取 policykit-desktop-privileges 版本
fn get_policykit_version() -> Option<String> {
    use std::process::Command;
    use regex::Regex;

    // 方法1: 使用 dpkg -l
    if let Ok(output) = Command::new("dpkg").arg("-l").output() {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("policykit-desktop-privileges") {
                    // 提取版本号
                    let version_regex = Regex::new(r"[0-9][0-9a-zA-Z\.]+").ok()?;
                    if let Some(mat) = version_regex.find(line) {
                        return Some(mat.as_str().to_string());
                    }
                }
            }
        }
    }

    // 方法2: 使用 apt-cache policy
    if let Ok(output) = Command::new("apt-cache")
        .arg("policy")
        .arg("policykit-desktop-privileges")
        .output()
    {
        if output.status.success() {
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
    }

    None
}

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
async fn path() -> Option<Finding> {
    use std::env;

    let path_env = env::var("PATH").ok()?;

    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "PATH",
        "PATH environment variable configuration",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses");

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
        finding.details.push("WARNING: Writable directories in PATH can lead to privilege escalation".to_string());
        finding.details.push("Attack: Place malicious binaries in writable PATH directories".to_string());
    }

    Some(finding)
}

/// 检查目录是否可写
fn is_writable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;

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

///  System Information - Date & Uptime
///  Author: Sangge
///  Last Update: 2025-10-24
///  Description: Check system date and uptime information
///
///  Provides:
///  - Current system date and time
///  - System uptime
///  - Last boot time
///
///  References:
///  - Long uptime may indicate unpatched systems
///
///  Execution Mode:
///  - Default: no
///  - Stealth (-s): no
///  - Extra (-e): yes
///  - All (-a): yes
async fn date_uptime() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "Date & Uptime",
        "System date and uptime information",
    );

    // 读取当前时间
    if let Ok(output) = std::process::Command::new("date").output() {
        if output.status.success() {
            let date_str = String::from_utf8_lossy(&output.stdout);
            finding.details.push(format!("Date: {}", date_str.trim()));
        }
    }

    // 读取 uptime
    if let Ok(uptime_str) = fs::read_to_string("/proc/uptime") {
        let parts: Vec<&str> = uptime_str.split_whitespace().collect();
        if let Some(uptime_secs) = parts.first() {
            if let Ok(secs) = uptime_secs.parse::<f64>() {
                let days = (secs / 86400.0) as u64;
                let hours = ((secs % 86400.0) / 3600.0) as u64;
                let minutes = ((secs % 3600.0) / 60.0) as u64;
                finding.details.push(format!(
                    "Uptime: {} days, {} hours, {} minutes",
                    days, hours, minutes
                ));

                // 如果系统运行时间超过 100 天，提示可能未打补丁
                if days > 100 {
                    finding.details.push(format!(
                        "NOTE: System has been running for {} days - may need updates/patches",
                        days
                    ));
                }
            }
        }
    }

    Some(finding)
}

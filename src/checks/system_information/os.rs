use crate::{Category, Finding, Severity};
use std::fs;

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
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "Operating System",
        "Operating system and kernel version information",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits",
    );

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

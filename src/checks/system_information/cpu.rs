use crate::{Category, Finding, Severity};

///  System Information - CPU info
///  Author: Sangge
///  Last Update: 2025-10-24
///  Description: Check for CPU information relevant to privilege escalation
///
///  Provides:
///  - CPU architecture
///  - CPU features
///  - CPU vulnerabilities (Spectre, Meltdown, etc.)
///
///  References:
///  - CPU-specific vulnerabilities may provide privilege escalation vectors
///
///  Execution Mode:
///  - Default: no
///  - Stealth (-s): no
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "CPU Info",
        "CPU information and features",
    );

    // 读取 /proc/cpuinfo
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        // 提取关键信息
        for line in cpuinfo.lines() {
            if line.starts_with("model name") || line.starts_with("cpu family") || line.starts_with("vendor_id") {
                if let Some((key, value)) = line.split_once(':') {
                    finding.details.push(format!("{}: {}", key.trim(), value.trim()));
                }
            }
        }

        // 只取第一个 CPU 的信息，避免重复
        finding.details.truncate(3);
    }

    // 读取 CPU vulnerabilities
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu/vulnerabilities") {
        let mut vulns = Vec::new();
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(status) = std::fs::read_to_string(entry.path()) {
                    let status = status.trim();
                    // 只显示存在漏洞或未缓解的
                    if status.contains("Vulnerable") || status.contains("Not affected") == false && status != "Mitigation" {
                        vulns.push(format!("{}: {}", name, status));
                    }
                }
            }
        }

        if !vulns.is_empty() {
            finding.details.push("CPU Vulnerabilities:".to_string());
            finding.details.extend(vulns);
        }
    }

    Some(finding)
}

use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;

///  System Information - Protections
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Check for system security protections
///
///  Checks for:
///  - AppArmor/SELinux status
///  - ASLR status
///  - Seccomp filters
///  - grsecurity/PaX
///  - User namespaces
///  - Cgroup2
///  - Virtual machine detection
///
///  References:
///  - Disabled or weak security protections can aid privilege escalation
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
        "Protections",
        "System security protections status",
    );

    let mut protections = Vec::new();

    // 检查 AppArmor
    if let Ok(output) = Command::new("aa-status").output() {
        if output.status.success() {
            protections.push("AppArmor: enabled".to_string());
        } else {
            protections.push("AppArmor: disabled or not installed".to_string());
        }
    } else if fs::metadata("/etc/apparmor").is_ok() || fs::metadata("/etc/apparmor.d").is_ok() {
        protections.push("AppArmor: config present".to_string());
    } else {
        protections.push("AppArmor: not found".to_string());
    }

    // 检查当前进程的 AppArmor profile
    if let Ok(profile) = fs::read_to_string("/proc/self/attr/current") {
        let profile = profile.trim();
        if profile == "unconfined" {
            protections.push("AppArmor profile: unconfined (WARNING)".to_string());
        } else {
            protections.push(format!("AppArmor profile: {}", profile));
        }
    }

    // 检查 SELinux
    if let Ok(output) = Command::new("sestatus").output() {
        if output.status.success() {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.to_lowercase().contains("disabled") {
                protections.push("SELinux: disabled".to_string());
            } else {
                protections.push("SELinux: enabled".to_string());
            }
        }
    } else {
        protections.push("SELinux: not found".to_string());
    }

    // 检查 ASLR
    if let Ok(aslr) = fs::read_to_string("/proc/sys/kernel/randomize_va_space") {
        let aslr_value = aslr.trim();
        match aslr_value {
            "0" => {
                protections.push("ASLR: DISABLED (CRITICAL)".to_string());
                finding.severity = Severity::Critical;
            }
            "1" => protections.push("ASLR: conservative randomization".to_string()),
            "2" => protections.push("ASLR: full randomization".to_string()),
            _ => protections.push(format!("ASLR: unknown ({})", aslr_value)),
        }
    }

    // 检查 Seccomp
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Seccomp:") {
                let value = line.split(':').nth(1).unwrap_or("").trim();
                if value == "0" {
                    protections.push("Seccomp: disabled".to_string());
                } else {
                    protections.push(format!("Seccomp: enabled (mode {})", value));
                }
                break;
            }
        }
    }

    // 检查 User namespace
    if fs::read_to_string("/proc/self/uid_map").is_ok() {
        protections.push("User namespace: enabled".to_string());
    } else {
        protections.push("User namespace: disabled".to_string());
    }

    // 检查 Cgroup2
    if let Ok(filesystems) = fs::read_to_string("/proc/filesystems") {
        if filesystems.contains("cgroup2") {
            protections.push("Cgroup2: enabled".to_string());
        } else {
            protections.push("Cgroup2: disabled".to_string());
        }
    }

    // 检查 grsecurity
    if let Ok(kernel) = fs::read_to_string("/proc/version") {
        if kernel.contains("grsec") {
            protections.push("grsecurity: present".to_string());
        }
    }

    // 检查是否在虚拟机中运行
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        if cpuinfo.contains("hypervisor") {
            // 尝试使用 systemd-detect-virt 获取详细信息
            if let Ok(output) = Command::new("systemd-detect-virt").output() {
                if output.status.success() {
                    let virt_type = String::from_utf8_lossy(&output.stdout);
                    protections.push(format!(
                        "Virtual machine: Yes ({})",
                        virt_type.trim()
                    ));
                } else {
                    protections.push("Virtual machine: Yes".to_string());
                }
            } else {
                protections.push("Virtual machine: Yes".to_string());
            }
        } else {
            protections.push("Virtual machine: No".to_string());
        }
    }

    finding.details.extend(protections);

    Some(finding)
}

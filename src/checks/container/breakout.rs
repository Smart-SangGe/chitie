use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;

///  Container - Container Breakout Enumeration
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Container breakout enumeration to identify potential escape vectors
///
///  Checks for:
///  - Security mechanisms (Seccomp, AppArmor, User namespaces)
///  - Dangerous capabilities
///  - Writable/shared mount points
///  - Container escape tools
///  - Runtime vulnerabilities
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html
///
///  Execution Mode:
///  - Default: yes (only if inside container)
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    // 只在容器内运行
    if !is_in_container() {
        return None;
    }

    let mut finding = Finding::new(
        Category::Container,
        Severity::Info,
        "Container Breakout",
        "Container escape enumeration",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html");

    finding
        .details
        .push("Running inside container - checking escape vectors".to_string());
    finding.details.push("".to_string());

    // 检查安全机制
    finding
        .details
        .push("=== Security Mechanisms ===".to_string());

    // Seccomp
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Seccomp:") {
                let value = line.split(':').nth(1).unwrap_or("").trim();
                if value == "0" {
                    finding
                        .details
                        .push("WARNING: Seccomp disabled!".to_string());
                    finding.severity = Severity::High;
                } else {
                    finding
                        .details
                        .push(format!("Seccomp: enabled (mode {})", value));
                }
                break;
            }
        }
    }

    // AppArmor
    if let Ok(apparmor) = fs::read_to_string("/proc/self/attr/current") {
        let apparmor = apparmor.trim();
        if apparmor == "unconfined" {
            finding
                .details
                .push("WARNING: AppArmor unconfined!".to_string());
            finding.severity = Severity::High;
        } else {
            finding.details.push(format!("AppArmor: {}", apparmor));
        }
    }

    // User namespace
    if fs::read_to_string("/proc/self/uid_map").is_ok() {
        finding.details.push("User namespace: enabled".to_string());
    } else {
        finding
            .details
            .push("WARNING: User namespace disabled!".to_string());
    }

    finding.details.push("".to_string());

    // 检查危险挂载点
    finding.details.push("=== Dangerous Mounts ===".to_string());
    let mut dangerous_mounts = Vec::new();

    if let Ok(output) = Command::new("mount").output() {
        if output.status.success() {
            let mount_str = String::from_utf8_lossy(&output.stdout);
            for line in mount_str.lines() {
                // Docker socket
                if line.contains("docker.sock") {
                    dangerous_mounts.push("CRITICAL: Docker socket mounted!".to_string());
                    finding.severity = Severity::Critical;
                }
                // Host filesystem
                if line.contains("/host") || line.contains("host") {
                    dangerous_mounts.push(format!("WARNING: Host filesystem: {}", line));
                    if finding.severity < Severity::High {
                        finding.severity = Severity::High;
                    }
                }
                // /proc
                if line.contains("proc on /proc") {
                    dangerous_mounts.push("INFO: /proc mounted".to_string());
                }
                // /dev
                if line.contains("devtmpfs on /dev") {
                    dangerous_mounts.push("INFO: /dev mounted".to_string());
                }
            }
        }
    }

    if dangerous_mounts.is_empty() {
        finding
            .details
            .push("No obviously dangerous mounts detected".to_string());
    } else {
        finding.details.extend(dangerous_mounts);
    }

    finding.details.push("".to_string());

    // 检查容器逃逸工具
    finding
        .details
        .push("=== Container Escape Tools ===".to_string());
    let escape_tools = [
        "nsenter", "unshare", "chroot", "capsh", "setcap", "getcap", "docker", "kubectl", "runc",
    ];

    let mut found_tools = Vec::new();
    for tool in &escape_tools {
        if let Ok(output) = Command::new("which").arg(tool).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                found_tools.push(format!("  {} -> {}", tool, path));
                if finding.severity < Severity::Medium {
                    finding.severity = Severity::Medium;
                }
            }
        }
    }

    if found_tools.is_empty() {
        finding.details.push("No escape tools found".to_string());
    } else {
        finding
            .details
            .push("WARNING: Escape tools available:".to_string());
        finding.details.extend(found_tools);
    }

    finding.details.push("".to_string());

    // 检查 capabilities
    finding.details.push("=== Capabilities ===".to_string());
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Cap") {
                finding.details.push(line.to_string());
                // 检查是否有危险的 capabilities
                if line.contains("CapEff") && !line.contains("0000000000000000") {
                    if finding.severity < Severity::Medium {
                        finding.severity = Severity::Medium;
                    }
                }
            }
        }
        finding
            .details
            .push("NOTE: Use 'capsh --decode=<hex>' to decode capabilities".to_string());
    }

    finding.details.push("".to_string());

    // 检查命名空间
    finding.details.push("=== Namespaces ===".to_string());
    if let Ok(entries) = fs::read_dir("/proc/self/ns") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(link) = fs::read_link(entry.path()) {
                    finding
                        .details
                        .push(format!("  {}: {}", name, link.display()));
                }
            }
        }
    }

    Some(finding)
}

/// 检测是否在容器中
fn is_in_container() -> bool {
    // /.dockerenv
    if fs::metadata("/.dockerenv").is_ok() {
        return true;
    }

    // /run/.containerenv (Podman)
    if fs::metadata("/run/.containerenv").is_ok() {
        return true;
    }

    // /proc/1/cgroup
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker") || cgroup.contains("lxc") || cgroup.contains("kubepods") {
            return true;
        }
    }

    false
}

use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;

///  Container - Writable Bind Mounts without nosuid
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Detect writable bind-mounted paths without nosuid option
///
///  Checks for:
///  - Bind mounts that are writable (rw)
///  - Bind mounts without nosuid option
///  - SUID persistence risk for container-to-host breakout
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html#writable-bind-mounts
///  - Attackers can drop SUID binaries on shared paths to escalate privileges on the host
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
        "RW Bind Mounts",
        "Writable bind mounts without nosuid",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html#writable-bind-mounts");

    // 尝试从 /proc/self/mountinfo 读取
    let mut dangerous_mounts = Vec::new();

    if let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") {
        for line in mountinfo.lines() {
            // 格式: mountid parentid maj:min root mountpoint options ... - fstype source superoptions
            if !line.contains("bind") {
                continue;
            }

            // 检查是否包含 rw 选项
            if !line.contains("rw") {
                continue;
            }

            // 检查是否缺少 nosuid
            if line.contains("nosuid") {
                continue;
            }

            dangerous_mounts.push(line.to_string());
        }
    } else {
        // 后备方案：使用 mount 命令
        if let Ok(output) = Command::new("mount").arg("-l").output() {
            if output.status.success() {
                let mount_str = String::from_utf8_lossy(&output.stdout);
                for line in mount_str.lines() {
                    if !line.contains("bind") {
                        continue;
                    }
                    if !line.contains("rw") {
                        continue;
                    }
                    if line.contains("nosuid") {
                        continue;
                    }
                    dangerous_mounts.push(line.to_string());
                }
            }
        }
    }

    if dangerous_mounts.is_empty() {
        finding.details.push("No writable bind mounts without nosuid found".to_string());
        return Some(finding);
    }

    // 发现危险挂载
    finding.severity = Severity::Critical;
    finding.description = "CRITICAL: Writable bind mounts without nosuid detected!".to_string();

    finding.details.push("WARNING: Found writable bind mounts without nosuid option:".to_string());
    finding.details.push("".to_string());

    for mount in &dangerous_mounts {
        finding.details.push(mount.to_string());
    }

    finding.details.push("".to_string());

    // 检查当前用户是否是 root
    let is_root = if let Ok(output) = Command::new("id").arg("-u").output() {
        if output.status.success() {
            let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            uid == "0"
        } else {
            false
        }
    } else {
        false
    };

    if is_root {
        finding.details.push("CRITICAL: You are root inside the container!".to_string());
        finding.details.push("Attack vector:".to_string());
        finding.details.push("  1. Copy a SUID shell to the writable bind mount:".to_string());
        finding.details.push("     cp /bin/bash /mounted/path/escalate".to_string());
        finding.details.push("     chmod 6777 /mounted/path/escalate".to_string());
        finding.details.push("  2. Execute from the host to get root access".to_string());
    } else {
        finding.details.push("NOTE: Current user is not root in container".to_string());
        finding.details.push("If you obtain container root, these mounts enable host escalation via SUID planting".to_string());
    }

    Some(finding)
}

/// 检测是否在容器中
fn is_in_container() -> bool {
    if fs::metadata("/.dockerenv").is_ok() {
        return true;
    }
    if fs::metadata("/run/.containerenv").is_ok() {
        return true;
    }
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker") || cgroup.contains("lxc") || cgroup.contains("kubepods") {
            return true;
        }
    }
    false
}

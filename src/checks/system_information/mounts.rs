use crate::{Category, Finding, Severity};
use std::fs;

///  System Information - Mounts
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Check for mount point misconfigurations
///
///  Checks for:
///  - Unmounted filesystems in /etc/fstab
///  - Mount point permissions
///  - Mount options (rw, nosuid, noexec, etc.)
///  - Writable mount points
///
///  References:
///  - Mount misconfigurations can lead to privilege escalation
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
        "Mounts",
        "Filesystem mount information",
    );

    // 读取 /etc/fstab
    if let Ok(fstab) = fs::read_to_string("/etc/fstab") {
        let mut fstab_entries = Vec::new();

        for line in fstab.lines() {
            let line = line.trim();
            // 跳过注释和空行
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            fstab_entries.push(line.to_string());
        }

        if !fstab_entries.is_empty() {
            finding.details.push("/etc/fstab entries:".to_string());
            finding.details.extend(fstab_entries);
        }
    }

    // 读取当前挂载点 /proc/mounts
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        let mut mount_issues = Vec::new();

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let _device = parts[0];
            let mount_point = parts[1];
            let _fs_type = parts[2];
            let options = parts[3];

            // 检查危险的挂载选项
            if options.contains("rw") && !options.contains("nosuid") {
                // 可写且没有 nosuid 选项
                if is_interesting_mount(mount_point) {
                    mount_issues.push(format!(
                        "NOTICE: {} mounted rw without nosuid (options: {})",
                        mount_point, options
                    ));
                }
            }
        }

        if !mount_issues.is_empty() {
            finding.details.push("".to_string());
            finding.details.push("Mount point notices:".to_string());
            finding.details.extend(mount_issues);
        }
    }

    Some(finding)
}

/// 检查是否是值得关注的挂载点
fn is_interesting_mount(mount_point: &str) -> bool {
    // 只关注用户可能利用的挂载点
    matches!(
        mount_point,
        "/tmp" | "/var/tmp" | "/dev/shm" | "/home" | "/opt" | "/usr/local"
    )
}

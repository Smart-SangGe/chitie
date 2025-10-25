use crate::{Category, Finding, Severity};
use std::fs;

///  System Information - Disks
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Check for disk information and misconfigurations
///
///  Checks for:
///  - Available disk devices in /dev
///  - Encrypted devices (crypt)
///  - Block device information
///
///  References:
///  - Writable disk devices can lead to privilege escalation
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
        "Disks",
        "Disk and block device information",
    );

    // 读取 /dev 目录中的磁盘设备
    if let Ok(entries) = fs::read_dir("/dev") {
        let mut disk_devices = Vec::new();

        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                // 查找 sd* 或 disk* 设备
                if name.starts_with("sd") || name.starts_with("disk") {
                    // 检查是否是加密设备
                    if name.contains("crypt") {
                        disk_devices.push(format!("ENCRYPTED: {}", name));
                    } else {
                        disk_devices.push(name);
                    }
                }
            }
        }

        // 限制显示前 20 个设备
        disk_devices.truncate(20);

        if !disk_devices.is_empty() {
            finding.details.push("Disk devices in /dev:".to_string());
            finding.details.extend(disk_devices);
        }
    }

    // 读取 /proc/partitions 获取分区信息
    if let Ok(partitions) = fs::read_to_string("/proc/partitions") {
        let mut partition_info = Vec::new();

        for line in partitions.lines().skip(2) {
            // 跳过头两行
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let _major = parts[0];
                let _minor = parts[1];
                let blocks = parts[2];
                let name = parts[3];

                // 只显示主设备（sd*, nvme*, vd* 等）
                if name.starts_with("sd")
                    || name.starts_with("nvme")
                    || name.starts_with("vd")
                    || name.starts_with("hd")
                {
                    partition_info.push(format!("{}: {} blocks", name, blocks));
                }
            }
        }

        if !partition_info.is_empty() {
            finding.details.push("".to_string());
            finding.details.push("Partitions:".to_string());
            finding.details.extend(partition_info);
        }
    }

    Some(finding)
}

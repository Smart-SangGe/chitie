use crate::{Category, Finding, Severity};
use std::fs;

///  System Information - Disks Extra
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Additional disk and system resource information
///
///  Checks for:
///  - Disk space utilization (df -h equivalent)
///  - Memory information (free equivalent)
///  - Low disk space warnings
///
///  References:
///  - Low disk space can be exploited for race conditions
///  - Resource exhaustion attacks
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
        "System Stats",
        "Disk and memory utilization",
    );

    // 读取磁盘使用情况 /proc/mounts + statvfs
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        let mut disk_usage = Vec::new();

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let mount_point = parts[1];

            // 只显示主要挂载点
            if !is_main_mount(mount_point) {
                continue;
            }

            // 使用 statvfs 获取磁盘使用情况
            if let Ok(stat) = nix::sys::statvfs::statvfs(mount_point) {
                let total = stat.blocks() * stat.block_size();
                let free = stat.blocks_free() * stat.block_size();
                let used = total - free;
                let used_percent = if total > 0 {
                    (used as f64 / total as f64 * 100.0) as u32
                } else {
                    0
                };

                let total_gb = total / 1024 / 1024 / 1024;
                let used_gb = used / 1024 / 1024 / 1024;
                let free_gb = free / 1024 / 1024 / 1024;

                let usage_line = format!(
                    "{}: {}G used, {}G free, {}G total ({}% used)",
                    mount_point, used_gb, free_gb, total_gb, used_percent
                );

                // 如果磁盘使用超过 90%，标记为警告
                if used_percent > 90 {
                    disk_usage.push(format!("WARNING: {}", usage_line));
                    finding.severity = Severity::Medium;
                } else {
                    disk_usage.push(usage_line);
                }
            }
        }

        if !disk_usage.is_empty() {
            finding.details.push("Disk usage:".to_string());
            finding.details.extend(disk_usage);
        }
    }

    // 读取内存信息 /proc/meminfo
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        let mut mem_total = 0u64;
        let mut mem_free = 0u64;
        let mut mem_available = 0u64;
        let mut swap_total = 0u64;
        let mut swap_free = 0u64;

        for line in meminfo.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let value = value.trim().split_whitespace().next().unwrap_or("0");
                let value_kb = value.parse::<u64>().unwrap_or(0);

                match key {
                    "MemTotal" => mem_total = value_kb,
                    "MemFree" => mem_free = value_kb,
                    "MemAvailable" => mem_available = value_kb,
                    "SwapTotal" => swap_total = value_kb,
                    "SwapFree" => swap_free = value_kb,
                    _ => {}
                }
            }
        }

        finding.details.push("".to_string());
        finding.details.push("Memory:".to_string());
        finding.details.push(format!(
            "Total: {} MB, Free: {} MB, Available: {} MB",
            mem_total / 1024,
            mem_free / 1024,
            mem_available / 1024
        ));

        if swap_total > 0 {
            finding.details.push(format!(
                "Swap: {} MB total, {} MB free",
                swap_total / 1024,
                swap_free / 1024
            ));
        } else {
            finding.details.push("Swap: none configured".to_string());
        }
    }

    Some(finding)
}

/// 检查是否是主要挂载点
fn is_main_mount(mount_point: &str) -> bool {
    matches!(
        mount_point,
        "/" | "/home" | "/boot" | "/tmp" | "/var" | "/usr" | "/opt"
    )
}

use crate::{Category, Finding, Severity};
use std::fs;

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
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "Date & Uptime",
        "System date and uptime information",
    );

    // 读取当前时间
    if let Ok(output) = std::process::Command::new("date").output()
        && output.status.success()
    {
        let date_str = String::from_utf8_lossy(&output.stdout);
        finding.details.push(format!("Date: {}", date_str.trim()));
    }

    // 读取 uptime
    if let Ok(uptime_str) = fs::read_to_string("/proc/uptime") {
        let parts: Vec<&str> = uptime_str.split_whitespace().collect();
        if let Some(uptime_secs) = parts.first()
            && let Ok(secs) = uptime_secs.parse::<f64>()
        {
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

    Some(finding)
}

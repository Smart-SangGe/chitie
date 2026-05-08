use crate::utils::command::Command;
use crate::{Category, Finding, Severity};
use std::fs;

///  Network Information - Inetd/Xinetd Services
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Analyze inetd and xinetd service configurations
///
///  Checks for:
///  - inetd configuration (/etc/inetd.conf)
///  - xinetd configuration (/etc/xinetd.conf, /etc/xinetd.d/*)
///  - Dangerous services (rsh, rlogin, telnet, ftp)
///  - Services running as root
///
///  References:
///  - Based on LinPEAS NT_Inetdconf
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Network,
        Severity::Info,
        "Inetd/Xinetd Services",
        "Internet super-server service configurations",
    );

    let mut details = Vec::new();

    // 检查inetd配置
    if let Ok(inetd_conf) = fs::read_to_string("/etc/inetd.conf") {
        details.push("=== INETD CONFIGURATION ===".to_string());
        details.push("File: /etc/inetd.conf".to_string());

        let mut dangerous_services = Vec::new();
        let mut normal_services = Vec::new();

        for line in inetd_conf.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // 检查危险服务
            if trimmed.contains("shell")
                || trimmed.contains("login")
                || trimmed.contains("exec")
                || trimmed.contains("rsh")
                || trimmed.contains("rlogin")
                || trimmed.contains("rexec")
                || trimmed.contains("telnet")
                || trimmed.contains("ftp")
                || trimmed.contains("tftp")
            {
                dangerous_services.push(format!("DANGEROUS: {}", trimmed));
            } else {
                normal_services.push(format!("  {}", trimmed));
            }
        }

        if !dangerous_services.is_empty() {
            details.push(String::new());
            details.push("Dangerous services found:".to_string());
            details.extend(dangerous_services);
            finding.severity = Severity::High;
        }

        if !normal_services.is_empty() && normal_services.len() <= 10 {
            details.push(String::new());
            details.push("Other services:".to_string());
            details.extend(normal_services);
        }

        details.push(String::new());
    }

    // 检查xinetd主配置
    if let Ok(xinetd_conf) = fs::read_to_string("/etc/xinetd.conf") {
        details.push("=== XINETD CONFIGURATION ===".to_string());
        details.push("File: /etc/xinetd.conf".to_string());

        for line in xinetd_conf.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                details.push(format!("  {}", trimmed));
            }
        }
        details.push(String::new());
    }

    // 检查xinetd服务目录
    if let Ok(entries) = fs::read_dir("/etc/xinetd.d") {
        details.push("=== XINETD SERVICES ===".to_string());
        details.push("Directory: /etc/xinetd.d/".to_string());
        details.push(String::new());

        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if let Some(service_name) = path.file_name().and_then(|n| n.to_str())
                && let Ok(content) = fs::read_to_string(&path)
            {
                let mut is_enabled = false;
                let mut runs_as_root = false;
                let mut uses_system_bin = false;

                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.contains("disable") && trimmed.contains("no") {
                        is_enabled = true;
                    }
                    if trimmed.contains("user") && trimmed.contains("root") {
                        runs_as_root = true;
                    }
                    if trimmed.contains("server")
                        && (trimmed.contains("/bin/") || trimmed.contains("/sbin/"))
                    {
                        uses_system_bin = true;
                    }
                }

                let mut warnings = Vec::new();
                if is_enabled {
                    warnings.push("ENABLED");
                    if runs_as_root {
                        warnings.push("RUNS AS ROOT");
                        finding.severity = Severity::Medium;
                    }
                    if uses_system_bin {
                        warnings.push("USES SYSTEM BINARIES");
                    }
                }

                details.push(format!(
                    "Service: {} {}",
                    service_name,
                    if warnings.is_empty() {
                        "(disabled)".to_string()
                    } else {
                        format!("[{}]", warnings.join(", "))
                    }
                ));

                if !warnings.is_empty() {
                    for line in content.lines().take(15) {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            details.push(format!("  {}", trimmed));
                        }
                    }
                    details.push(String::new());
                }
            }
        }
    }

    // 检查是否有进程在运行
    if let Ok(output) = Command::new("pgrep").args(["-l", "inetd"]).output()
        && output.status.success()
    {
        let processes = String::from_utf8_lossy(&output.stdout);
        if !processes.trim().is_empty() {
            details.push("=== RUNNING PROCESSES ===".to_string());
            for line in processes.lines() {
                details.push(format!("  {}", line));
            }
            finding.severity = Severity::Medium;
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

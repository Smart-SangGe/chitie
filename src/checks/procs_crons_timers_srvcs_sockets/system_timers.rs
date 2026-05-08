use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;

///  Processes - System Timers
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Enumerate systemd timers and check for privilege escalation vectors
///
///  Checks for:
///  - Active and disabled systemd timers
///  - Writable timer unit files
///  - Timers that run services as root
///  - Writable executables in timer services
///  - Weak permissions on timer files
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers
///  - Based on LinPEAS PR_System_timers
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Process,
        Severity::Info,
        "System Timers",
        "Systemd timers and privilege escalation vectors",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers",
    );

    let mut details = Vec::new();

    // 检查systemctl是否可用
    if Command::new("systemctl").arg("--version").output().is_err() {
        details.push("systemctl not available (not using systemd?)".to_string());
        finding.details = details;
        return Some(finding);
    }

    // 列出所有激活的timers
    details.push("=== ACTIVE TIMERS ===".to_string());
    if let Ok(output) = Command::new("systemctl")
        .args(&["list-timers", "--all", "--no-pager"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut timer_count = 0;

            for line in stdout.lines() {
                // 跳过标题和汇总行
                if line.contains("NEXT") || line.contains("timers listed") || line.trim().is_empty()
                {
                    continue;
                }

                // 提取timer名称（最后一列）
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                let timer_name = parts[parts.len() - 1];
                if !timer_name.ends_with(".timer") {
                    continue;
                }

                timer_count += 1;

                // 检查timer文件权限
                if let Ok(show_output) = Command::new("systemctl")
                    .args(&["show", timer_name, "-p", "FragmentPath"])
                    .output()
                {
                    if show_output.status.success() {
                        let fragment = String::from_utf8_lossy(&show_output.stdout);
                        if let Some(path) = fragment.strip_prefix("FragmentPath=") {
                            let path = path.trim();
                            if !path.is_empty() {
                                check_timer_file(path, timer_name, &mut details, &mut finding);
                            }
                        }
                    }
                }

                // 检查关联的service
                if let Ok(unit_output) = Command::new("systemctl")
                    .args(&["show", timer_name, "-p", "Unit"])
                    .output()
                {
                    if unit_output.status.success() {
                        let unit = String::from_utf8_lossy(&unit_output.stdout);
                        if let Some(service_name) = unit.strip_prefix("Unit=") {
                            let service_name = service_name.trim();
                            if !service_name.is_empty() && service_name != "n/a" {
                                check_timer_service(
                                    service_name,
                                    timer_name,
                                    &mut details,
                                    &mut finding,
                                );
                            }
                        }
                    }
                }

                // 添加timer基本信息
                details.push(format!("  {}", line.trim()));
            }

            if timer_count == 0 {
                details.push("No active timers found".to_string());
            }
        }
    }

    details.push(String::new());

    // 列出禁用的timers
    details.push("=== DISABLED TIMERS ===".to_string());
    if let Ok(output) = Command::new("systemctl")
        .args(&[
            "list-unit-files",
            "--type=timer",
            "--state=disabled",
            "--no-pager",
        ])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut disabled_count = 0;

            for line in stdout.lines() {
                if line.contains("UNIT FILE") || line.trim().is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                let timer_name = parts[0];
                if !timer_name.ends_with(".timer") {
                    continue;
                }

                disabled_count += 1;

                // 检查禁用timer的文件权限
                if let Ok(show_output) = Command::new("systemctl")
                    .args(&["show", timer_name, "-p", "FragmentPath"])
                    .output()
                {
                    if show_output.status.success() {
                        let fragment = String::from_utf8_lossy(&show_output.stdout);
                        if let Some(path) = fragment.strip_prefix("FragmentPath=") {
                            let path = path.trim();
                            if !path.is_empty() {
                                check_timer_file(path, timer_name, &mut details, &mut finding);
                            }
                        }
                    }
                }

                details.push(format!("  {}", timer_name));
            }

            if disabled_count == 0 {
                details.push("No disabled timers found".to_string());
            }
        }
    }

    if details.is_empty() {
        details.push("No timers found".to_string());
    }

    finding.details = details;
    Some(finding)
}

fn check_timer_file(
    timer_path: &str,
    timer_name: &str,
    details: &mut Vec<String>,
    finding: &mut Finding,
) {
    if let Ok(metadata) = fs::metadata(timer_path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();

        // 检查是否可写
        if mode & 0o022 != 0 {
            details.push(format!(
                "  ⚠ WRITABLE timer file: {} (mode: {:o})",
                timer_path,
                mode & 0o7777
            ));
            finding.severity = Severity::High;
        }

        // 检查是否是777权限
        if mode & 0o777 == 0o777 {
            details.push(format!("  ⚠ WEAK PERMS (777): {}", timer_path));
            finding.severity = Severity::High;
        }
    }

    // 检查timer文件内容
    if let Ok(content) = fs::read_to_string(timer_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            // 检查相对路径
            if trimmed.starts_with("Unit=") && !trimmed.contains("Unit=/") {
                details.push(format!("  ⚠ RELATIVE PATH in {}: {}", timer_name, trimmed));
                finding.severity = Severity::Medium;
            }
        }
    }
}

fn check_timer_service(
    service_name: &str,
    _timer_name: &str,
    details: &mut Vec<String>,
    finding: &mut Finding,
) {
    // 检查service是否以root运行
    if let Ok(output) = Command::new("systemctl")
        .args(&["show", service_name, "-p", "User"])
        .output()
    {
        if output.status.success() {
            let user = String::from_utf8_lossy(&output.stdout);
            if user.contains("User=root") || user.contains("User=") && user.trim() == "User=" {
                // User= 为空意味着以root运行
                details.push(format!("  ⚠ {} runs as ROOT", service_name));
                finding.severity = Severity::Medium;
            }
        }
    }

    // 检查ExecStart路径
    if let Ok(output) = Command::new("systemctl")
        .args(&["show", service_name, "-p", "ExecStart"])
        .output()
    {
        if output.status.success() {
            let exec_start = String::from_utf8_lossy(&output.stdout);

            // 提取可执行文件路径
            if let Some(path_part) = exec_start.split("path=").nth(1) {
                if let Some(exec_path) = path_part.split(';').next() {
                    let exec_path = exec_path.trim();

                    // 检查是否为相对路径
                    if !exec_path.starts_with('/') && !exec_path.is_empty() {
                        details.push(format!(
                            "  ⚠ RELATIVE PATH in {}: {}",
                            service_name, exec_path
                        ));
                        finding.severity = Severity::Medium;
                    }

                    // 检查可执行文件是否可写
                    if let Ok(metadata) = fs::metadata(exec_path) {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = metadata.permissions().mode();
                        if mode & 0o022 != 0 {
                            details.push(format!(
                                "  ⚠ WRITABLE executable in {}: {} (mode: {:o})",
                                service_name,
                                exec_path,
                                mode & 0o7777
                            ));
                            finding.severity = Severity::High;
                        }
                    }
                }
            }

            // 检查危险命令
            let dangerous_cmds = ["chmod", "chown", "mount", "sudo", "su"];
            for cmd in &dangerous_cmds {
                if exec_start.contains(cmd) {
                    details.push(format!(
                        "  ⚠ UNSAFE CMD in {}: contains '{}'",
                        service_name, cmd
                    ));
                    finding.severity = Severity::Medium;
                    break;
                }
            }
        }
    }
}

use crate::{Category, Finding, Severity};
use regex::Regex;
use std::fs;
use std::process::Command;

///  Processes - Services
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Enumerate systemd services and check for privilege escalation vectors
///
///  Checks for:
///  - Active and disabled systemd services
///  - Writable service unit files
///  - Services that run as root
///  - Writable executables in services
///  - Relative paths in ExecStart directives
///  - Dangerous capabilities
///  - Sensitive environment variables
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services
///  - Based on LinPEAS PR_Services
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
        "Services",
        "Systemd services and privilege escalation vectors",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services",
    );

    let mut details = Vec::new();

    // 检查systemctl是否可用
    if Command::new("systemctl")
        .arg("--version")
        .output()
        .is_err()
    {
        details.push("systemctl not available (not using systemd?)".to_string());
        finding.details = details;
        return Some(finding);
    }

    // 列出活动的services
    details.push("=== ACTIVE SERVICES ===".to_string());
    if let Ok(output) = Command::new("systemctl")
        .args(&["list-units", "--type=service", "--state=active", "--no-pager"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut service_count = 0;

            for line in stdout.lines() {
                // 跳过标题行
                if line.contains("UNIT") || line.trim().is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                let service_name = parts[0];
                if !service_name.ends_with(".service") {
                    continue;
                }

                service_count += 1;

                // 获取service文件路径并检查
                if let Ok(show_output) = Command::new("systemctl")
                    .args(&["show", service_name, "-p", "FragmentPath"])
                    .output()
                {
                    if show_output.status.success() {
                        let fragment = String::from_utf8_lossy(&show_output.stdout);
                        if let Some(path) = fragment.strip_prefix("FragmentPath=") {
                            let path = path.trim();
                            if !path.is_empty() {
                                check_service_file(path, service_name, &mut details, &mut finding);
                            }
                        }
                    }
                }

                // 检查service配置
                check_service_content(service_name, &mut details, &mut finding);

                // 限制输出数量
                if service_count > 50 {
                    details.push(format!("... and more services (showing first 50)"));
                    break;
                }
            }

            if service_count == 0 {
                details.push("No active services found".to_string());
            }
        }
    }

    details.push(String::new());

    // 列出禁用的services（简化版，不详细检查）
    details.push("=== DISABLED SERVICES (Sample) ===".to_string());
    if let Ok(output) = Command::new("systemctl")
        .args(&[
            "list-unit-files",
            "--type=service",
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

                let service_name = parts[0];
                if !service_name.ends_with(".service") {
                    continue;
                }

                disabled_count += 1;
                details.push(format!("  {}", service_name));

                // 只列举前20个禁用服务
                if disabled_count >= 20 {
                    details.push("... (showing first 20 disabled services)".to_string());
                    break;
                }
            }

            if disabled_count == 0 {
                details.push("No disabled services found".to_string());
            }
        }
    }

    if details.is_empty() {
        details.push("No services found".to_string());
    }

    finding.details = details;
    Some(finding)
}

fn check_service_file(
    service_path: &str,
    service_name: &str,
    details: &mut Vec<String>,
    finding: &mut Finding,
) {
    // 检查service文件是否存在
    if !std::path::Path::new(service_path).exists() {
        return;
    }

    // 检查文件权限
    if let Ok(metadata) = fs::metadata(service_path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();

        // 检查是否可写（非root用户）
        let current_uid = unsafe { libc::getuid() };
        if current_uid != 0 && (mode & 0o022 != 0) {
            details.push(format!(
                "  ⚠ WRITABLE service file: {} (mode: {:o})",
                service_path,
                mode & 0o7777
            ));
            finding.severity = Severity::High;
        }

        // 检查是否是777权限
        if mode & 0o777 == 0o777 {
            details.push(format!("  ⚠ WEAK PERMS (777): {}", service_path));
            finding.severity = Severity::High;
        }
    }

    // 读取并检查service文件内容
    if let Ok(content) = fs::read_to_string(service_path) {
        // 检查相对路径
        let exec_regex = Regex::new(r"^Exec[^=]*=\s*[^/]").unwrap();
        for line in content.lines() {
            let trimmed = line.trim();

            // 检查Exec指令中的相对路径
            if exec_regex.is_match(trimmed) && !trimmed.contains("=/") {
                details.push(format!(
                    "  ⚠ RELATIVE PATH in {}: {}",
                    service_name, trimmed
                ));
                finding.severity = Severity::Medium;
            }

            // 提取可执行文件路径并检查是否可写
            if trimmed.starts_with("Exec") {
                if let Some(exec_part) = trimmed.split('=').nth(1) {
                    // 去除前缀符号 (@, -, +, !)
                    let exec_path = exec_part.trim().trim_start_matches(&['@', '-', '+', '!'][..]);
                    let exec_path = exec_path.split_whitespace().next().unwrap_or("");

                    if !exec_path.is_empty() && std::path::Path::new(exec_path).exists() {
                        if let Ok(exec_meta) = fs::metadata(exec_path) {
                            use std::os::unix::fs::PermissionsExt;
                            let exec_mode = exec_meta.permissions().mode();

                            // 检查可执行文件是否可写
                            if exec_mode & 0o022 != 0 {
                                details.push(format!(
                                    "  ⚠ WRITABLE executable in {}: {} (mode: {:o})",
                                    service_name,
                                    exec_path,
                                    exec_mode & 0o7777
                                ));
                                finding.severity = Severity::High;
                            }

                            // 检查777权限
                            if exec_mode & 0o777 == 0o777 {
                                details.push(format!(
                                    "  ⚠ WEAK PERMS (777) on executable: {}",
                                    exec_path
                                ));
                                finding.severity = Severity::High;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn check_service_content(
    service_name: &str,
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
            // User=root 或者 User= (空表示root)
            if user.contains("User=root") || (user.starts_with("User=") && user.trim() == "User=")
            {
                // Service以root运行很常见，不单独报告
            }
        }
    }

    // 检查危险的capabilities
    if let Ok(output) = Command::new("systemctl")
        .args(&["show", service_name, "-p", "CapabilityBoundingSet"])
        .output()
    {
        if output.status.success() {
            let caps = String::from_utf8_lossy(&output.stdout);
            let dangerous_caps = [
                "CAP_SYS_ADMIN",
                "CAP_DAC_OVERRIDE",
                "CAP_DAC_READ_SEARCH",
            ];

            for cap in &dangerous_caps {
                if caps.contains(cap) {
                    details.push(format!("  ⚠ DANGEROUS CAP in {}: {}", service_name, cap));
                    finding.severity = Severity::Medium;
                }
            }
        }
    }

    // 检查环境变量中的敏感信息
    if let Ok(output) = Command::new("systemctl")
        .args(&["show", service_name, "-p", "Environment"])
        .output()
    {
        if output.status.success() {
            let env = String::from_utf8_lossy(&output.stdout);
            let sensitive_keywords = ["PASS", "SECRET", "KEY", "TOKEN", "CRED"];

            for keyword in &sensitive_keywords {
                if env.to_uppercase().contains(keyword) {
                    details.push(format!(
                        "  ⚠ SENSITIVE ENV in {}: contains '{}'",
                        service_name, keyword
                    ));
                    finding.severity = Severity::Medium;
                    break;
                }
            }
        }
    }

    // 检查ExecStart中的危险命令
    if let Ok(output) = Command::new("systemctl")
        .args(&["show", service_name, "-p", "ExecStart"])
        .output()
    {
        if output.status.success() {
            let exec_start = String::from_utf8_lossy(&output.stdout);
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

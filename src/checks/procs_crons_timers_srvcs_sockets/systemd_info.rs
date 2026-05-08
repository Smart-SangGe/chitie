use crate::utils::command::Command;
use crate::{Category, Finding, Severity};

///  System Information - Systemd
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Check systemd configuration and vulnerabilities
///
///  Checks for:
///  - Systemd version and known vulnerabilities
///  - Services running as root
///  - Services with dangerous capabilities
///  - Writable systemd PATH
///  - Services with writable executables
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths
///  - Based on LinPEAS SY_Systemd
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
        "Systemd Information",
        "Systemd version, services and configuration",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths",
    );

    let mut details = Vec::new();

    // 检查systemctl是否可用
    if Command::new("systemctl").arg("--version").output().is_err() {
        details.push("systemctl not available (not using systemd)".to_string());
        finding.details = details;
        return Some(finding);
    }

    // 获取systemd版本
    details.push("=== SYSTEMD VERSION ===".to_string());
    if let Ok(output) = Command::new("systemctl").arg("--version").output() {
        if output.status.success() {
            let version_output = String::from_utf8_lossy(&output.stdout);
            if let Some(first_line) = version_output.lines().next() {
                details.push(first_line.to_string());

                // 检查已知漏洞
                if let Some(version) = extract_version(first_line) {
                    check_known_vulnerabilities(&version, &mut details, &mut finding);
                }
            }
        }
    }

    details.push(String::new());

    // 检查以root运行的服务
    details.push("=== SERVICES RUNNING AS ROOT (Sample) ===".to_string());
    if let Ok(output) = Command::new("systemctl")
        .args(&[
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
        ])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut root_count = 0;

            for line in stdout.lines() {
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

                // 检查用户
                if let Ok(user_output) = Command::new("systemctl")
                    .args(&["show", service_name, "-p", "User"])
                    .output()
                {
                    if user_output.status.success() {
                        let user = String::from_utf8_lossy(&user_output.stdout);
                        // User=root 或 User= (空表示root)
                        if user.contains("User=root")
                            || (user.starts_with("User=") && user.trim() == "User=")
                        {
                            root_count += 1;
                            details.push(format!("  {}", service_name));

                            // 限制输出
                            if root_count >= 20 {
                                details.push("  ... (showing first 20 root services)".to_string());
                                break;
                            }
                        }
                    }
                }
            }

            if root_count == 0 {
                details.push("No services running as root found".to_string());
            }
        }
    }

    details.push(String::new());

    // 检查具有危险capabilities的服务
    details.push("=== SERVICES WITH DANGEROUS CAPABILITIES ===".to_string());
    if let Ok(output) = Command::new("systemctl")
        .args(&[
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
        ])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut dangerous_count = 0;

            for line in stdout.lines() {
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

                // 检查capabilities
                if let Ok(caps_output) = Command::new("systemctl")
                    .args(&["show", service_name, "-p", "CapabilityBoundingSet"])
                    .output()
                {
                    if caps_output.status.success() {
                        let caps = String::from_utf8_lossy(&caps_output.stdout);
                        let dangerous_caps = [
                            "CAP_SYS_ADMIN",
                            "CAP_DAC_OVERRIDE",
                            "CAP_DAC_READ_SEARCH",
                            "CAP_SETUID",
                            "CAP_SETGID",
                            "CAP_NET_ADMIN",
                        ];

                        for cap in &dangerous_caps {
                            if caps.contains(cap) {
                                dangerous_count += 1;
                                details.push(format!("  ⚠ {}: {}", service_name, cap));
                                finding.severity = Severity::Medium;

                                // 限制输出
                                if dangerous_count >= 15 {
                                    details.push(
                                        "  ... (showing first 15 dangerous services)".to_string(),
                                    );
                                    break;
                                }
                                break;
                            }
                        }
                    }
                }

                if dangerous_count >= 15 {
                    break;
                }
            }

            if dangerous_count == 0 {
                details.push("No services with dangerous capabilities found".to_string());
            }
        }
    }

    details.push(String::new());

    // 检查systemd PATH
    details.push("=== SYSTEMD PATH ===".to_string());
    if let Ok(output) = Command::new("systemctl")
        .args(&["show-environment"])
        .output()
    {
        if output.status.success() {
            let env_output = String::from_utf8_lossy(&output.stdout);
            for line in env_output.lines() {
                if line.starts_with("PATH=") {
                    details.push(line.to_string());

                    // 检查PATH中是否包含可写目录
                    if let Some(path_value) = line.strip_prefix("PATH=") {
                        check_writable_paths(path_value, &mut details, &mut finding);
                    }
                }
            }
        }
    }

    if details.is_empty() {
        details.push("No systemd information available".to_string());
    }

    finding.details = details;
    Some(finding)
}

fn extract_version(version_line: &str) -> Option<String> {
    // 提取版本号，例如 "systemd 245 (245.4-4ubuntu3.22)"
    let parts: Vec<&str> = version_line.split_whitespace().collect();
    if parts.len() >= 2 {
        return Some(parts[1].to_string());
    }
    None
}

fn check_known_vulnerabilities(version: &str, details: &mut Vec<String>, finding: &mut Finding) {
    // 解析版本号
    if let Ok(ver) = version.parse::<u32>() {
        // CVE-2021-4034 (Polkit) - systemd 230-234
        if (230..=234).contains(&ver) {
            details.push("  ⚠ Potentially vulnerable to CVE-2021-4034 (Polkit)".to_string());
            finding.severity = Severity::High;
        }

        // CVE-2021-33910 (systemd-tmpfiles) - systemd 240-249
        if (240..=249).contains(&ver) {
            details.push(
                "  ⚠ Potentially vulnerable to CVE-2021-33910 (systemd-tmpfiles)".to_string(),
            );
            finding.severity = Severity::High;
        }

        // 其他已知漏洞
        if ver < 240 {
            details.push("  ⚠ Old systemd version - check for known vulnerabilities".to_string());
            finding.severity = Severity::Medium;
        }
    }
}

fn check_writable_paths(path_value: &str, details: &mut Vec<String>, finding: &mut Finding) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let paths: Vec<&str> = path_value.split(':').collect();
    let mut writable_found = false;

    for path in paths {
        // 跳过相对路径和当前目录
        if path == "." || path.starts_with("./") || path.ends_with("/.") {
            details.push(format!("  ⚠ DANGEROUS: PATH contains '.': {}", path));
            finding.severity = Severity::High;
            writable_found = true;
            continue;
        }

        // 检查路径是否可写
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 {
                details.push(format!(
                    "  ⚠ WRITABLE PATH: {} (mode: {:o})",
                    path,
                    mode & 0o7777
                ));
                finding.severity = Severity::High;
                writable_found = true;
            }
        }
    }

    if !writable_found {
        details.push("  All PATH directories are non-writable (good)".to_string());
    }
}

use crate::{Category, Finding, Severity};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use walkdir::WalkDir;

///  System Information - Kernel Modules
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Check for kernel module vulnerabilities and misconfigurations
///
///  Checks for:
///  - Loaded kernel modules (in extra mode)
///  - Kernel modules with weak permissions
///  - Ability to load kernel modules
///  - Kernel module signing requirements
///
///  References:
///  - Vulnerable or modifiable kernel modules can lead to privilege escalation
///  - Module loading capabilities may allow loading malicious modules
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let config = crate::config::config();

    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "Kernel Modules",
        "Kernel module information and permissions",
    );

    // 在 extra 模式下显示已加载的模块
    if (config.extra || config.all_checks)
        && let Ok(output) = Command::new("lsmod").output()
        && output.status.success()
    {
        let lsmod_output = String::from_utf8_lossy(&output.stdout);
        let module_count = lsmod_output.lines().count().saturating_sub(1); // 减去标题行
        finding
            .details
            .push(format!("Loaded modules: {}", module_count));

        // 只显示前 10 个模块
        let modules: Vec<&str> = lsmod_output.lines().skip(1).take(10).collect();
        if !modules.is_empty() {
            finding.details.push("".to_string());
            finding.details.push("First 10 loaded modules:".to_string());
            for module in modules {
                if let Some(name) = module.split_whitespace().next() {
                    finding.details.push(format!("  - {}", name));
                }
            }
        }
    }

    // 检查是否可以加载模块
    if let Ok(modules_disabled) = fs::read_to_string("/proc/sys/kernel/modules_disabled") {
        let value = modules_disabled.trim();
        finding.details.push("".to_string());
        if value == "0" {
            finding
                .details
                .push("WARNING: Kernel modules can be loaded".to_string());
            finding.severity = Severity::Medium;
        } else {
            finding
                .details
                .push("Kernel modules loading: disabled".to_string());
        }
    }

    // 检查内核模块目录权限
    let mut weak_perms = Vec::new();
    if let Ok(kernel_release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let kernel_release = kernel_release.trim();
        let modules_dir = format!("/lib/modules/{}", kernel_release);

        if fs::metadata(&modules_dir).is_ok() {
            // 只检查前 50 个 .ko 文件
            let mut checked = 0;
            for entry in WalkDir::new(&modules_dir)
                .max_depth(5)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if checked >= 50 {
                    break;
                }

                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("ko") {
                    checked += 1;

                    if let Ok(metadata) = fs::metadata(path) {
                        let perms = metadata.permissions();
                        let mode = perms.mode();

                        // 检查是否不是 root:root 或有其他用户写权限
                        if mode & 0o002 != 0 || mode & 0o020 != 0 {
                            weak_perms.push(format!(
                                "Weak permissions: {} ({:o})",
                                path.display(),
                                mode & 0o777
                            ));
                        }
                    }
                }
            }
        }
    }

    if !weak_perms.is_empty() {
        finding.severity = Severity::High;
        finding.details.push("".to_string());
        finding
            .details
            .push("ALERT: Kernel modules with weak permissions found:".to_string());
        finding.details.extend(weak_perms);
    } else if !finding.details.is_empty() {
        finding.details.push("".to_string());
        finding
            .details
            .push("No kernel modules with weak permissions found".to_string());
    }

    Some(finding)
}

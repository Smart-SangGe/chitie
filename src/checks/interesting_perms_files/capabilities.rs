use crate::utils::command::Command;
use crate::{Category, Finding, Severity};

///  Interesting Permissions - Capabilities
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Find files with dangerous capabilities
///
///  Checks for:
///  - Files with capabilities set
///  - Dangerous capabilities (CAP_SETUID, CAP_SETGID, CAP_SYS_ADMIN, etc.)
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "Capabilities",
        "Files with Linux capabilities",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities",
    );

    // 使用 getcap 搜索具有 capabilities 的文件
    let search_paths = vec!["/usr", "/bin", "/sbin", "/opt"];

    let mut capabilities_found = Vec::new();
    let mut dangerous_caps = Vec::new();

    let dangerous_cap_names = [
        "cap_setuid",
        "cap_setgid",
        "cap_sys_admin",
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_fowner",
        "cap_sys_ptrace",
        "cap_sys_module",
    ];

    for search_path in search_paths {
        if let Ok(output) = Command::new("getcap").args(["-r", search_path]).output()
            && output.status.success()
        {
            let getcap_output = String::from_utf8_lossy(&output.stdout);
            for line in getcap_output.lines() {
                if line.trim().is_empty() {
                    continue;
                }

                // 检查是否包含危险 capability
                let is_dangerous = dangerous_cap_names
                    .iter()
                    .any(|&cap| line.to_lowercase().contains(cap));

                if is_dangerous {
                    dangerous_caps.push(format!("DANGEROUS: {}", line));
                    finding.severity = Severity::High;
                } else {
                    capabilities_found.push(line.to_string());
                }
            }
        }
    }

    if dangerous_caps.is_empty() && capabilities_found.is_empty() {
        return None;
    }

    if !dangerous_caps.is_empty() {
        finding
            .details
            .push("=== DANGEROUS CAPABILITIES ===".to_string());
        finding.details.extend(dangerous_caps);
        finding.details.push("".to_string());
    }

    if !capabilities_found.is_empty() {
        finding
            .details
            .push("=== OTHER CAPABILITIES ===".to_string());
        finding
            .details
            .extend(capabilities_found.iter().take(20).cloned());
        if capabilities_found.len() > 20 {
            finding
                .details
                .push(format!("... and {} more", capabilities_found.len() - 20));
        }
    }

    Some(finding)
}

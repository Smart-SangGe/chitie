use crate::{Category, Finding, Severity};
use std::process::Command;

///  System Information - Dmesg
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Check for kernel signature verification failures
///
///  Checks for:
///  - Failed kernel module signature verifications
///  - Disabled kernel module signing
///  - Unsigned kernel modules
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed
///  - Signature verification failures may allow loading malicious kernel modules
///
///  Execution Mode:
///  - Default: no
///  - Stealth (-s): no
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    // 尝试读取 dmesg
    let output = Command::new("dmesg").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let dmesg_output = String::from_utf8_lossy(&output.stdout);

    // 搜索签名相关的行
    let signature_lines: Vec<&str> = dmesg_output
        .lines()
        .filter(|line| {
            line.to_lowercase().contains("signature")
                || line.to_lowercase().contains("verification failed")
        })
        .collect();

    if signature_lines.is_empty() {
        return None;
    }

    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "Kernel Messages",
        "Signature verification information in dmesg",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed");

    // 检查是否有失败的签名验证
    let mut has_failures = false;
    for line in &signature_lines {
        if line.to_lowercase().contains("failed") || line.to_lowercase().contains("error") {
            has_failures = true;
            finding
                .details
                .push(format!("WARNING: {}", line.trim()));
        } else {
            finding.details.push(line.trim().to_string());
        }
    }

    if has_failures {
        finding.severity = Severity::High;
        finding.description = "Kernel signature verification failures detected!".to_string();
        finding.details.insert(
            0,
            "ALERT: Failed signature verifications may allow loading unsigned kernel modules"
                .to_string(),
        );
    }

    Some(finding)
}

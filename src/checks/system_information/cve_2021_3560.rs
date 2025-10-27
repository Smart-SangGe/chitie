use crate::{Category, Finding, Severity};
use std::process::Command;

///  System Information - CVE-2021-3560
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Check for Polkit vulnerability (CVE-2021-3560)
///
///  Vulnerable versions:
///  - polkit 0.105-26 (Ubuntu)
///  - polkit 0.117-2 (RHEL)
///  - polkit 0.115-6 (RHEL)
///
///  References:
///  - CVE-2021-3560: Race condition in Polkit authentication
///  - Allows unprivileged users to gain root privileges
///
///  Execution Mode:
///  - Default: no
///  - Stealth (-s): no
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut is_vulnerable = false;

    // 检查 apt (Debian/Ubuntu)
    if let Ok(output) = Command::new("apt").args(["list", "--installed"]).output()
        && output.status.success()
    {
        let apt_output = String::from_utf8_lossy(&output.stdout);
        if apt_output.contains("polkit") && apt_output.contains("0.105-26") {
            is_vulnerable = true;
        }
    }

    // 检查 yum (RHEL/CentOS)
    if !is_vulnerable
        && let Ok(output) = Command::new("yum").args(["list", "installed"]).output()
        && output.status.success()
    {
        let yum_output = String::from_utf8_lossy(&output.stdout);
        if yum_output.contains("polkit")
            && (yum_output.contains("0.117-2") || yum_output.contains("0.115-6"))
        {
            is_vulnerable = true;
        }
    }

    // 检查 rpm
    if !is_vulnerable
        && let Ok(output) = Command::new("rpm").args(["-qa"]).output()
        && output.status.success()
    {
        let rpm_output = String::from_utf8_lossy(&output.stdout);
        for line in rpm_output.lines() {
            if line.contains("polkit") && (line.contains("0.117-2") || line.contains("0.115-6")) {
                is_vulnerable = true;
                break;
            }
        }
    }

    if !is_vulnerable {
        return None;
    }

    let mut finding = Finding::new(
        Category::System,
        Severity::Critical,
        "CVE-2021-3560",
        "CRITICAL: System vulnerable to Polkit CVE-2021-3560",
    )
    .with_reference(
        "https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/",
    );

    finding
        .details
        .push("ALERT: Vulnerable Polkit version detected!".to_string());
    finding
        .details
        .push("CVE-2021-3560: Race condition in Polkit authentication".to_string());
    finding
        .details
        .push("Impact: Unprivileged users can gain root privileges".to_string());
    finding.details.push("".to_string());
    finding.details.push("Vulnerable versions:".to_string());
    finding
        .details
        .push("  - polkit 0.105-26 (Ubuntu)".to_string());
    finding
        .details
        .push("  - polkit 0.117-2 (RHEL)".to_string());
    finding
        .details
        .push("  - polkit 0.115-6 (RHEL)".to_string());
    finding.details.push("".to_string());
    finding
        .details
        .push("Recommendation: Update Polkit immediately".to_string());

    Some(finding)
}

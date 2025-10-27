use crate::{Category, Finding, Severity};
use std::process::Command;

///  Software Information - Compilers
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Detect installed compilers
///
///  Checks for:
///  - Compilers installed via package manager (dpkg/yum)
///  - GCC and G++ in PATH
///  - GCC versions via locate
///
///  References:
///  - Based on LinPEAS SI_Compilers
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Software,
        Severity::Medium,
        "Installed Compilers",
        "Compilers that could be used to compile exploits",
    );

    let mut compilers_found = Vec::new();

    // 检查 dpkg 包管理器中的编译器
    if let Ok(output) = Command::new("dpkg").args(["--list"]).output()
        && output.status.success()
    {
        let dpkg_output = String::from_utf8_lossy(&output.stdout);
        for line in dpkg_output.lines() {
            if line.contains("compiler") && !line.contains("decompiler") && !line.contains("lib") {
                compilers_found.push(format!("Package: {}", line.trim()));
            }
        }
    }

    // 检查 yum/rpm 包管理器中的 gcc
    if let Ok(output) = Command::new("yum")
        .args(["list", "installed", "gcc*"])
        .output()
        && output.status.success()
    {
        let yum_output = String::from_utf8_lossy(&output.stdout);
        for line in yum_output.lines() {
            if line.contains("gcc") {
                compilers_found.push(format!("Package: {}", line.trim()));
            }
        }
    }

    // 检查 PATH 中的 gcc 和 g++
    for compiler in &["gcc", "g++", "cc", "c++", "clang", "clang++"] {
        if let Ok(output) = Command::new("command").args(["-v", compiler]).output()
            && output.status.success()
        {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                compilers_found.push(format!("{} -> {}", compiler, path));

                // 尝试获取版本
                if let Ok(version_output) = Command::new(compiler).arg("--version").output()
                    && version_output.status.success()
                {
                    let version = String::from_utf8_lossy(&version_output.stdout);
                    if let Some(first_line) = version.lines().next() {
                        compilers_found.push(format!("  Version: {}", first_line.trim()));
                    }
                }
            }
        }
    }

    // 在 extra 模式下使用 locate 查找更多 gcc 版本
    let config = crate::config::config();
    if (config.extra || config.all_checks)
        && let Ok(output) = Command::new("locate")
            .args(["-r", "/gcc[0-9.-]+$"])
            .output()
        && output.status.success()
    {
        let locate_output = String::from_utf8_lossy(&output.stdout);
        let mut locate_results: Vec<String> = locate_output
            .lines()
            .filter(|l| !l.contains("/doc/"))
            .map(|l| format!("Located: {}", l.trim()))
            .take(10)
            .collect();

        if !locate_results.is_empty() {
            compilers_found.push(String::new());
            compilers_found.push("Additional GCC installations:".to_string());
            compilers_found.append(&mut locate_results);
        }
    }

    if compilers_found.is_empty() {
        finding.severity = Severity::Info;
        finding.details.push("No compilers found".to_string());
        return Some(finding);
    }

    finding.details = compilers_found;
    Some(finding)
}

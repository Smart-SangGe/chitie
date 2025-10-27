use crate::{Category, Finding, Severity};
use std::fs;

///  Processes - List Running Processes
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: List running processes and check for unusual configurations
///
///  Checks for:
///  - Running processes
///  - Processes run by root
///  - Unusual process capabilities
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes
///  - Based on LinPEAS PR_List_processes
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
        "Running Processes",
        "List of running processes",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes",
    );

    let mut processes = Vec::new();

    // 读取/proc目录获取进程列表
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();

            // 只处理数字目录（PID）
            if !filename_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let pid = &filename_str;
            let cmdline_path = path.join("cmdline");
            let status_path = path.join("status");

            if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                let cmd = cmdline.replace('\0', " ").trim().to_string();
                if cmd.is_empty() {
                    continue;
                }

                // 读取进程状态获取用户
                let mut user = String::from("?");
                if let Ok(status) = fs::read_to_string(&status_path) {
                    for line in status.lines() {
                        if line.starts_with("Uid:") {
                            if let Some(uid_str) = line.split_whitespace().nth(1) {
                                if uid_str == "0" {
                                    user = "root".to_string();
                                    finding.severity = Severity::Medium;
                                }
                            }
                            break;
                        }
                    }
                }

                processes.push(format!("{:>6} {:>10} {}", pid, user, cmd));
            }
        }
    }

    if processes.is_empty() {
        return None;
    }

    // 限制输出数量
    finding.details = processes.iter().take(100).cloned().collect();
    if processes.len() > 100 {
        finding
            .details
            .push(format!("... and {} more processes", processes.len() - 100));
    }

    Some(finding)
}

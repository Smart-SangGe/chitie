use crate::{Category, Finding, Severity};
use std::collections::HashMap;
use std::fs;

///  Processes - PPID Different User
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Find processes whose parent process belongs to a different user
///
///  Checks for:
///  - Child processes running as different user than parent
///  - Potential privilege escalation vectors
///  - User spawning processes as different users
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes
///  - Based on LinPEAS PR_Processes_PPID_different_user
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
        "Processes with PPID Different User",
        "Processes whose parent belongs to a different user",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes",
    );

    let mut details = Vec::new();
    let mut uid_cache: HashMap<u32, String> = HashMap::new();

    // 读取 /etc/passwd 构建 UID -> 用户名映射
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(uid) = parts[2].parse::<u32>() {
                    uid_cache.insert(uid, parts[0].to_string());
                }
            }
        }
    }

    // 遍历所有进程
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.filter_map(Result::ok) {
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();

            // 只处理数字目录（PID）
            if !filename_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let pid = filename_str.to_string();
            let status_path = entry.path().join("status");

            // 读取进程状态
            if let Ok(status) = fs::read_to_string(&status_path) {
                let mut proc_uid: Option<u32> = None;
                let mut ppid: Option<String> = None;

                for line in status.lines() {
                    if line.starts_with("Uid:") {
                        if let Some(uid_str) = line.split_whitespace().nth(1) {
                            proc_uid = uid_str.parse().ok();
                        }
                    } else if line.starts_with("PPid:") {
                        if let Some(ppid_str) = line.split_whitespace().nth(1) {
                            ppid = Some(ppid_str.to_string());
                        }
                    }
                }

                // 如果找到了进程UID和PPID
                if let (Some(proc_uid), Some(ppid)) = (proc_uid, ppid) {
                    if ppid == "0" {
                        continue; // 跳过PPID为0的进程
                    }

                    // 读取父进程的UID
                    let parent_status_path = format!("/proc/{}/status", ppid);
                    if let Ok(parent_status) = fs::read_to_string(&parent_status_path) {
                        for line in parent_status.lines() {
                            if line.starts_with("Uid:") {
                                if let Some(parent_uid_str) = line.split_whitespace().nth(1) {
                                    if let Ok(parent_uid) = parent_uid_str.parse::<u32>() {
                                        // 检查用户是否不同，且父进程不是root
                                        if proc_uid != parent_uid && parent_uid != 0 {
                                            let proc_user = uid_cache
                                                .get(&proc_uid)
                                                .map(|s| s.as_str())
                                                .unwrap_or("?");
                                            let parent_user = uid_cache
                                                .get(&parent_uid)
                                                .map(|s| s.as_str())
                                                .unwrap_or("?");

                                            details.push(format!(
                                                "PID {} (user: {}) parent PID {} (user: {})",
                                                pid, proc_user, ppid, parent_user
                                            ));

                                            finding.severity = Severity::Medium;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if details.is_empty() {
        details.push("No processes found with different user than parent".to_string());
    }

    finding.details = details;
    Some(finding)
}

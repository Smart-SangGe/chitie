use crate::{Category, Finding, Severity};
use std::collections::HashMap;
use std::fs;

///  Processes - Files Opened by Other Users
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Files opened by processes belonging to other users
///
///  Checks for:
///  - Files accessible by processes owned by other users
///  - Potential information disclosure
///  - Shared file access between users
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes
///  - Based on LinPEAS PR_Files_open_process_other_user
///
///  Note: This check usually returns empty results for non-root users
///  due to lack of permissions to read other processes' file descriptors
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
        "Files Opened by Other Users",
        "Files opened by processes belonging to other users",
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

    // 获取当前用户UID
    let current_uid = unsafe { libc::getuid() };

    // 检查是否为root
    if current_uid == 0 {
        details.push("Running as root - skipping this check".to_string());
        finding.details = details;
        return Some(finding);
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

            let pid = &filename_str;
            let proc_path = entry.path();
            let status_path = proc_path.join("status");
            let fd_path = proc_path.join("fd");

            // 检查是否可以访问此进程
            if !status_path.exists() || !fd_path.exists() {
                continue;
            }

            // 读取进程UID
            if let Ok(status) = fs::read_to_string(&status_path) {
                let mut proc_uid: Option<u32> = None;

                for line in status.lines() {
                    if line.starts_with("Uid:") {
                        if let Some(uid_str) = line.split_whitespace().nth(1) {
                            proc_uid = uid_str.parse().ok();
                            break;
                        }
                    }
                }

                // 跳过当前用户的进程
                if proc_uid == Some(current_uid) {
                    continue;
                }

                // 获取进程用户名
                let user = proc_uid
                    .and_then(|uid| uid_cache.get(&uid))
                    .map(|s| s.as_str())
                    .unwrap_or("?");

                // 读取进程命令行
                let cmdline_path = proc_path.join("cmdline");
                let cmd = if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                    let cmd = cmdline.replace('\0', " ");
                    if cmd.len() > 100 {
                        format!("{}...", &cmd[..100])
                    } else {
                        cmd
                    }
                } else {
                    continue;
                };

                if cmd.is_empty() {
                    continue;
                }

                // 遍历文件描述符
                if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                    let mut process_files = Vec::new();

                    for fd_entry in fd_entries.filter_map(Result::ok) {
                        let fd_link = fd_entry.path();

                        // 读取符号链接目标
                        if let Ok(target) = fs::read_link(&fd_link) {
                            let target_str = target.to_string_lossy();

                            // 跳过特殊文件
                            if target_str.starts_with("/dev/")
                                || target_str.starts_with("/proc/")
                                || target_str.starts_with("/sys/")
                            {
                                continue;
                            }

                            // 检查目标是否存在
                            if target.exists() {
                                process_files.push(target_str.to_string());
                                finding.severity = Severity::Medium;
                            }
                        }
                    }

                    // 如果找到了打开的文件
                    if !process_files.is_empty() {
                        details.push(format!("Process {} (user: {}) - {}", pid, user, cmd));
                        for file in process_files {
                            details.push(format!("  └─ {}", file));
                        }
                    }
                }
            }
        }
    }

    if details.is_empty() {
        details.push(
            "No accessible files opened by other users' processes (expected for non-root)"
                .to_string(),
        );
    }

    finding.details = details;
    Some(finding)
}

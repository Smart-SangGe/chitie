use crate::{Category, Finding, Severity};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

///  Processes - Process Binary Permissions
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Check the permissions of the binaries of running processes
///
///  Checks for:
///  - Writable process binaries (potential binary replacement attack)
///  - Process binaries not owned by root
///  - Process binaries owned by other users
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes
///  - Based on LinPEAS PR_Process_binaries_perms
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
        "Process Binary Permissions",
        "Permissions of running process binaries",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes",
    );

    let mut details = Vec::new();
    let mut seen_binaries = HashSet::new();

    // 获取当前用户
    let current_uid = nix::unistd::getuid().as_raw();

    // 遍历所有进程
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.filter_map(Result::ok) {
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();

            // 只处理数字目录（PID）
            if !filename_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let exe_path = entry.path().join("exe");

            // 读取进程可执行文件路径
            if let Ok(real_path) = fs::read_link(&exe_path) {
                let path_str = real_path.to_string_lossy().to_string();

                // 跳过已经检查过的二进制文件
                if seen_binaries.contains(&path_str) {
                    continue;
                }
                seen_binaries.insert(path_str.clone());

                // 检查文件是否存在
                if !Path::new(&path_str).exists() {
                    continue;
                }

                // 获取文件元数据
                if let Ok(metadata) = fs::metadata(&path_str) {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = metadata.permissions().mode();
                    let uid = metadata.uid();
                    let gid = metadata.gid();

                    // 跳过 root:root 所有的文件（除非可写）
                    let is_root_owned = uid == 0 && gid == 0;
                    let is_current_user = uid == current_uid;

                    // 检查是否可写
                    let is_writable = mode & 0o022 != 0; // world or group writable

                    // 如果是root所有且不可写，跳过
                    if is_root_owned && !is_writable {
                        continue;
                    }

                    // 如果是当前用户且不可写，跳过
                    if is_current_user && !is_writable {
                        continue;
                    }

                    // 构建详细信息
                    let mut line = format!("{:o} uid:{} gid:{} {}", mode & 0o7777, uid, gid, path_str);

                    // 标记可写文件为高危
                    if is_writable {
                        line = format!("WRITABLE: {}", line);
                        finding.severity = Severity::High;
                    } else if !is_root_owned {
                        // 非root所有的进程二进制文件
                        finding.severity = Severity::Medium;
                    }

                    details.push(line);
                }
            }
        }
    }

    if details.is_empty() {
        details.push("All process binaries are properly owned (root:root)".to_string());
    }

    // 按路径排序
    details.sort();

    finding.details = details;
    Some(finding)
}

use crate::{Category, Finding, Severity};
use nix::unistd::getuid;
use std::env;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use walkdir::WalkDir;

///  Interesting Files - .sh files in PATH
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Find .sh script files in PATH directories
///
///  Checks for:
///  - Shell scripts (.sh) in PATH
///  - Owned or writable shell scripts
///  - Broken symbolic links in PATH
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path
///  - Based on LinPEAS IF_Sh_files_in_PATH
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Shell Scripts in PATH",
        "Shell script files in PATH directories",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path",
    );

    let mut sh_files = Vec::new();
    let mut owned_files = Vec::new();
    let mut writable_files = Vec::new();
    let mut broken_links = Vec::new();

    // 获取当前用户 UID
    let current_uid = getuid().as_raw();
    let is_root = current_uid == 0;

    // 解析 PATH
    if let Ok(path_var) = env::var("PATH") {
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }

            // 查找 .sh 文件
            for entry in WalkDir::new(dir)
                .max_depth(1)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                // 检查是否是 .sh 文件
                if (filename.ends_with(".sh") || filename.contains(".sh."))
                    && let Ok(metadata) = fs::metadata(path)
                {
                    let mode = metadata.permissions().mode();
                    let owner_uid = metadata.uid();
                    let path_str = path.display().to_string();

                    // 检查是否拥有或可写
                    if !is_root {
                        if owner_uid == current_uid {
                            owned_files.push(format!("OWNED: {}", path_str));
                            finding.severity = Severity::High;
                            continue;
                        } else if (mode & 0o002 != 0) || (mode & 0o020 != 0) {
                            writable_files.push(format!("WRITABLE: {}", path_str));
                            finding.severity = Severity::High;
                            continue;
                        }
                    }

                    sh_files.push(path_str);
                }

                // 检查断开的符号链接
                if path.is_symlink() && fs::read_link(path).is_ok() && fs::metadata(path).is_err() {
                    broken_links.push(format!("Broken link: {}", path.display()));
                }
            }
        }
    }

    // 构建输出
    if !owned_files.is_empty() {
        finding
            .details
            .push("=== OWNED SHELL SCRIPTS (CRITICAL) ===".to_string());
        finding.details.extend(owned_files);
        finding.details.push(String::new());
    }

    if !writable_files.is_empty() {
        finding
            .details
            .push("=== WRITABLE SHELL SCRIPTS (CRITICAL) ===".to_string());
        finding.details.extend(writable_files);
        finding.details.push(String::new());
    }

    if !sh_files.is_empty() {
        finding
            .details
            .push("=== SHELL SCRIPTS IN PATH ===".to_string());
        finding.details.extend(sh_files.iter().take(20).cloned());
        if sh_files.len() > 20 {
            finding
                .details
                .push(format!("... and {} more", sh_files.len() - 20));
        }
        finding.details.push(String::new());
    }

    if !broken_links.is_empty() {
        finding
            .details
            .push("=== BROKEN SYMBOLIC LINKS ===".to_string());
        finding
            .details
            .extend(broken_links.iter().take(10).cloned());
        if broken_links.len() > 10 {
            finding
                .details
                .push(format!("... and {} more", broken_links.len() - 10));
        }
    }

    if finding.details.is_empty() {
        return None;
    }

    Some(finding)
}

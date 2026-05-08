use crate::{Category, Finding, Severity};
use regex::Regex;
use std::fs;

///  Processes - Socket Files
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Analyze systemd socket files for privilege escalation vectors
///
///  Checks for:
///  - Writable .socket files
///  - Socket files with writable executables
///  - Socket files with writable listeners
///  - Relative paths in socket configuration
///  - Unsafe socket configurations (root, dangerous caps)
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets
///  - Based on LinPEAS PR_Socket_files
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
        "Socket Files",
        "Systemd socket files analysis",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets",
    );

    let mut details = Vec::new();
    let current_uid = nix::unistd::getuid().as_raw();

    // 如果是root用户，跳过此检查
    if current_uid == 0 {
        details.push("Running as root - skipping socket file checks".to_string());
        finding.details = details;
        return Some(finding);
    }

    // 搜索.socket文件
    let socket_dirs = vec![
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/system",
    ];

    let mut socket_files = Vec::new();
    for dir in socket_dirs {
        if let Ok(walker) = std::fs::read_dir(dir) {
            for entry in walker.filter_map(Result::ok) {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "socket" {
                        socket_files.push(path);
                    }
                }
            }
        }
    }

    if socket_files.is_empty() {
        details.push("No socket files found".to_string());
        finding.details = details;
        return Some(finding);
    }

    details.push(format!("=== FOUND {} SOCKET FILES ===", socket_files.len()));

    // 检查每个socket文件
    for socket_file in socket_files.iter().take(30) {
        // 限制检查数量
        let path_str = socket_file.to_string_lossy();
        check_socket_file(&path_str, &mut details, &mut finding);
    }

    if socket_files.len() > 30 {
        details.push(format!(
            "... and {} more socket files (showing first 30)",
            socket_files.len() - 30
        ));
    }

    if details.len() == 1 {
        // 只有标题，没有发现问题
        details.push("All socket files appear properly configured".to_string());
    }

    finding.details = details;
    Some(finding)
}

fn check_socket_file(socket_path: &str, details: &mut Vec<String>, finding: &mut Finding) {
    let mut issues = Vec::new();

    // 检查文件权限
    if let Ok(metadata) = fs::metadata(socket_path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();

        // 检查是否可写
        if mode & 0o022 != 0 {
            issues.push(format!("WRITABLE file (mode: {:o})", mode & 0o7777));
            finding.severity = Severity::High;
        }

        // 检查是否是777权限
        if mode & 0o777 == 0o777 {
            issues.push("WEAK PERMS (777)".to_string());
            finding.severity = Severity::High;
        }
    }

    // 读取并分析文件内容
    if let Ok(content) = fs::read_to_string(socket_path) {
        // 提取可执行文件路径
        let exec_regex = Regex::new(r"^Exec[^=]*=\s*[@+!-]*(.+)$").unwrap();
        for line in content.lines() {
            let trimmed = line.trim();

            // 检查Exec指令
            if let Some(caps) = exec_regex.captures(trimmed) {
                if let Some(exec_match) = caps.get(1) {
                    let exec_path = exec_match.as_str().trim();
                    let exec_path = exec_path.split_whitespace().next().unwrap_or("");

                    if !exec_path.is_empty() {
                        // 检查相对路径
                        if !exec_path.starts_with('/') {
                            issues.push(format!("RELATIVE PATH: {}", exec_path));
                            finding.severity = Severity::Medium;
                        }

                        // 检查可执行文件是否可写
                        if std::path::Path::new(exec_path).exists() {
                            if let Ok(exec_meta) = fs::metadata(exec_path) {
                                use std::os::unix::fs::PermissionsExt;
                                let exec_mode = exec_meta.permissions().mode();
                                if exec_mode & 0o022 != 0 {
                                    issues.push(format!(
                                        "WRITABLE executable: {} (mode: {:o})",
                                        exec_path,
                                        exec_mode & 0o7777
                                    ));
                                    finding.severity = Severity::High;
                                }
                            }
                        }
                    }
                }
            }

            // 检查Listen指令
            if trimmed.starts_with("Listen") {
                if let Some(listen_part) = trimmed.split('=').nth(1) {
                    let listen_path = listen_part
                        .trim()
                        .trim_start_matches(&['@', '-', '+', '!'][..]);

                    // 只检查Unix socket路径 (以/开头)
                    if listen_path.starts_with('/') {
                        // 检查监听路径的父目录是否可写
                        if let Some(parent) = std::path::Path::new(listen_path).parent() {
                            if parent.exists() {
                                if let Ok(parent_meta) = fs::metadata(parent) {
                                    use std::os::unix::fs::PermissionsExt;
                                    let parent_mode = parent_meta.permissions().mode();
                                    if parent_mode & 0o022 != 0 {
                                        issues.push(format!(
                                            "WRITABLE listener parent dir: {} (mode: {:o})",
                                            parent.display(),
                                            parent_mode & 0o7777
                                        ));
                                        finding.severity = Severity::High;
                                    }
                                }
                            }
                        }
                    } else if !listen_path.starts_with('/') && !listen_path.contains(':') {
                        // 相对路径且不是网络地址
                        issues.push(format!("RELATIVE LISTENER: {}", listen_path));
                        finding.severity = Severity::Medium;
                    }
                }
            }

            // 检查危险配置
            if trimmed.starts_with("User=root") || trimmed.starts_with("Group=root") {
                issues.push("Runs as ROOT".to_string());
                finding.severity = Severity::Medium;
            }

            if trimmed.contains("CAP_SYS_ADMIN") {
                issues.push("DANGEROUS CAPS: CAP_SYS_ADMIN".to_string());
                finding.severity = Severity::Medium;
            }
        }
    }

    // 如果有问题，添加到详细信息
    if !issues.is_empty() {
        details.push(format!("\n{}", socket_path));
        for issue in issues {
            details.push(format!("  ⚠ {}", issue));
        }
    }
}

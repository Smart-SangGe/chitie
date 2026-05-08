use crate::{Category, Finding, Severity};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

///  Processes - Unix Sockets
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Analyze Unix domain sockets for privilege escalation vectors
///
///  Checks for:
///  - Listening Unix sockets
///  - Socket file permissions (readable/writable)
///  - Socket ownership (especially root-owned)
///  - Weak permissions (666, 777)
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets
///  - Based on LinPEAS PR_Unix_sockets_listening
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
        "Unix Sockets",
        "Unix domain sockets analysis",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets",
    );

    let mut details = Vec::new();
    // 获取当前用户
    let current_uid = nix::unistd::getuid().as_raw();

    // 如果是root用户，跳过此检查
    if current_uid == 0 {
        details.push("Running as root - skipping Unix socket checks".to_string());
        finding.details = details;
        return Some(finding);
    }

    // 1. 从ss命令获取监听中的socket
    let mut listening_sockets = Vec::new();
    if let Ok(output) = Command::new("ss")
        .args(&["-xlp", "-H", "state", "listening"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // 提取socket路径
                for word in line.split_whitespace() {
                    if word.starts_with('/') && !word.contains('*') {
                        listening_sockets.push(word.to_string());
                    }
                }
            }
        }
    }

    // 2. 查找系统中的所有socket文件（限制在常见目录）
    let search_dirs = vec!["/run", "/tmp", "/var/run", "/var/tmp", "/dev", "/home"];

    let mut all_sockets = Vec::new();
    for dir in search_dirs {
        if Path::new(dir).exists() {
            for entry in WalkDir::new(dir)
                .max_depth(5) // 限制深度避免扫描太久
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                let path = entry.path();
                if let Ok(metadata) = fs::metadata(path) {
                    use std::os::unix::fs::FileTypeExt;
                    if metadata.file_type().is_socket() {
                        if let Some(path_str) = path.to_str() {
                            all_sockets.push(path_str.to_string());
                        }
                    }
                }
            }
        }
    }

    // 合并并去重
    listening_sockets.extend(all_sockets);
    listening_sockets.sort();
    listening_sockets.dedup();

    if listening_sockets.is_empty() {
        details.push("No Unix sockets found".to_string());
        finding.details = details;
        return Some(finding);
    }

    details.push(format!(
        "=== FOUND {} UNIX SOCKETS ===",
        listening_sockets.len()
    ));

    // 分析每个socket
    let mut analyzed = 0;
    for socket_path in listening_sockets.iter() {
        if analyzed >= 50 {
            // 限制分析数量
            details.push(format!(
                "... and {} more sockets (showing first 50)",
                listening_sockets.len() - 50
            ));
            break;
        }

        if let Some(socket_info) = analyze_socket(socket_path) {
            details.push(format!("\n{}", socket_path));

            // 权限信息
            if !socket_info.permissions.is_empty() {
                details.push(format!("  Permissions: {}", socket_info.permissions));
            }

            // 所有者信息
            details.push(format!(
                "  Owner: {}:{} (uid:{} gid:{})",
                socket_info.owner, socket_info.group, socket_info.uid, socket_info.gid
            ));

            // 检查是否可写
            if socket_info.writable {
                details.push("  ⚠ WRITABLE by current user".to_string());
                finding.severity = Severity::Medium;
            }

            // 检查是否可读
            if socket_info.readable {
                details.push("  ⚠ READABLE by current user".to_string());
                if socket_info.owner == "root" {
                    finding.severity = Severity::Medium;
                }
            }

            // 检查弱权限
            if socket_info.mode == 0o777 || socket_info.mode == 0o666 {
                details.push(format!("  ⚠ WEAK PERMISSIONS: {:o}", socket_info.mode));
                finding.severity = Severity::High;
            }

            // 标记root所有的可访问socket
            if socket_info.owner == "root" && (socket_info.readable || socket_info.writable) {
                details.push("  ⚠ ROOT-owned socket accessible by current user".to_string());
                finding.severity = Severity::Medium;
            }

            analyzed += 1;
        }
    }

    if analyzed == 0 {
        details.push("No accessible Unix sockets found".to_string());
    }

    finding.details = details;
    Some(finding)
}

#[derive(Debug)]
struct SocketInfo {
    readable: bool,
    writable: bool,
    owner: String,
    group: String,
    uid: u32,
    gid: u32,
    mode: u32,
    permissions: String,
}

fn analyze_socket(socket_path: &str) -> Option<SocketInfo> {
    let path = Path::new(socket_path);

    // 检查socket是否存在
    if !path.exists() {
        return None;
    }

    // 获取元数据
    let metadata = fs::metadata(path).ok()?;

    // 确认是socket
    use std::os::unix::fs::FileTypeExt;
    if !metadata.file_type().is_socket() {
        return None;
    }

    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o7777;
    let uid = metadata.uid();
    let gid = metadata.gid();

    // 获取用户名和组名
    let owner = get_username(uid).unwrap_or_else(|| uid.to_string());
    let group = get_groupname(gid).unwrap_or_else(|| gid.to_string());

    // 检查读写权限
    let readable = path
        .metadata()
        .map(|m| m.permissions())
        .ok()
        .map(|_p| {
            // 简单检查：尝试打开文件
            fs::File::open(path).is_ok()
        })
        .unwrap_or(false);

    let writable = fs::OpenOptions::new().write(true).open(path).is_ok();

    // 构建权限字符串
    let mut permissions = Vec::new();
    if readable {
        permissions.push("Read");
    }
    if writable {
        permissions.push("Write");
    }

    Some(SocketInfo {
        readable,
        writable,
        owner,
        group,
        uid,
        gid,
        mode,
        permissions: permissions.join(" + "),
    })
}

fn get_username(uid: u32) -> Option<String> {
    // 读取/etc/passwd
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(line_uid) = parts[2].parse::<u32>() {
                    if line_uid == uid {
                        return Some(parts[0].to_string());
                    }
                }
            }
        }
    }
    None
}

fn get_groupname(gid: u32) -> Option<String> {
    // 读取/etc/group
    if let Ok(group_file) = fs::read_to_string("/etc/group") {
        for line in group_file.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(line_gid) = parts[2].parse::<u32>() {
                    if line_gid == gid {
                        return Some(parts[0].to_string());
                    }
                }
            }
        }
    }
    None
}

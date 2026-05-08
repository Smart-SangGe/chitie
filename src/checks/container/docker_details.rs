use crate::utils::command::Command;
use crate::{Category, Finding, Severity};
use regex::Regex;
use std::fs;
use std::os::unix::fs::PermissionsExt;

///  Container - Docker Container Details
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Get Docker container details from inside
///
///  Checks for:
///  - Docker group membership
///  - Docker socket enumeration
///  - Docker version and CVE vulnerabilities
///  - Rootless Docker detection
///  - Docker overlays
///
///  References:
///  - CVE-2019-5736: Docker runc vulnerability
///  - CVE-2019-13139: Docker cp vulnerability
///  - CVE-2021-41091: Docker overlay vulnerability
///
///  Execution Mode:
///  - Default: yes (only if inside Docker)
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    // 检测是否在 Docker 容器中
    if !is_in_docker() {
        return None;
    }

    let mut finding = Finding::new(
        Category::Container,
        Severity::Info,
        "Docker Details",
        "Docker container security details",
    );

    finding
        .details
        .push("Running inside Docker container".to_string());
    finding.details.push("".to_string());

    // 检查是否在 docker 组中
    if is_in_docker_group() {
        finding
            .details
            .push("WARNING: User is in docker group!".to_string());
        finding.severity = Severity::High;
    } else {
        finding
            .details
            .push("User is NOT in docker group".to_string());
    }

    // 枚举 Docker socket
    let sockets = enumerate_docker_sockets();
    if !sockets.is_empty() {
        finding.details.push("".to_string());
        finding.details.push("Docker sockets found:".to_string());
        finding.details.extend(sockets);
        finding.severity = Severity::High;
    }

    // 检查 Docker 版本
    if let Some(version) = get_docker_version() {
        finding.details.push("".to_string());
        finding.details.push(format!("Docker version: {}", version));

        // 检查 CVE 漏洞
        let vulnerabilities = check_docker_cves(&version);
        if !vulnerabilities.is_empty() {
            finding.severity = Severity::Critical;
            finding.details.push("".to_string());
            finding
                .details
                .push("CRITICAL: Docker version vulnerable to:".to_string());
            finding.details.extend(vulnerabilities);
        }
    }

    // 检查是否是 rootless Docker
    if is_rootless_docker() {
        finding.details.push("".to_string());
        finding.details.push("Rootless Docker: Yes".to_string());
    } else {
        finding.details.push("".to_string());
        finding
            .details
            .push("Rootless Docker: No (WARNING)".to_string());
    }

    // 检查 Docker overlays
    if let Ok(output) = Command::new("df").arg("-h").output() {
        if output.status.success() {
            let df_output = String::from_utf8_lossy(&output.stdout);
            let overlays: Vec<&str> = df_output
                .lines()
                .filter(|l| l.contains("docker") || l.contains("overlay"))
                .collect();

            if !overlays.is_empty() {
                finding.details.push("".to_string());
                finding.details.push("Docker overlays:".to_string());
                for overlay in overlays {
                    finding.details.push(format!("  {}", overlay));
                }
            }
        }
    }

    Some(finding)
}

/// 检测是否在 Docker 容器中
fn is_in_docker() -> bool {
    // 检查 /.dockerenv
    if fs::metadata("/.dockerenv").is_ok() {
        return true;
    }

    // 检查 /proc/1/cgroup
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker") {
            return true;
        }
    }

    false
}

/// 检查用户是否在 docker 组中
fn is_in_docker_group() -> bool {
    if let Ok(output) = Command::new("id").output() {
        if output.status.success() {
            let id_output = String::from_utf8_lossy(&output.stdout);
            return id_output.contains("docker");
        }
    }
    false
}

/// 枚举 Docker sockets
fn enumerate_docker_sockets() -> Vec<String> {
    let mut sockets = Vec::new();
    let possible_paths = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/dockershim.sock",
    ];

    for path in &possible_paths {
        if let Ok(metadata) = fs::metadata(path) {
            let perms = metadata.permissions();
            let mode = perms.mode();
            sockets.push(format!("  {} (permissions: {:o})", path, mode & 0o777));

            // 检查是否可写
            if mode & 0o002 != 0 || mode & 0o020 != 0 {
                sockets.push("    WARNING: Socket is writable!".to_string());
            }
        }
    }

    sockets
}

/// 获取 Docker 版本
fn get_docker_version() -> Option<String> {
    if let Ok(output) = Command::new("docker").arg("--version").output() {
        if output.status.success() {
            let version_str = String::from_utf8_lossy(&output.stdout);
            return Some(version_str.trim().to_string());
        }
    }
    None
}

/// 检查 Docker CVE 漏洞
fn check_docker_cves(version: &str) -> Vec<String> {
    let mut vulnerabilities = Vec::new();

    // 提取版本号
    let version_regex = match Regex::new(r"(\d+)\.(\d+)\.(\d+)") {
        Ok(r) => r,
        Err(_) => return vulnerabilities,
    };

    let caps = match version_regex.captures(version) {
        Some(c) => c,
        None => return vulnerabilities,
    };

    let major: u32 = match caps.get(1).and_then(|m| m.as_str().parse().ok()) {
        Some(v) => v,
        None => return vulnerabilities,
    };

    let minor: u32 = match caps.get(2).and_then(|m| m.as_str().parse().ok()) {
        Some(v) => v,
        None => return vulnerabilities,
    };

    let patch: u32 = match caps.get(3).and_then(|m| m.as_str().parse().ok()) {
        Some(v) => v,
        None => return vulnerabilities,
    };

    // CVE-2019-5736: runc vulnerability (Docker < 18.09.2)
    if major < 18 || (major == 18 && minor < 9) || (major == 18 && minor == 9 && patch < 2) {
        vulnerabilities.push("  CVE-2019-5736: runc container breakout".to_string());
    }

    // CVE-2019-13139: Docker cp vulnerability (Docker < 19.03.1)
    if major < 19 || (major == 19 && minor < 3) || (major == 19 && minor == 3 && patch < 1) {
        vulnerabilities.push("  CVE-2019-13139: docker cp race condition".to_string());
    }

    // CVE-2021-41091: Overlay vulnerability (Docker < 20.10.9)
    if major < 20 || (major == 20 && minor < 10) || (major == 20 && minor == 10 && patch < 9) {
        vulnerabilities.push("  CVE-2021-41091: overlay directory traversal".to_string());
    }

    vulnerabilities
}

/// 检查是否是 rootless Docker
fn is_rootless_docker() -> bool {
    // 检查 XDG_RUNTIME_DIR 中的 docker.sock
    if let Ok(xdg_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let rootless_sock = format!("{}/docker.sock", xdg_dir);
        if fs::metadata(&rootless_sock).is_ok() {
            return true;
        }
    }

    // 检查 /run/user/UID/docker.sock
    if let Ok(output) = Command::new("id").arg("-u").output() {
        if output.status.success() {
            let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let rootless_sock = format!("/run/user/{}/docker.sock", uid);
            if fs::metadata(&rootless_sock).is_ok() {
                return true;
            }
        }
    }

    false
}

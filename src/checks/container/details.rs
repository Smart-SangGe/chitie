use crate::utils::command::Command;
use crate::{Category, Finding, Severity};
use std::fs;

///  Container - Container Details
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Get detailed container information
///
///  Checks for:
///  - Container type detection (Docker, Podman, LXC, etc.)
///  - Running containers count
///  - Container runtime information
///
///  References:
///  - Running containers may indicate privilege escalation opportunities
///  - Privileged containers can be exploited for container escape
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Container,
        Severity::Info,
        "Container Details",
        "Container runtime and running containers",
    );

    // 检测容器类型
    let container_type = detect_container_type();
    if let Some(ctype) = &container_type {
        finding.details.push(format!("Running inside: {}", ctype));
        finding.severity = Severity::Medium;
    } else {
        finding
            .details
            .push("Not running inside a container".to_string());
    }

    finding.details.push("".to_string());

    // 检查 Docker
    let docker_count = count_docker_containers();
    if docker_count > 0 {
        finding
            .details
            .push(format!("Docker containers running: {}", docker_count));
        finding.severity = Severity::Medium;

        // 获取容器列表
        if let Ok(output) = Command::new("docker").args(["ps", "-a"]).output() {
            if output.status.success() {
                let ps_output = String::from_utf8_lossy(&output.stdout);
                finding.details.push("".to_string());
                finding.details.push("Docker containers:".to_string());
                for line in ps_output.lines().take(10) {
                    finding.details.push(format!("  {}", line));
                }
            }
        }
    }

    // 检查 Podman
    let podman_count = count_podman_containers();
    if podman_count > 0 {
        finding.details.push("".to_string());
        finding
            .details
            .push(format!("Podman containers running: {}", podman_count));
        finding.severity = Severity::Medium;
    }

    // 检查 LXC
    let lxc_count = count_lxc_containers();
    if lxc_count > 0 {
        finding.details.push("".to_string());
        finding
            .details
            .push(format!("LXC containers running: {}", lxc_count));
        finding.severity = Severity::Medium;
    }

    Some(finding)
}

/// 检测是否在容器中运行
fn detect_container_type() -> Option<String> {
    // 方法1: 检查 /.dockerenv
    if fs::metadata("/.dockerenv").is_ok() {
        return Some("Docker container".to_string());
    }

    // 方法2: 检查 /proc/1/cgroup
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker") {
            return Some("Docker container".to_string());
        }
        if cgroup.contains("lxc") {
            return Some("LXC container".to_string());
        }
        if cgroup.contains("kubepods") {
            return Some("Kubernetes pod".to_string());
        }
    }

    // 方法3: 检查 /run/.containerenv (Podman)
    if fs::metadata("/run/.containerenv").is_ok() {
        return Some("Podman container".to_string());
    }

    None
}

/// 统计 Docker 容器数量
fn count_docker_containers() -> usize {
    if let Ok(output) = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}"])
        .output()
    {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            return output_str.lines().filter(|l| !l.is_empty()).count();
        }
    }
    0
}

/// 统计 Podman 容器数量
fn count_podman_containers() -> usize {
    if let Ok(output) = Command::new("podman")
        .args(["ps", "--format", "{{.Names}}"])
        .output()
    {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            return output_str.lines().filter(|l| !l.is_empty()).count();
        }
    }
    0
}

/// 统计 LXC 容器数量
fn count_lxc_containers() -> usize {
    if let Ok(output) = Command::new("lxc")
        .args(["list", "-c", "n", "--format", "csv"])
        .output()
    {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            return output_str.lines().filter(|l| !l.is_empty()).count();
        }
    }
    0
}

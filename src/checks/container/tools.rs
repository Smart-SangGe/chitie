use crate::utils::command::Command;
use crate::{Category, Finding, Severity};

///  Container - Container Tools
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Find container related tools that could be used for container escape
///
///  Checks for:
///  - Container runtimes (docker, podman, lxc, etc.)
///  - Container management tools (kubectl, crictl, etc.)
///  - Container networking tools
///  - Container security tools
///  - Container debugging tools
///
///  References:
///  - Container tools can be exploited for privilege escalation and container escape
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
        "Container Tools",
        "Container related tools present on system",
    );

    let mut found_tools = Vec::new();

    // Container runtimes
    let runtimes = [
        "docker",
        "lxc",
        "rkt",
        "podman",
        "runc",
        "ctr",
        "containerd",
        "crio",
        "nerdctl",
    ];

    // Container management
    let management = [
        "kubectl",
        "crictl",
        "docker-compose",
        "docker-machine",
        "minikube",
        "kind",
    ];

    // Container networking
    let networking = ["docker-proxy", "cni", "flanneld", "calicoctl"];

    // Container security
    let security = ["apparmor_parser", "seccomp", "gvisor", "kata-runtime"];

    // Container debugging
    let debugging = ["nsenter", "unshare", "chroot", "capsh", "setcap", "getcap"];

    // 检查所有工具
    check_tools(&runtimes, "Container Runtimes", &mut found_tools);
    check_tools(&management, "Container Management", &mut found_tools);
    check_tools(&networking, "Container Networking", &mut found_tools);
    check_tools(&security, "Container Security", &mut found_tools);
    check_tools(&debugging, "Container Debugging", &mut found_tools);

    if found_tools.is_empty() {
        return None;
    }

    finding.details.extend(found_tools);

    Some(finding)
}

/// 检查一组工具并记录找到的
fn check_tools(tools: &[&str], category: &str, found: &mut Vec<String>) {
    let mut category_tools = Vec::new();

    for tool in tools {
        if let Ok(output) = Command::new("which").args([tool]).output()
            && output.status.success()
        {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                category_tools.push(format!("  {} -> {}", tool, path));
            }
        }
    }

    if !category_tools.is_empty() {
        found.push(format!("{}:", category));
        found.extend(category_tools);
        found.push("".to_string());
    }
}

use crate::{Category, Finding, Severity};
use std::process::Command;

///  Software Information - Useful Software
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Detect useful software that could be used for privilege escalation
///
///  Checks for:
///  - Development tools (gcc, g++, go, perl, python, ruby, php, lua)
///  - Network tools (nc, netcat, ncat, socat, curl, wget, fetch)
///  - Container tools (docker, podman, lxc, rkt, runc, ctr, kubectl)
///  - Cloud tools (aws, az, gcloud)
///  - Debugging tools (gdb)
///  - Other useful tools (sudo, doas, base64, xterm, ping)
///
///  References:
///  - Based on LinPEAS SI_Useful_software
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Software,
        Severity::Info,
        "Useful Software",
        "Potentially useful software for privilege escalation",
    );

    let useful_software = [
        // Development tools
        "gcc",
        "g++",
        "make",
        "go",
        "perl",
        "python",
        "python2",
        "python2.6",
        "python2.7",
        "python3",
        "python3.6",
        "python3.7",
        "ruby",
        "php",
        "lua",
        // Network tools
        "nc",
        "nc.traditional",
        "ncat",
        "netcat",
        "nmap",
        "socat",
        "curl",
        "wget",
        "fetch",
        "ping",
        // Container tools
        "docker",
        "podman",
        "lxc",
        "rkt",
        "runc",
        "ctr",
        "kubectl",
        // Cloud tools
        "aws",
        "az",
        "gcloud",
        // Debug tools
        "gdb",
        // Other tools
        "sudo",
        "doas",
        "base64",
        "xterm",
        "authbind",
        "pwsh",
    ];

    let mut found_tools = Vec::new();

    for tool in &useful_software {
        if let Ok(output) = Command::new("command").args(["-v", tool]).output()
            && output.status.success()
        {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                found_tools.push(format!("{} -> {}", tool, path));
            }
        }
    }

    if found_tools.is_empty() {
        return None;
    }

    // 如果发现编译器或容器工具，提升严重性
    if found_tools.iter().any(|t| {
        t.contains("gcc")
            || t.contains("g++")
            || t.contains("docker")
            || t.contains("podman")
            || t.contains("sudo")
    }) {
        finding.severity = Severity::Medium;
        finding.description = "Development tools or container runtime found".to_string();
    }

    finding.details = found_tools;
    Some(finding)
}

use crate::utils::command::Command;
use crate::{Category, Finding, Severity};
use std::fs;
use std::path::Path;

///  Container - Container Breakout Enumeration
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Container breakout enumeration to identify potential escape vectors
///  Corresponds to LinPEAS: 5_Container_breakout.sh
pub async fn check() -> Option<Finding> {
    if !is_in_container() {
        return None;
    }

    let mut finding = Finding::new(
        Category::Container,
        Severity::Info,
        "Container Breakout",
        "Container escape enumeration",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html");

    let mut details = Vec::new();

    // 1. Basic Info
    if let Ok(hostname) = fs::read_to_string("/etc/hostname") {
        details.push(format!("Container ID: {}", hostname.trim()));
    }

    // 2. Security Mechanisms
    details.push("=== Security Mechanisms ===".to_string());
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Seccomp:") {
                let val = line.split(':').nth(1).unwrap_or("").trim();
                let status = if val == "0" {
                    "[!] Seccomp: DISABLED"
                } else {
                    "Seccomp: enabled"
                };
                details.push(status.to_string());
                if val == "0" && finding.severity < Severity::High {
                    finding.severity = Severity::High;
                }
            }
        }
    }

    if let Ok(apparmor) = fs::read_to_string("/proc/self/attr/current") {
        let val = apparmor.trim();
        let status = if val == "unconfined" {
            "[!] AppArmor: UNCONFINED"
        } else {
            "AppArmor: enabled"
        };
        details.push(status.to_string());
        if val == "unconfined" && finding.severity < Severity::High {
            finding.severity = Severity::High;
        }
    }

    if fs::metadata("/proc/self/uid_map").is_ok() {
        details.push("User Proc Namespace: enabled".to_string());
    }

    // 3. Runtime Vulnerabilities
    details.push("\n=== Runtime Vulnerabilities ===".to_string());
    if let Ok(output) = Command::new("runc").arg("--version").output() {
        let out = String::from_utf8_lossy(&output.stdout);
        details.push(format!(
            "runc version: {}",
            out.lines().next().unwrap_or("unknown")
        ));
        if out.contains("version 1.0.0-rc") || out.contains("version 0.") {
            details.push("[!] CRITICAL: runc might be vulnerable to CVE-2019-5736!".to_string());
            finding.severity = Severity::Critical;
        }
    }

    if let Ok(output) = Command::new("containerd").arg("--version").output() {
        let out = String::from_utf8_lossy(&output.stdout);
        details.push(format!("containerd version: {}", out.trim()));
        if out.contains("v1.4.0")
            || out.contains("v1.4.1")
            || out.contains("v1.4.2")
            || out.contains("v1.3.")
        {
            details.push(
                "[!] CRITICAL: containerd might be vulnerable to CVE-2020-15257!".to_string(),
            );
            finding.severity = Severity::Critical;
        }
    }

    // 4. Mount Escape Vectors
    details.push("\n=== Breakout via Mounts ===".to_string());
    if let Ok(output) = Command::new("mount").output() {
        let mount_str = String::from_utf8_lossy(&output.stdout);
        for line in mount_str.lines() {
            if line.contains("docker.sock") {
                details.push(format!("[!] CRITICAL: Docker socket mounted: {}", line));
                finding.severity = Severity::Critical;
            }
            if line.contains("/host") || (line.contains(" / ") && !line.contains("overlay")) {
                details.push(format!(
                    "[!] HIGH: Host filesystem might be mounted: {}",
                    line
                ));
                if finding.severity < Severity::High {
                    finding.severity = Severity::High;
                }
            }
            if line.contains("rw,") && (line.contains("/sys") || line.contains("/proc")) {
                details.push(format!("[!] WARNING: Writable /sys or /proc: {}", line));
                if finding.severity < Severity::Medium {
                    finding.severity = Severity::Medium;
                }
            }
        }
    }

    // 5. Capability Checks
    details.push("\n=== Capability Checks ===".to_string());
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                details.push(format!("Effective Caps: {}", line));
                let caps = line.split(':').nth(1).unwrap_or("").trim();
                // Check for dangerous caps (Simplified check for common privileged values)
                if caps != "0000000000000000" && caps != "00000000a80425fb" {
                    details.push(
                        "[!] HIGH: Excessive capabilities detected! Run 'capsh --decode' to audit."
                            .to_string(),
                    );
                    if finding.severity < Severity::High {
                        finding.severity = Severity::High;
                    }
                }
            }
        }
    }

    // 6. Kubernetes Specific Checks
    let k8s_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    if Path::new(k8s_token_path).exists() {
        details.push("\n=== Kubernetes Specific Checks ===".to_string());
        if let Ok(ns) =
            fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        {
            details.push(format!("K8s Namespace: {}", ns.trim()));
        }
        details.push(format!("[!] K8s Token found at: {}", k8s_token_path));
        finding.severity = Severity::High;

        // Try to check API access via environment variables
        if let Ok(host) = std::env::var("KUBERNETES_SERVICE_HOST") {
            details.push(format!("K8s API Server: {}", host));
        }
    }

    // 7. Escape Tools in PATH
    let tools = ["nsenter", "unshare", "chroot", "capsh", "kubectl", "docker"];
    let mut found_tools = Vec::new();
    for tool in &tools {
        if let Ok(output) = Command::new("which").arg(tool).output() {
            if output.status.success() {
                found_tools.push(*tool);
            }
        }
    }
    if !found_tools.is_empty() {
        details.push(format!("\nEscape tools found: {}", found_tools.join(", ")));
    }

    finding.details = details;
    Some(finding)
}

fn is_in_container() -> bool {
    if fs::metadata("/.dockerenv").is_ok() || fs::metadata("/run/.containerenv").is_ok() {
        return true;
    }
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker")
            || cgroup.contains("lxc")
            || cgroup.contains("kubepods")
            || cgroup.contains("containerd")
        {
            return true;
        }
    }
    // Check for container env vars
    std::env::var("container").is_ok() || std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
}

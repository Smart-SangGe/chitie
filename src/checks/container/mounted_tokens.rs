use crate::{Category, Finding, Severity};
use std::collections::HashSet;
use std::fs;
use std::process::Command;

///  Container - Mounted Tokens
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: List tokens mounted in the system (Kubernetes service account tokens)
///
///  Checks for:
///  - Kubernetes service account tokens mounted in containers
///  - Token namespaces
///  - Unique tokens (deduplicated)
///
///  References:
///  - https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/attacking-kubernetes-from-inside-a-pod.html
///  - Service account tokens can be used to access Kubernetes API
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    // 读取 mount 信息
    let mount_output = Command::new("mount").output().ok()?;
    if !mount_output.status.success() {
        return None;
    }

    let mount_str = String::from_utf8_lossy(&mount_output.stdout);

    // 查找包含 "secret" 和 "default" 的 tmpfs 挂载
    let mut token_dirs = Vec::new();
    for line in mount_str.lines() {
        if line.contains("secret") && line.contains("default") && line.contains("tmpfs") {
            // 格式: tmpfs on /var/run/secrets/kubernetes.io/serviceaccount type tmpfs
            if let Some(start) = line.find(" on ") {
                if let Some(end) = line[start + 4..].find(" type ") {
                    let dir = &line[start + 4..start + 4 + end];
                    token_dirs.push(dir.to_string());
                }
            }
        }
    }

    if token_dirs.is_empty() {
        return None;
    }

    let mut finding = Finding::new(
        Category::Container,
        Severity::High,
        "Mounted Tokens",
        "Kubernetes service account tokens found",
    )
    .with_reference("https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/attacking-kubernetes-from-inside-a-pod.html");

    finding
        .details
        .push("WARNING: Kubernetes service account tokens detected!".to_string());
    finding
        .details
        .push("These tokens can be used to access the Kubernetes API".to_string());
    finding.details.push("".to_string());

    let mut seen_tokens = HashSet::new();

    for dir in token_dirs {
        // 读取 namespace
        let namespace_path = format!("{}/namespace", dir);
        let namespace = fs::read_to_string(&namespace_path)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        // 读取 token
        let token_path = format!("{}/token", dir);
        if let Ok(token) = fs::read_to_string(&token_path) {
            let token = token.trim().to_string();

            // 去重
            if !seen_tokens.contains(&token) {
                seen_tokens.insert(token.clone());

                finding.details.push(format!("Directory: {}", dir));
                finding.details.push(format!("Namespace: {}", namespace));
                finding.details.push("".to_string());

                // 只显示 token 的前 50 个字符
                if token.len() > 50 {
                    finding
                        .details
                        .push(format!("Token: {}...[truncated]", &token[..50]));
                } else {
                    finding.details.push(format!("Token: {}", token));
                }
                finding.details.push("=".repeat(80));
                finding.details.push("".to_string());
            }
        }
    }

    Some(finding)
}

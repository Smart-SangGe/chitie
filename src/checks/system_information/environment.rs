use crate::{Category, Finding, Severity};
use regex::Regex;
use std::env;

///  System Information - Environment
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Check for sensitive information in environment variables
///
///  Checks for:
///  - Credentials in environment variables
///  - API keys and tokens
///  - Database credentials
///  - Service account tokens
///
///  References:
///  - Environment variables may contain sensitive information
///  - Credentials can be harvested for privilege escalation
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::System,
        Severity::Info,
        "Environment",
        "Environment variables",
    );

    // 敏感关键词模式 (来自 LinPEAS EnvVarsRed)
    let sensitive_pattern = Regex::new(
        r"(?i)(pass|apikey|api_key|aws|azure|gcp|secret|sql|database|token|credential|auth)",
    )
    .ok()?;

    // 需要过滤的非敏感变量 (来自 LinPEAS NoEnvVars，简化版)
    let ignore_pattern = Regex::new(
        r"(?i)(LESS_TERMCAP|JOURNAL_STREAM|XDG_SESSION|DBUS_SESSION|systemd|MEMORY_PRESSURE|VERSION|LS_COLORS|PATH|INVOCATION_ID|WATCHDOG_PID|LISTEN_PID|TERM|LANG|LC_)",
    )
    .ok()?;

    let mut env_vars = Vec::new();
    let mut sensitive_vars = Vec::new();

    // 获取所有环境变量
    for (key, value) in env::vars() {
        // 跳过需要忽略的变量
        if ignore_pattern.is_match(&key) {
            continue;
        }

        // 检查是否包含敏感信息
        if sensitive_pattern.is_match(&key) || sensitive_pattern.is_match(&value) {
            // 为了安全，不完全显示敏感值
            let masked_value = if value.len() > 20 {
                format!("{}...[masked]", &value[..20])
            } else {
                "[masked]".to_string()
            };
            sensitive_vars.push(format!("SENSITIVE: {}={}", key, masked_value));
        } else {
            // 普通环境变量，限制显示长度
            let display_value = if value.len() > 100 {
                format!("{}...", &value[..100])
            } else {
                value
            };
            env_vars.push(format!("{}={}", key, display_value));
        }
    }

    // 优先显示敏感变量
    if !sensitive_vars.is_empty() {
        finding.severity = Severity::High;
        finding.description = "Sensitive information found in environment variables!".to_string();
        finding
            .details
            .push("WARNING: Sensitive environment variables detected:".to_string());
        finding.details.extend(sensitive_vars);
        finding.details.push("".to_string());
    }

    // 只显示前 20 个普通环境变量
    env_vars.truncate(20);
    if !env_vars.is_empty() {
        finding.details.push("Environment variables:".to_string());
        finding.details.extend(env_vars);
    }

    Some(finding)
}

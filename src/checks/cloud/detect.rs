use crate::{Category, Finding, Severity};
use std::fs;
use std::process::Command;

///  Cloud - Cloud Environment Detection and Metadata Harvesting
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Detect cloud environment and harvest sensitive metadata
///  Corresponds to LinPEAS: 3_cloud/ (multiple scripts)
pub async fn check() -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // 1. Detect environment
    let cloud_type = detect_cloud();
    if cloud_type == "None" {
        return Ok(findings);
    }

    let mut finding = Finding::new(
        Category::Cloud,
        Severity::Info,
        format!("Cloud Platform: {}", cloud_type),
        "Detected cloud environment and attempted metadata harvesting",
    );

    let mut details = Vec::new();
    details.push(format!("Platform: {}", cloud_type));

    // 2. Harvest Metadata based on platform
    match cloud_type.as_str() {
        "AWS" => harvest_aws(&mut details, &mut finding.severity),
        "Alibaba" => harvest_alibaba(&mut details, &mut finding.severity),
        "GCP" => harvest_gcp(&mut details, &mut finding.severity),
        "Azure" => harvest_azure(&mut details, &mut finding.severity),
        _ => {}
    }

    if !details.is_empty() {
        finding.details = details;
        findings.push(finding);
    }

    Ok(findings)
}

fn detect_cloud() -> String {
    // Check DMI info (common for many clouds)
    if let Ok(vendor) = fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
        let vendor = vendor.to_lowercase();
        if vendor.contains("amazon") {
            return "AWS".to_string();
        }
        if vendor.contains("google") {
            return "GCP".to_string();
        }
        if vendor.contains("microsoft") {
            return "Azure".to_string();
        }
        if vendor.contains("alibaba") {
            return "Alibaba".to_string();
        }
        if vendor.contains("tencent") {
            return "Tencent".to_string();
        }
    }

    // Check product_name
    if let Ok(name) = fs::read_to_string("/sys/class/dmi/id/product_name") {
        let name = name.to_lowercase();
        if name.contains("amazon") {
            return "AWS".to_string();
        }
        if name.contains("google") {
            return "GCP".to_string();
        }
        if name.contains("alibaba") {
            return "Alibaba".to_string();
        }
    }

    "None".to_string()
}

fn curl_metadata(url: &str, headers: Vec<(&str, &str)>) -> Option<String> {
    let mut cmd = Command::new("curl");
    cmd.args(&[
        "-s",
        "-f",
        "-L",
        "--connect-timeout",
        "2",
        "--max-time",
        "5",
    ]);
    for (k, v) in headers {
        cmd.arg("-H").arg(format!("{}: {}", k, v));
    }
    cmd.arg(url);

    if let Ok(output) = cmd.output() {
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
    }
    None
}

fn harvest_aws(details: &mut Vec<String>, severity: &mut Severity) {
    details.push("--- AWS EC2 Metadata ---".to_string());

    // Try to get IMDSv2 token first
    let token = curl_metadata(
        "http://169.254.164.254/latest/api/token",
        vec![("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
    );
    let headers = match &token {
        Some(t) => vec![("X-aws-ec2-metadata-token", t.as_str())],
        None => vec![],
    };

    if let Some(iam_roles) = curl_metadata(
        "http://169.254.164.254/latest/meta-data/iam/security-credentials/",
        headers.clone(),
    ) {
        details.push(format!("[!] Found IAM Roles: {}", iam_roles));
        *severity = Severity::High;
        for role in iam_roles.lines() {
            if let Some(creds) = curl_metadata(
                &format!(
                    "http://169.254.164.254/latest/meta-data/iam/security-credentials/{}",
                    role
                ),
                headers.clone(),
            ) {
                details.push(format!("Role {}: {}", role, creds));
            }
        }
    }

    if let Some(userdata) = curl_metadata("http://169.254.164.254/latest/user-data", headers) {
        details.push("[!] Found UserData (may contain secrets):".to_string());
        details.push(userdata);
        *severity = Severity::High;
    }
}

fn harvest_alibaba(details: &mut Vec<String>, severity: &mut Severity) {
    details.push("--- Alibaba Cloud ECS Metadata ---".to_string());

    // Aliyun metadata token
    let token = curl_metadata(
        "http://100.100.100.200/latest/api/token",
        vec![("X-aliyun-ecs-metadata-token-ttl-seconds", "1000")],
    );
    let headers = match &token {
        Some(t) => vec![("X-aliyun-ecs-metadata-token", t.as_str())],
        None => vec![],
    };

    if let Some(roles) = curl_metadata(
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        headers.clone(),
    ) {
        details.push(format!("[!] Found RAM Roles: {}", roles));
        *severity = Severity::High;
        for role in roles.lines() {
            if let Some(creds) = curl_metadata(
                &format!(
                    "http://100.100.100.200/latest/meta-data/ram/security-credentials/{}",
                    role
                ),
                headers.clone(),
            ) {
                details.push(format!("Role {}: {}", role, creds));
            }
        }
    }
}

fn harvest_gcp(details: &mut Vec<String>, severity: &mut Severity) {
    details.push("--- GCP Metadata ---".to_string());
    let headers = vec![("Metadata-Flavor", "Google")];

    if let Some(token) = curl_metadata(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        headers.clone(),
    ) {
        details.push(format!(
            "[!] Found GCP Default Service Account Token: {}",
            token
        ));
        *severity = Severity::High;
    }
}

fn harvest_azure(details: &mut Vec<String>, _severity: &mut Severity) {
    details.push("--- Azure Metadata ---".to_string());
    let headers = vec![("Metadata", "true")];

    if let Some(vm_info) = curl_metadata(
        "http://169.254.164.254/metadata/instance?api-version=2021-02-01",
        headers,
    ) {
        details.push("Found Azure Instance Metadata".to_string());
        details.push(vm_info);
    }
}

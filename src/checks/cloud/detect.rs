use crate::{Category, Finding, Severity};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

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

fn fetch_metadata(url: &str, headers: Vec<(&str, &str)>) -> Option<String> {
    fetch_metadata_with_method("GET", url, headers)
}

fn put_metadata(url: &str, headers: Vec<(&str, &str)>) -> Option<String> {
    fetch_metadata_with_method("PUT", url, headers)
}

fn fetch_metadata_with_method(
    method: &str,
    url: &str,
    headers: Vec<(&str, &str)>,
) -> Option<String> {
    let parsed = HttpUrl::parse(url)?;
    let address = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()
        .ok()?
        .next()?;

    let timeout = Duration::from_secs(2);
    let mut stream = TcpStream::connect_timeout(&address, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;

    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: chitie\r\nConnection: close\r\n",
        method, parsed.path, parsed.host
    );
    for (key, value) in headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).ok()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    let response = String::from_utf8_lossy(&response);
    let (head, body) = response.split_once("\r\n\r\n")?;
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200 ") {
        return None;
    }

    Some(body.trim().to_string())
}

struct HttpUrl {
    host: String,
    port: u16,
    path: String,
}

impl HttpUrl {
    fn parse(url: &str) -> Option<Self> {
        let rest = url.strip_prefix("http://")?;
        let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = if let Some((host, port)) = host_port.rsplit_once(':') {
            (host.to_string(), port.parse().ok()?)
        } else {
            (host_port.to_string(), 80)
        };

        Some(Self {
            host,
            port,
            path: format!("/{}", path),
        })
    }
}

fn harvest_aws(details: &mut Vec<String>, severity: &mut Severity) {
    details.push("--- AWS EC2 Metadata ---".to_string());

    // Try to get IMDSv2 token first
    let token = put_metadata(
        "http://169.254.169.254/latest/api/token",
        vec![("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
    );
    let headers = match &token {
        Some(t) => vec![("X-aws-ec2-metadata-token", t.as_str())],
        None => vec![],
    };

    if let Some(iam_roles) = fetch_metadata(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        headers.clone(),
    ) {
        details.push(format!("[!] Found IAM Roles: {}", iam_roles));
        *severity = Severity::High;
        for role in iam_roles.lines() {
            if let Some(creds) = fetch_metadata(
                &format!(
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/{}",
                    role
                ),
                headers.clone(),
            ) {
                details.push(format!("Role {}: {}", role, creds));
            }
        }
    }

    if let Some(userdata) = fetch_metadata("http://169.254.169.254/latest/user-data", headers) {
        details.push("[!] Found UserData (may contain secrets):".to_string());
        details.push(userdata);
        *severity = Severity::High;
    }
}

fn harvest_alibaba(details: &mut Vec<String>, severity: &mut Severity) {
    details.push("--- Alibaba Cloud ECS Metadata ---".to_string());

    // Aliyun metadata token
    let token = put_metadata(
        "http://100.100.100.200/latest/api/token",
        vec![("X-aliyun-ecs-metadata-token-ttl-seconds", "1000")],
    );
    let headers = match &token {
        Some(t) => vec![("X-aliyun-ecs-metadata-token", t.as_str())],
        None => vec![],
    };

    if let Some(roles) = fetch_metadata(
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        headers.clone(),
    ) {
        details.push(format!("[!] Found RAM Roles: {}", roles));
        *severity = Severity::High;
        for role in roles.lines() {
            if let Some(creds) = fetch_metadata(
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

    if let Some(token) = fetch_metadata(
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

    if let Some(vm_info) = fetch_metadata(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers,
    ) {
        details.push("Found Azure Instance Metadata".to_string());
        details.push(vm_info);
    }
}

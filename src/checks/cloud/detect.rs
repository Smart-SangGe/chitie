use crate::{Category, Finding, Severity};
use std::env;
use std::fs;
use std::process::Command;

///  Cloud - Detect Cloud Environment
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Check if the system is running in a cloud environment
///
///  Checks for:
///  - AWS EC2, ECS, Lambda, CodeBuild, Beanstalk
///  - Google Cloud VM, Cloud Functions
///  - Azure VM, App Service, Automation Account
///  - DigitalOcean Droplet
///  - IBM Cloud VM
///  - Alibaba Cloud ECS
///  - Tencent Cloud CVM
///
///  References:
///  - https://training.hacktricks.xyz
///  - Cloud metadata services can be exploited for privilege escalation
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Cloud,
        Severity::Info,
        "Cloud Detection",
        "Cloud environment detection",
    );

    let mut detections = Vec::new();
    let mut detected_any = false;

    // AWS 检测
    if is_aws_ec2() {
        detections.push("AWS EC2: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    if is_aws_ecs() {
        detections.push("AWS ECS: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    if is_aws_lambda() {
        detections.push("AWS Lambda: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    if is_aws_codebuild() {
        detections.push("AWS CodeBuild: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    // GCP 检测
    if is_gcp_vm() {
        detections.push("GCP Virtual Machine: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    if is_gcp_function() {
        detections.push("GCP Cloud Function: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    // Azure 检测
    if is_azure_vm() {
        detections.push("Azure VM: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    if is_azure_app() {
        detections.push("Azure App Service: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    // 其他云
    if is_digitalocean() {
        detections.push("DigitalOcean Droplet: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    if is_alibaba_cloud() {
        detections.push("Alibaba Cloud ECS: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    if is_tencent_cloud() {
        detections.push("Tencent Cloud CVM: Yes".to_string());
        detected_any = true;
        finding.severity = Severity::Medium;
    }

    if detected_any {
        finding.description = "Running in cloud environment!".to_string();
        finding
            .details
            .push("Cloud platform(s) detected:".to_string());
        finding.details.extend(detections);
        finding.details.push("".to_string());
        finding
            .details
            .push("WARNING: Cloud metadata services may be accessible".to_string());
        finding
            .details
            .push("Check for exposed credentials and instance metadata".to_string());
    } else {
        finding
            .details
            .push("Not running in a detected cloud environment".to_string());
        return None; // 如果不在云环境中，返回 None
    }

    Some(finding)
}

/// AWS EC2 检测
fn is_aws_ec2() -> bool {
    // 检查 DMI 信息
    if let Ok(product_version) = fs::read_to_string("/sys/class/dmi/id/product_version") {
        if product_version.to_lowercase().contains("amazon") {
            return true;
        }
    }

    // 检查元数据服务
    if let Ok(output) = Command::new("curl")
        .args(["-s", "-m", "1", "http://169.254.169.254/latest/meta-data/"])
        .output()
    {
        if output.status.success() {
            return true;
        }
    }

    false
}

/// AWS ECS 检测
fn is_aws_ecs() -> bool {
    env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").is_ok()
        || env::var("ECS_CONTAINER_METADATA_URI").is_ok()
}

/// AWS Lambda 检测
fn is_aws_lambda() -> bool {
    env::var("AWS_LAMBDA_FUNCTION_NAME").is_ok()
}

/// AWS CodeBuild 检测
fn is_aws_codebuild() -> bool {
    env::var("CODEBUILD_BUILD_ID").is_ok()
}

/// GCP VM 检测
fn is_gcp_vm() -> bool {
    // 检查 DMI 信息
    if let Ok(product_name) = fs::read_to_string("/sys/class/dmi/id/product_name") {
        if product_name.to_lowercase().contains("google") {
            return true;
        }
    }

    // 检查元数据服务
    if let Ok(output) = Command::new("curl")
        .args([
            "-s",
            "-m",
            "1",
            "-H",
            "Metadata-Flavor: Google",
            "http://metadata.google.internal/computeMetadata/v1/",
        ])
        .output()
    {
        if output.status.success() {
            return true;
        }
    }

    false
}

/// GCP Cloud Function 检测
fn is_gcp_function() -> bool {
    env::var("FUNCTION_NAME").is_ok() || env::var("GCP_PROJECT").is_ok()
}

/// Azure VM 检测
fn is_azure_vm() -> bool {
    // 检查元数据服务
    if let Ok(output) = Command::new("curl")
        .args([
            "-s",
            "-m",
            "1",
            "-H",
            "Metadata:true",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ])
        .output()
    {
        if output.status.success() {
            return true;
        }
    }

    false
}

/// Azure App Service 检测
fn is_azure_app() -> bool {
    env::var("IDENTITY_ENDPOINT").is_ok() || env::var("WEBSITE_SITE_NAME").is_ok()
}

/// DigitalOcean 检测
fn is_digitalocean() -> bool {
    // 检查元数据服务
    if let Ok(output) = Command::new("curl")
        .args(["-s", "-m", "1", "http://169.254.169.254/metadata/v1/"])
        .output()
    {
        if output.status.success() {
            let response = String::from_utf8_lossy(&output.stdout);
            return response.contains("droplet");
        }
    }

    false
}

/// Alibaba Cloud 检测
fn is_alibaba_cloud() -> bool {
    if let Ok(output) = Command::new("curl")
        .args(["-s", "-m", "1", "http://100.100.100.200/latest/meta-data/"])
        .output()
    {
        if output.status.success() {
            return true;
        }
    }

    false
}

/// Tencent Cloud 检测
fn is_tencent_cloud() -> bool {
    if let Ok(output) = Command::new("curl")
        .args(["-s", "-m", "1", "http://metadata.tencentyun.com/latest/"])
        .output()
    {
        if output.status.success() {
            return true;
        }
    }

    false
}

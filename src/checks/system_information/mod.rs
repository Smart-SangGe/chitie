/// System information checks
mod datetime;
mod os;
mod path;
mod sudo;
mod usb;

use crate::Finding;

/// 运行系统信息检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let config = crate::config::config();

    let mut handles = vec![
        tokio::spawn(os::check()),
        tokio::spawn(sudo::check()),
        tokio::spawn(path::check()),
    ];

    if config.extra || config.all_checks {
        handles.push(tokio::spawn(usb::check()));
        handles.push(tokio::spawn(datetime::check()));
    }

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

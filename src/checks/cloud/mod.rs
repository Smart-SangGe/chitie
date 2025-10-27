/// Cloud environment checks
mod detect;

use crate::Finding;

/// 运行云环境检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![tokio::spawn(detect::check())];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

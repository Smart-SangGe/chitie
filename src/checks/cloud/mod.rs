pub mod detect;

use crate::Finding;

/// 运行所有云环境检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(detect::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Ok(module_findings)) = handle.await {
            findings.extend(module_findings);
        }
    }

    Ok(findings)
}
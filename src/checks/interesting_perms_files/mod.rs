/// Interesting permissions and files checks
mod capabilities;
mod suid;

use crate::Finding;

/// 运行权限检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(suid::check()),
        tokio::spawn(capabilities::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

/// Users information checks
mod my_user;
mod sudo_permissions;

use crate::Finding;

/// 运行用户信息检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(my_user::check()),
        tokio::spawn(sudo_permissions::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

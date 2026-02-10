pub mod useful_software;
pub mod compilers;
pub mod terminal_sessions;
pub mod ssh_info;
pub mod mysql;
pub mod postgresql;

use crate::Finding;

/// 运行所有软件信息检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(useful_software::check()),
        tokio::spawn(compilers::check()),
        tokio::spawn(terminal_sessions::check()),
        tokio::spawn(ssh_info::check()),
        tokio::spawn(mysql::check()),
        tokio::spawn(postgresql::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

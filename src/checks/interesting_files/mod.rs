pub mod backup_files;
pub mod executable_files;
pub mod hidden_files;
pub mod modified_last_5mins;
pub mod sh_files_in_path;

use crate::Finding;

pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(executable_files::check()),
        tokio::spawn(modified_last_5mins::check()),
        tokio::spawn(sh_files_in_path::check()),
        tokio::spawn(backup_files::check()),
        tokio::spawn(hidden_files::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

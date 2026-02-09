/// Interesting permissions and files checks
mod acls;
mod capabilities;
mod cred_files;
mod ld_so;
mod root_paths;
mod sgid;
mod suid;
mod world_writable_files;

use crate::Finding;

/// 运行权限检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(suid::check()),
        tokio::spawn(sgid::check()),
        tokio::spawn(capabilities::check()),
        tokio::spawn(world_writable_files::check()),
        tokio::spawn(ld_so::check()),
        tokio::spawn(root_paths::check()),
        tokio::spawn(cred_files::check()),
        tokio::spawn(acls::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

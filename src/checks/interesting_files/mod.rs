pub mod sh_files_in_path;

use crate::Finding;

/// 运行所有有趣文件检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![tokio::spawn(sh_files_in_path::check())];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

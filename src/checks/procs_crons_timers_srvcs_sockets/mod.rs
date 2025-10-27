pub mod processes;
pub mod cron_jobs;

use crate::Finding;

/// 运行所有进程/定时任务/服务检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(processes::check()),
        tokio::spawn(cron_jobs::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

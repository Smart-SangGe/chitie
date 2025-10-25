use crate::Finding;
use crate::checks;

/// 运行所有检查
pub async fn run_all_checks() -> anyhow::Result<Vec<Finding>> {
    // 创建所有检查任务
    let tasks = vec![
        tokio::spawn(checks::system_information::run()),
        tokio::spawn(checks::container::run()),
        // tokio::spawn(checks::permissions::run()),
        // tokio::spawn(checks::cloud::run()),
        // tokio::spawn(checks::processes::run()),
        // tokio::spawn(checks::network::run()),
        // tokio::spawn(checks::users::run()),
        // tokio::spawn(checks::software::run()),
        // tokio::spawn(checks::files::run()),
        // tokio::spawn(checks::secrets::run()),
    ];

    // 收集所有结果
    let mut all_findings = Vec::new();
    for task in tasks {
        let findings = task.await??;
        all_findings.extend(findings);
    }

    // 按严重程度排序
    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    Ok(all_findings)
}

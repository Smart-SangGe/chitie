use crate::Finding;
use crate::checks;
use crate::config::config;

/// 运行所有检查
pub async fn run_all_checks() -> anyhow::Result<Vec<Finding>> {
    let cfg = config();

    // 解析 only_modules 参数
    let enabled_modules = if let Some(modules_str) = &cfg.only_modules {
        modules_str.split(',').map(|s| s.trim()).collect::<Vec<_>>()
    } else {
        vec![] // 空表示运行所有模块
    };

    let should_run =
        |module: &str| -> bool { enabled_modules.is_empty() || enabled_modules.contains(&module) };

    // 创建检查任务
    let mut tasks = vec![];

    if should_run("system_information") {
        tasks.push(tokio::spawn(checks::system_information::run()));
    }

    if should_run("container") {
        tasks.push(tokio::spawn(checks::container::run()));
    }

    if should_run("cloud") {
        tasks.push(tokio::spawn(checks::cloud::run()));
    }

    if should_run("users_information") {
        tasks.push(tokio::spawn(checks::users_information::run()));
    }

    if should_run("interesting_perms_files") {
        tasks.push(tokio::spawn(checks::interesting_perms_files::run()));
    }

    if should_run("network_information") {
        tasks.push(tokio::spawn(checks::network_information::run()));
    }

    if should_run("software_information") {
        tasks.push(tokio::spawn(checks::software_information::run()));
    }

    if should_run("interesting_files") {
        tasks.push(tokio::spawn(checks::interesting_files::run()));
    }

    if should_run("procs_crons_timers_srvcs_sockets") {
        tasks.push(tokio::spawn(checks::procs_crons_timers_srvcs_sockets::run()));
    }

    if should_run("api_keys_regex") {
        tasks.push(tokio::spawn(checks::api_key_regex::run()));
    }

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

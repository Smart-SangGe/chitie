/// Container checks
mod am_i_contained;
mod breakout;
mod details;
mod docker_details;
mod mounted_tokens;
mod rw_bind_mounts;
mod tools;

use crate::Finding;

/// 运行容器检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(tools::check()),
        tokio::spawn(details::check()),
        tokio::spawn(mounted_tokens::check()),
        tokio::spawn(docker_details::check()),
        tokio::spawn(breakout::check()),
        tokio::spawn(rw_bind_mounts::check()),
        // TODO: 待手动实现
        // tokio::spawn(am_i_contained::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

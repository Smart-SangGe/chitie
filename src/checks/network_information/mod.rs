pub mod firewall;
pub mod hostname_dns;
pub mod inetdconf;
pub mod interfaces;
pub mod internet_access;
pub mod network_neighbours;
pub mod open_ports;
pub mod tcpdump;

use crate::Finding;

/// 运行所有网络信息检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let config = crate::config::config();

    let mut handles = vec![
        tokio::spawn(interfaces::check()),
        tokio::spawn(hostname_dns::check()),
        tokio::spawn(open_ports::check()),
        tokio::spawn(tcpdump::check()),
        tokio::spawn(inetdconf::check()),
        tokio::spawn(internet_access::check()),
    ];

    if config.extra || config.all_checks {
        handles.push(tokio::spawn(network_neighbours::check()));
        handles.push(tokio::spawn(firewall::check()));
    }

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

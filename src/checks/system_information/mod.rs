/// System information checks
mod cpu;
mod cve_2021_3560;
mod datetime;
mod disks;
mod disks_extra;
mod dmesg;
mod environment;
mod exploit_suggester;
mod kernel_modules;
mod mounts;
mod os;
mod path;
mod protections;
mod sudo;
mod usb;

use crate::Finding;

/// 运行系统信息检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let config = crate::config::config();

    let mut handles = vec![
        tokio::spawn(os::check()),
        tokio::spawn(sudo::check()),
        tokio::spawn(path::check()),
        tokio::spawn(mounts::check()),
        tokio::spawn(disks::check()),
        tokio::spawn(environment::check()),
        tokio::spawn(kernel_modules::check()),
        tokio::spawn(exploit_suggester::check()),
    ];

    if config.extra || config.all_checks {
        handles.push(tokio::spawn(cpu::check()));
        handles.push(tokio::spawn(cve_2021_3560::check()));
        handles.push(tokio::spawn(disks_extra::check()));
        handles.push(tokio::spawn(dmesg::check()));
        handles.push(tokio::spawn(protections::check()));
        handles.push(tokio::spawn(usb::check()));
        handles.push(tokio::spawn(datetime::check()));
    }

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

pub mod processes;
pub mod cron_jobs;
pub mod process_binaries_perms;
pub mod processes_ppid_different_user;
pub mod files_open_by_other_users;
pub mod system_timers;
pub mod services;
pub mod systemd_info;
pub mod socket_files;
pub mod unix_sockets;
pub mod rcommands_trust;

use crate::Finding;

/// 运行所有进程/定时任务/服务检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(processes::check()),
        tokio::spawn(process_binaries_perms::check()),
        tokio::spawn(processes_ppid_different_user::check()),
        tokio::spawn(files_open_by_other_users::check()),
        tokio::spawn(cron_jobs::check()),
        tokio::spawn(system_timers::check()),
        tokio::spawn(services::check()),
        tokio::spawn(systemd_info::check()),
        tokio::spawn(socket_files::check()),
        tokio::spawn(unix_sockets::check()),
        tokio::spawn(rcommands_trust::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

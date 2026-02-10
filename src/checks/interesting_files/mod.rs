pub mod backup_files;
pub mod database_files;
pub mod environment_variables;
pub mod executable_files;
pub mod hidden_files;
pub mod history_files;
pub mod log_analysis;
pub mod mail_files;
pub mod modified_last_5mins;
pub mod others_homes;
pub mod sensitive_files;
pub mod sh_files_in_path;
pub mod tmp_files;
pub mod tty_passwords;
pub mod unexpected_files;
pub mod web_files;
pub mod writable_log_files;

use crate::Finding;

pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let handles = vec![
        tokio::spawn(executable_files::check()),
        tokio::spawn(modified_last_5mins::check()),
        tokio::spawn(sh_files_in_path::check()),
        tokio::spawn(backup_files::check()),
        tokio::spawn(hidden_files::check()),
        tokio::spawn(sensitive_files::run()),
        tokio::spawn(history_files::run()),
        tokio::spawn(log_analysis::run()),
        tokio::spawn(database_files::check()),
        tokio::spawn(mail_files::check()),
        tokio::spawn(web_files::check()),
        tokio::spawn(others_homes::check()),
        tokio::spawn(environment_variables::check()),
        tokio::spawn(writable_log_files::check()),
        tokio::spawn(unexpected_files::check()),
        tokio::spawn(tmp_files::check()),
        tokio::spawn(tty_passwords::check()),
    ];

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

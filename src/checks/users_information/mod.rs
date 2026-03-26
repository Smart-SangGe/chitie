/// Users information checks
mod all_users_groups;
mod clipboard;
mod doas;
mod last_logons;
mod logged_in_users;
mod my_user;
mod password_policy;
mod pgp_keys;
mod pkexec;
mod sudo_permissions;
mod sudo_token;
mod superusers;
mod su_bruteforce;
mod users_with_console;

use crate::Finding;
use crate::config::config;

/// 运行用户信息检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let cfg = config();
    let mut handles = vec![
        tokio::spawn(my_user::check()),
        tokio::spawn(sudo_permissions::check()),
        tokio::spawn(pgp_keys::check()),
        tokio::spawn(clipboard::check()),
        tokio::spawn(sudo_token::check()),
        tokio::spawn(doas::check()),
        tokio::spawn(pkexec::check()),
        tokio::spawn(superusers::check()),
        tokio::spawn(users_with_console::check()),
        tokio::spawn(all_users_groups::check()),
        tokio::spawn(logged_in_users::check()),
        tokio::spawn(last_logons::check()),
        tokio::spawn(password_policy::check()),
    ];

    // Keep dangerous and very slow checks aligned with -a behavior.
    if cfg.all_checks {
        handles.push(tokio::spawn(su_bruteforce::check()));
    }

    let mut findings = Vec::new();
    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

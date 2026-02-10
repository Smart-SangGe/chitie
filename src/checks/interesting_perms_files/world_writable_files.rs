use crate::{Category, Finding, Severity};
use nix::unistd::getuid;
use regex::Regex;
use std::env;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use walkdir::WalkDir;

///  Interesting Permissions - Writable files by ownership or all
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Interesting writable files owned by me or writable by everyone (not in Home)
///  Corresponds to LinPEAS: 14_Writable_files_owner_all.sh
pub async fn check() -> Option<Finding> {
    let config = crate::config::config();

    let mut finding = Finding::new(
        Category::Permission,
        Severity::Medium,
        "Writable files owned by me or world-writable",
        "Interesting writable files owned by current user or writable by everyone (not in Home)",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files");

    let current_uid = getuid().as_raw();
    let home_dir = env::var("HOME").unwrap_or_default();
    let exclude_dirs = vec!["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"];

    // Compile regex patterns from LinPEAS variables
    let not_extensions = Regex::new(r"(?i)\.tif$|\.tiff$|\.gif$|\.jpeg$|\.jpg|\.jif$|\.jfif$|\.jp2$|\.jpx$|\.j2k$|\.j2c$|\.fpx$|\.pcd$|\.png$|\.pdf$|\.flv$|\.mp4$|\.mp3$|\.gifv$|\.avi$|\.mov$|\.mpeg$|\.wav$|\.doc$|\.docx$|\.xls$|\.xlsx$|\.svg$").unwrap();
    
    // writeVB: Very Bad (Critical)
    let write_vb = Regex::new(r"/etc/anacrontab|/etc/apt/apt.conf.d|/etc/bash.bashrc|/etc/bash_completion|/etc/bash_completion.d/|/etc/cron|/etc/environment|/etc/environment.d/|/etc/group|/etc/incron.d/|/etc/init|/etc/ld.so.conf.d/|/etc/master.passwd|/etc/passwd|/etc/profile.d/|/etc/profile|/etc/rc.d|/etc/shadow|/etc/skey/|/etc/sudoers|/etc/sudoers.d/|/etc/supervisor/conf.d/|/etc/supervisor/supervisord.conf|/etc/systemd|/etc/sys|/lib/systemd|/etc/update-motd.d/|/root/.ssh/|/run/systemd|/usr/lib/cron/tabs/|/usr/lib/systemd|/systemd/system|/var/db/yubikey/|/var/spool/anacron|/var/spool/cron/crontabs").unwrap();
    
    // writeB: Bad (High)
    let write_b = Regex::new(r"00-header|10-help-text|50-motd-news|80-esm|91-release-upgrade|\.sh$|\./|/authorized_keys|/bin/|/boot/|/etc/apache2/apache2.conf|/etc/apache2/httpd.conf|/etc/hosts.allow|/etc/hosts.deny|/etc/httpd/conf/httpd.conf|/etc/httpd/httpd.conf|/etc/inetd.conf|/etc/incron.conf|/etc/login.defs|/etc/logrotate.d/|/etc/modprobe.d/|/etc/pam.d/|/etc/php.*/fpm/pool.d/|/etc/php/.*/fpm/pool.d/|/etc/rsyslog.d/|/etc/skel/|/etc/sysconfig/network-scripts/|/etc/sysctl.conf|/etc/sysctl.d/|/etc/uwsgi/apps-enabled/|/etc/xinetd.conf|/etc/xinetd.d/|/etc/|/home//|/lib/|/log/|/mnt/|/root|/sys/|/usr/bin|/usr/games|/usr/lib|/usr/local/bin|/usr/local/games|/usr/local/sbin|/usr/sbin|/sbin/|/var/log/|\.timer$|\.service$|.socket$").unwrap();

    let mut results = Vec::new();

    let search_paths = if config.stealth {
        vec!["/etc", "/usr", "/bin", "/sbin", "/opt", "/var"]
    } else {
        vec!["/"]
    };

    let max_depth = if config.stealth { 5 } else { 15 };

    for search_path in search_paths {
        for entry in WalkDir::new(search_path)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            let path_str = path.display().to_string();

            // 1. Exclude common dirs and HOME
            if exclude_dirs.iter().any(|&d| path_str.starts_with(d)) {
                continue;
            }
            if !home_dir.is_empty() && path_str.starts_with(&home_dir) {
                continue;
            }

            // 2. Exclude by extension
            if not_extensions.is_match(&path_str) {
                continue;
            }

            if let Ok(metadata) = entry.metadata() {
                let mode = metadata.permissions().mode();
                let uid = metadata.uid();

                // Logic: (Owned by user) OR (World writable)
                let is_owned_by_me = uid == current_uid;
                let is_world_writable = mode & 0o002 != 0;

                if is_owned_by_me || is_world_writable {
                    // 3. Determine Severity based on LinPEAS logic
                    let (severity_str, item_severity) = if write_vb.is_match(&path_str) {
                        ("CRITICAL", Severity::Critical)
                    } else if write_b.is_match(&path_str) {
                        ("HIGH", Severity::High)
                    } else {
                        ("MEDIUM", Severity::Medium)
                    };

                    if item_severity > finding.severity {
                        finding.severity = item_severity;
                    }

                    let type_str = if path.is_dir() { "DIR" } else { "FILE" };
                    let reason = if is_owned_by_me && is_world_writable {
                        "owned & world-writable"
                    } else if is_owned_by_me {
                        "owned"
                    } else {
                        "world-writable"
                    };

                    results.push(format!("[{}] {} {} (mode: {:o}, {})", severity_str, type_str, path_str, mode & 0o777, reason));
                }
            }

            if results.len() >= 200 { break; }
        }
        if results.len() >= 200 { break; }
    }

    if results.is_empty() {
        return None;
    }

    finding.details.push(format!("Found {} files/dirs (max 200):", results.len()));
    finding.details.extend(results);

    Some(finding)
}
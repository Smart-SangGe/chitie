use crate::{Category, Finding, Severity};
use regex::Regex;
use std::collections::HashSet;
use std::fs;

///  Interesting Files - Interesting Environment Variables
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching possible sensitive environment variables inside of /proc/*/environ
///  Corresponds to LinPEAS: 29_Interesting_environment_variables.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Interesting Environment Variables",
        "Searching possible sensitive environment variables inside of /proc/*/environ",
    );

    let mut env_vars = HashSet::new();
    
    // Patterns from LinPEAS
    let no_env_vars_re = Regex::new(r"(?i)LESS_TERMCAP|JOURNAL_STREAM|XDG_SESSION|DBUS_SESSION|systemd/sessions|systemd_exec|MEMORY_PRESSURE_WATCH|RELEVANT*|FIND*|^VERSION=|dbuslistG|mygroups|ldsoconfdG|pwd_inside_history|^sudovB=|^rootcommon=|^mounted=|^mountG=|^notmounted=|^mountpermsB=|^mountpermsG=|^kernelB=|^C=|^RED=|^GREEN=|^Y=|^B=|^NC=|TIMEOUT=|groupsB=|groupsVB=|knw_grps=|sidG|sidB=|sidVB=|sidVB2=|sudoB=|sudoG=|sudoVB=|timersG=|capsB=|notExtensions=|Wfolders=|writeB=|writeVB=|_usrs=|compiler=|LS_COLORS=|pathshG=|notBackup=|processesDump|processesB|commonrootdirs|USEFUL_SOFTWARE|PSTORAGE_|^PATH=|^INVOCATION_ID=|^WATCHDOG_PID=|^LISTEN_PID=").unwrap();
    let env_vars_red_re = Regex::new(r"(?i)[pP][aA][sS][sS][wW]|[aA][pP][iI][kK][eE][yY]|[aA][pP][iI][_][kK][eE][yY]|KRB5CCNAME|[aA][pP][iI]|[sS][eE][cC][rR][eE][tT]|[sS][qQ][lL]|[dD][aA][tT][aA][bB][aA][sS][eE]|[tT][oO][kK][eE][nN]").unwrap();

    // Iterate over /proc/[0-9]*/environ
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.chars().all(|c| c.is_ascii_digit()) {
                let environ_path = entry.path().join("environ");
                if let Ok(content) = fs::read(environ_path) {
                    // Split by null byte
                    for part in content.split(|&b| b == 0) {
                        let var = String::from_utf8_lossy(part).to_string();
                        if !var.is_empty() && !no_env_vars_re.is_match(&var) {
                            env_vars.insert(var);
                        }
                    }
                }
            }
        }
    }

    if env_vars.is_empty() {
        return None;
    }

    let mut details = Vec::new();
    let mut sorted_vars: Vec<String> = env_vars.into_iter().collect();
    sorted_vars.sort();

    for var in sorted_vars {
        if env_vars_red_re.is_match(&var) {
            details.push(format!("[!] SENSITIVE: {}", var));
            if finding.severity < Severity::Medium {
                finding.severity = Severity::Medium;
            }
        } else {
            details.push(var);
        }
    }

    if details.len() > 500 {
        details.truncate(500);
        details.push("... and more (truncated)".to_string());
    }

    finding.details = details;
    Some(finding)
}

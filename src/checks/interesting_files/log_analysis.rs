use crate::{Category, Finding, Severity};
use grep::regex::RegexMatcher;
use grep::searcher::{BinaryDetection, Searcher, SearcherBuilder, Sink, SinkMatch};
use ignore::WalkBuilder;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

///  Interesting Files - Log Analysis
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Extracting IPs, emails, and searching for passwords in logs
///  Corresponds to LinPEAS: 25_IPs_logs.sh, 26_Mails_addr_inside_logs.sh, 27_Passwords_in_logs.sh
pub async fn run() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Log Analysis",
        "Analyzing logs for IPs, emails, and sensitive information",
    );

    let start_time = Instant::now();
    let timeout = Duration::from_secs(120); // 2 minutes for logs

    // IP Regex
    let ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b";
    // Email Regex
    let email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b";
    // Password Keywords in logs
    let pwd_pattern = r"(?i)password|passwd|login|failed|authentication|auth|secret";

    let combined_pattern = format!("({})|({})|({})", ip_pattern, email_pattern, pwd_pattern);
    let matcher = match RegexMatcher::new_line_matcher(&combined_pattern) {
        Ok(m) => m,
        Err(_) => return None,
    };

    let ips = Arc::new(Mutex::new(HashSet::new()));
    let emails = Arc::new(Mutex::new(HashSet::new()));
    let pwd_matches = Arc::new(Mutex::new(Vec::new()));

    let ips_clone = ips.clone();
    let emails_clone = emails.clone();
    let pwd_clone = pwd_matches.clone();

    // Re-compile individual regexes for classification
    let ip_re = regex::Regex::new(ip_pattern).unwrap();
    let email_re = regex::Regex::new(email_pattern).unwrap();
    let pwd_re = regex::Regex::new(pwd_pattern).unwrap();

    let log_dir = "/var/log";
    if !std::path::Path::new(log_dir).exists() {
        return None;
    }

    let mut builder = WalkBuilder::new(log_dir);
    builder.threads(4).max_depth(Some(5)).filter_entry(|e| {
        if e.file_type().map_or(false, |ft| ft.is_file()) {
            let name = e.file_name().to_string_lossy();
            // Skip rotated logs to save time unless requested
            return !name.contains(".gz") && !name.contains(".xz");
        }
        true
    });

    builder.build_parallel().run(move || {
        let matcher = matcher.clone();
        let ips = ips_clone.clone();
        let emails = emails_clone.clone();
        let pwds = pwd_clone.clone();
        let ip_re = ip_re.clone();
        let email_re = email_re.clone();
        let pwd_re = pwd_re.clone();

        Box::new(move |entry| {
            if start_time.elapsed() > timeout {
                return ignore::WalkState::Quit;
            }

            let entry = match entry {
                Ok(e) => e,
                Err(_) => return ignore::WalkState::Continue,
            };

            if !entry.file_type().map_or(false, |ft| ft.is_file()) {
                return ignore::WalkState::Continue;
            }

            let path = entry.path().to_owned();

            // Limit log file size for analysis
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 5 * 1024 * 1024 {
                    // 5MB limit
                    return ignore::WalkState::Continue;
                }
            }

            struct LogSink {
                path: std::path::PathBuf,
                ips: Arc<Mutex<HashSet<String>>>,
                emails: Arc<Mutex<HashSet<String>>>,
                pwds: Arc<Mutex<Vec<String>>>,
                ip_re: regex::Regex,
                email_re: regex::Regex,
                pwd_re: regex::Regex,
                pwd_count: usize,
            }

            impl Sink for LogSink {
                type Error = std::io::Error;
                fn matched(
                    &mut self,
                    _searcher: &Searcher,
                    mat: &SinkMatch,
                ) -> Result<bool, Self::Error> {
                    let line = String::from_utf8_lossy(mat.bytes());

                    // Extract IPs
                    for m in self.ip_re.find_iter(&line) {
                        let mut guard = self.ips.lock().unwrap();
                        guard.insert(m.as_str().to_string());
                        if guard.len() > 1000 {
                            break;
                        }
                    }

                    // Extract Emails
                    for m in self.email_re.find_iter(&line) {
                        let mut guard = self.emails.lock().unwrap();
                        guard.insert(m.as_str().to_string());
                        if guard.len() > 1000 {
                            break;
                        }
                    }

                    // Extract Password related lines
                    if self.pwd_re.is_match(&line) && self.pwd_count < 10 {
                        let mut guard = self.pwds.lock().unwrap();
                        guard.push(format!("{}: {}", self.path.display(), line.trim()));
                        self.pwd_count += 1;
                    }

                    Ok(true)
                }
            }

            let mut searcher = SearcherBuilder::new()
                .binary_detection(BinaryDetection::quit(b'\x00'))
                .build();

            let mut sink = LogSink {
                path: path.clone(),
                ips: ips.clone(),
                emails: emails.clone(),
                pwds: pwds.clone(),
                ip_re: ip_re.clone(),
                email_re: email_re.clone(),
                pwd_re: pwd_re.clone(),
                pwd_count: 0,
            };

            let _ = searcher.search_path(&matcher, &path, &mut sink);

            ignore::WalkState::Continue
        })
    });

    let mut details = Vec::new();

    let collected_ips = ips.lock().unwrap();
    if !collected_ips.is_empty() {
        details.push(format!(
            "Found {} unique IP addresses in logs (showing 20):",
            collected_ips.len()
        ));
        details.extend(collected_ips.iter().take(20).map(|s| format!("  - {}", s)));
    }

    let collected_emails = emails.lock().unwrap();
    if !collected_emails.is_empty() {
        details.push(format!(
            "Found {} unique email addresses in logs (showing 10):",
            collected_emails.len()
        ));
        details.extend(
            collected_emails
                .iter()
                .take(10)
                .map(|s| format!("  - {}", s)),
        );
    }

    let collected_pwds = pwd_matches.lock().unwrap();
    if !collected_pwds.is_empty() {
        details.push(format!(
            "Found {} lines with password keywords in logs (showing 20):",
            collected_pwds.len()
        ));
        details.extend(collected_pwds.iter().take(20).map(|s| format!("  - {}", s)));
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

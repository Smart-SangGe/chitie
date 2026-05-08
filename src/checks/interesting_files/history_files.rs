use crate::{Category, Finding, Severity};
use grep::regex::RegexMatcher;
use grep::searcher::{BinaryDetection, Searcher, SearcherBuilder, Sink, SinkMatch};
use ignore::WalkBuilder;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

///  Interesting Files - Passwords in History Files
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching passwords in shell history files
///  Corresponds to LinPEAS: 20_Passwords_history_cmd.sh and 21_Passwords_history_files.sh
pub async fn run() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::High,
        "Passwords in History Files",
        "Searching for credentials and sensitive commands in shell history files",
    );

    let start_time = Instant::now();
    let timeout = Duration::from_secs(60); // 1 minute timeout for history check

    // Pattern from LinPEAS: pwd_inside_history
    let pattern = r"(?i)az login|enable_autologin|7z|unzip|useradd|linenum|linpeas|mkpasswd|htpasswd|openssl|PASSW|passw|shadow|roadrecon auth|root|snyk|sudo|^su|pkexec|^ftp|mongo|psql|mysql|rdesktop|Save-AzContext|xfreerdp|^ssh|steghide|@|KEY=|TOKEN=|BEARER=|Authorization:|chpasswd";

    let matcher = match RegexMatcher::new_line_matcher(pattern) {
        Ok(m) => m,
        Err(_) => return None,
    };

    let results_collector = Arc::new(Mutex::new(Vec::new()));
    let results_clone = results_collector.clone();

    // Common history files
    let history_files_patterns = vec![
        ".bash_history",
        ".zsh_history",
        ".python_history",
        ".mysql_history",
        ".psql_history",
        ".nano_history",
        ".viminfo",
        ".lesshst",
        ".history",
    ];

    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/home".to_string());

    // We search in /home and /root
    let mut builder = WalkBuilder::new("/home");
    if std::path::Path::new("/root").exists() {
        builder.add("/root");
    }

    builder
        .threads(4)
        .hidden(true) // History files are hidden
        .max_depth(Some(5))
        .filter_entry(move |e| {
            let name = e.file_name().to_string_lossy();
            if e.file_type().map_or(false, |ft| ft.is_dir()) {
                return name != ".git" && name != "node_modules";
            }
            // Only search for history files
            history_files_patterns.iter().any(|&p| name.ends_with(p))
        });

    builder.build_parallel().run(move || {
        let matcher = matcher.clone();
        let results = results_clone.clone();

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

            struct HistorySink {
                path: std::path::PathBuf,
                results: Arc<Mutex<Vec<String>>>,
            }

            impl Sink for HistorySink {
                type Error = std::io::Error;
                fn matched(
                    &mut self,
                    _searcher: &Searcher,
                    mat: &SinkMatch,
                ) -> Result<bool, Self::Error> {
                    let line = String::from_utf8_lossy(mat.bytes()).trim().to_string();
                    if !line.is_empty() {
                        let mut guard = self.results.lock().unwrap();
                        guard.push(format!("{}: {}", self.path.display(), line));
                    }
                    Ok(true)
                }
            }

            let mut searcher = SearcherBuilder::new()
                .binary_detection(BinaryDetection::quit(b'\x00'))
                .build();

            let mut sink = HistorySink {
                path: path.clone(),
                results: results.clone(),
            };

            let _ = searcher.search_path(&matcher, &path, &mut sink);

            ignore::WalkState::Continue
        })
    });

    let collected = results_collector.lock().unwrap();
    if collected.is_empty() {
        return None;
    }

    finding.details.push(format!(
        "Found {} sensitive entries in history files:",
        collected.len()
    ));
    finding.details.extend(collected.iter().take(100).cloned());
    if collected.len() > 100 {
        finding
            .details
            .push(format!("... and {} more", collected.len() - 100));
    }

    Some(finding)
}

use crate::{Category, Finding, Severity};
use grep::searcher::{BinaryDetection, Searcher, SearcherBuilder, Sink, SinkMatch};
use grep::regex::RegexMatcher;
use ignore::WalkBuilder;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

///  Interesting Files - Sensitive Files (Passwords/Credentials)
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching possible password variables inside key folders and config files
///  Corresponds to LinPEAS: 22_Passwords_php_files.sh and 28_Files_with_passwords.sh
pub async fn run() -> Option<Finding> {
    let config = crate::config::config();

    let mut finding = Finding::new(
        Category::File,
        Severity::High,
        "Sensitive Files (Passwords/Credentials)",
        "Searching possible password variables inside key folders and config files",
    );

    let start_time = Instant::now();
    let timeout = Duration::from_secs(180); // 3 minutes timeout

    // Core patterns from LinPEAS variables
    let patterns = vec![
        r"(?i)(pwd|passwd|password|dbuser|dbpass|dbpassword).*[=:].+",
        r"(?i)define ?\('(\w*passw|\w*user|\w*datab)",
        r"(?i)kind:\W?Secret|\Wenv:|\Wsecret:|\WsecretName:",
        r"(?i)GITHUB_TOKEN|AWS_SECRET|ACCESS_KEY|AUTH_TOKEN|API_KEY",
        r"(?i)JDBC:MYSQL|jdbc_databaseurl|jdbc_host|jdbc_user",
    ];

    let combined_pattern = patterns.join("|");
    let matcher = match RegexMatcher::new_line_matcher(&combined_pattern) {
        Ok(m) => m,
        Err(_) => return None,
    };
    
    // Shared results collector
    let results_collector = Arc::new(Mutex::new(Vec::new()));
    let results_clone = results_collector.clone();

    // Key folders to search
    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/home".to_string());
    let search_dirs = vec![
        home_dir,
        "/var/www".to_string(),
        "/etc".to_string(),
        "/opt".to_string(),
        "/tmp".to_string(),
        "/mnt".to_string(),
    ];

    let mut builder = WalkBuilder::new(&search_dirs[0]);
    for dir in &search_dirs[1..] {
        if std::path::Path::new(dir).exists() {
            builder.add(dir);
        }
    }

    builder
        .threads(4)
        .hidden(false)
        .max_depth(Some(8))
        .filter_entry(|e| {
            let path = e.path();
            if path.is_dir() {
                let name = e.file_name().to_string_lossy();
                if name == "node_modules" || name == ".git" || name == "proc" || name == "sys" {
                    return false;
                }
            }
            true
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
            
            // Limit file size to 1MB for content searching
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 1024 * 1024 {
                    return ignore::WalkState::Continue;
                }
            }

            struct SensitiveSink {
                path: std::path::PathBuf,
                results: Arc<Mutex<Vec<String>>>,
                count: usize,
            }

            impl Sink for SensitiveSink {
                type Error = std::io::Error;
                fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch) -> Result<bool, Self::Error> {
                    let line = String::from_utf8_lossy(mat.bytes()).trim().to_string();
                    if line.len() < 200 { // Skip extremely long lines
                        let mut guard = self.results.lock().unwrap();
                        guard.push(format!("{}: {}", self.path.display(), line));
                        self.count += 1;
                    }
                    if self.count >= 3 { Ok(false) } else { Ok(true) }
                }
            }

            let mut searcher = SearcherBuilder::new()
                .binary_detection(BinaryDetection::quit(b'\x00'))
                .build();

            let mut sink = SensitiveSink {
                path: path.clone(),
                results: results.clone(),
                count: 0,
            };

            let _ = searcher.search_path(&matcher, &path, &mut sink);

            ignore::WalkState::Continue
        })
    });

    let collected = results_collector.lock().unwrap();
    if collected.is_empty() {
        return None;
    }

    finding.details.push(format!("Found {} possible matches (showing top 100):", collected.len()));
    finding.details.extend(collected.iter().take(100).cloned());

    Some(finding)
}
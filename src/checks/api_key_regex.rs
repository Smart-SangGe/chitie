use crate::{Category, Finding, Severity};
use grep::regex::RegexMatcher;
use grep::searcher::{BinaryDetection, Searcher, SearcherBuilder, Sink, SinkMatch};
use ignore::WalkBuilder;
use regex::Regex;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

///  API Keys Regex
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Search for API keys and secrets using ripgrep libraries
///
///  Checks for:
///  - AWS Access Keys
///  - Google Cloud Keys
///  - Slack Tokens
///  - Private Keys (RSA, DSA, EC, OPENSSH)
///  - Generic API Keys
///  - Azure Keys
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#api-keys
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let config = crate::config::config();

    // Only run if -r is enabled or specifically requested
    if !config.regex_secrets {
        return Ok(vec![]);
    }

    let mut finding = Finding::new(
        Category::Secret,
        Severity::High,
        "API Keys & Secrets",
        "Search for API keys and secrets in files (High Performance)",
    );

    let mut details = Vec::new();
    let start_time = Instant::now();
    let timeout = Duration::from_secs(300); // 5 minutes timeout

    // Define regex patterns with names
    let patterns_data = vec![
        ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
        ("AWS Secret Access Key", r"(?i)aws_secret_access_key\s*=\s*[a-zA-Z0-9/+] {40}"),
        ("Google Cloud API Key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Google OAuth Access Token", r"ya29\.[0-9A-Za-z\-_]+"),
        ("Slack Token", r"xox[baprs]-([0-9a-zA-Z]{10,48})"),
        ("Private Key", r"-----BEGIN [A-Z]+ PRIVATE KEY-----"),
        ("Generic API Key", r#"(?i)(api_key|apikey|secret|token)\s*[:=]\s*['"][a-zA-Z0-9\-_]{16,64}['"]"#),
        ("Azure Shared Key", r"DefaultEndpointsProtocol=[^;]+;AccountName=[^;]+;AccountKey=[^;]+;"),
        ("Facebook Access Token", r"EAACEdEose0cBA[0-9A-Za-z]+"),
        ("GitHub Personal Access Token", r"ghp_[0-9a-zA-Z]{36}"),
        ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24}"),
        ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24}"),
    ];

    // 1. Build a combined regex for grep (fast filtering)
    let pattern_strings: Vec<String> = patterns_data.iter().map(|(_, p)| format!("({})", p)).collect();
    let combined_pattern = pattern_strings.join("|");
    let matcher = RegexMatcher::new_line_matcher(&combined_pattern)?;

    // 2. Pre-compile individual regexes for classification (fast local check)
    let mut compiled_patterns = Vec::new();
    for (name, pat) in &patterns_data {
        if let Ok(re) = Regex::new(pat) {
            compiled_patterns.push((*name, re));
        }
    }
    // Shared patterns for threads
    let compiled_patterns = Arc::new(compiled_patterns);

    // Directories to search
    let search_dirs = vec![
        "/home",
        "/etc",
        "/opt",
        "/var/www",
        "/var/lib/jenkins",
        "/root",
    ];

    // Shared results collector
    let results = Arc::new(Mutex::new(Vec::new()));
    let results_clone = results.clone();

    // Build the parallel walker
    let mut builder = WalkBuilder::new(&search_dirs[0]);
    for dir in &search_dirs[1..] {
        builder.add(dir);
    }
    
    // Configure walker
    builder
        .threads(4) // Parallelism
        .hidden(false) // Search hidden files
        .git_ignore(false) // Don't respect gitignore
        .ignore(false) // Don't respect .ignore
        .max_depth(Some(10))
        .filter_entry(|e| {
            // Filter out obviously bad directories
            let path = e.path();
            if path.is_dir() {
                let name = e.file_name().to_string_lossy();
                if name == "node_modules" || name == ".git" || name == "proc" || name == "sys" || name == "dev" {
                    return false;
                }
            }
            true
        });

    // Run parallel search
    builder.build_parallel().run(move || {
        let matcher = matcher.clone();
        let results = results_clone.clone();
        let compiled_patterns = compiled_patterns.clone();
        
        Box::new(move |entry| {
            // Check timeout
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
            
            if let Ok(metadata) = entry.metadata() {
                if metadata.len() > 10 * 1024 * 1024 { // Skip > 10MB
                    return ignore::WalkState::Continue;
                }
            }

            let path = entry.path().to_owned();
            
            // Matcher sink
            struct MatchCollector {
                path: std::path::PathBuf,
                results: Arc<Mutex<Vec<String>>>,
                compiled_patterns: Arc<Vec<(&'static str, Regex)>>,
                match_count: usize,
            }

            impl Sink for MatchCollector {
                type Error = std::io::Error;

                fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch) -> Result<bool, Self::Error> {
                    let line = String::from_utf8_lossy(mat.bytes());
                    
                    // Identify which pattern matched
                    for (name, re) in self.compiled_patterns.iter() {
                        if re.is_match(&line) {
                            if let Some(m) = re.find(&line) {
                                let match_str = m.as_str().trim();
                                let display_str = if match_str.len() > 60 {
                                    format!("{}...", &match_str[..57])
                                } else {
                                    match_str.to_string()
                                };

                                let mut guard = self.results.lock().unwrap();
                                guard.push(format!("FOUND {}: {} in {}", name, display_str, self.path.display()));
                                
                                self.match_count += 1;
                                break; // Only report the first matching type per line to avoid duplicates
                            }
                        }
                    }

                    if self.match_count >= 5 {
                        Ok(false)
                    } else {
                        Ok(true)
                    }
                }
            }

            let mut searcher = SearcherBuilder::new()
                .binary_detection(BinaryDetection::quit(b'\x00')) // Skip binary files
                .line_number(false)
                .build();

            let mut collector = MatchCollector {
                path: path.clone(),
                results: results.clone(),
                compiled_patterns: compiled_patterns.clone(),
                match_count: 0,
            };

            let _ = searcher.search_path(&matcher, &path, &mut collector);

            ignore::WalkState::Continue
        })
    });

    let collected_results = results.lock().unwrap();
    
    if collected_results.is_empty() {
        return Ok(vec![]);
    }

    details.push(format!("Scan completed in {:.2?}s", start_time.elapsed()));
    details.push(format!("Found {} secrets:", collected_results.len()));
    details.extend(collected_results.clone());

    finding.details = details;
    Ok(vec![finding])
}

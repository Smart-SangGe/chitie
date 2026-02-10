use crate::{Category, Finding, Severity};
use grep::searcher::{BinaryDetection, Searcher, SearcherBuilder, Sink, SinkMatch};
use grep::regex::RegexMatcher;
use std::process::Command;
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

///  Interesting Files - TTY Passwords (Audit logs)
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Checking for TTY passwords in audit logs via aureport and log files
///  Corresponds to LinPEAS: 24_Passwords_TTY.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "TTY Passwords (Audit Logs)",
        "Checking for passwords entered in TTYs (captured by auditd)",
    );

    let mut details = Vec::new();

    // 1. Try aureport --tty
    if let Ok(output) = Command::new("aureport").arg("--tty").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut found_any = false;
            for line in stdout.lines() {
                if line.contains("su ") || line.contains("sudo ") {
                    details.push(format!("aureport: {}", line.trim()));
                    found_any = true;
                }
            }
            if found_any {
                finding.severity = Severity::High;
            }
        }
    }

    // 2. Search in /var/log/ for audit logs with su/sudo commands
    let pattern = r#"comm="su"|comm="sudo""#;
    let matcher = RegexMatcher::new_line_matcher(pattern).unwrap();
    let logs_found = Arc::new(Mutex::new(Vec::new()));
    let logs_clone = logs_found.clone();

    for entry in WalkDir::new("/var/log")
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        
        let path = entry.path().to_owned();
        let logs_clone_inner = logs_clone.clone();
        let matcher_inner = matcher.clone();

        struct AuditSink {
            path: std::path::PathBuf,
            results: Arc<Mutex<Vec<String>>>,
        }

        impl Sink for AuditSink {
            type Error = std::io::Error;
            fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch) -> Result<bool, Self::Error> {
                let line = String::from_utf8_lossy(mat.bytes()).trim().to_string();
                let mut guard = self.results.lock().unwrap();
                guard.push(format!("{}: {}", self.path.display(), line));
                Ok(true)
            }
        }

        let mut searcher = SearcherBuilder::new()
            .binary_detection(BinaryDetection::quit(b'\x00'))
            .build();
        
        let mut sink = AuditSink {
            path: path.clone(),
            results: logs_clone_inner,
        };

        let _ = searcher.search_path(&matcher_inner, &path, &mut sink);
        
        if logs_found.lock().unwrap().len() >= 50 { break; }
    }

    let collected_logs = logs_found.lock().unwrap();
    if !collected_logs.is_empty() {
        details.push("=== Potential passwords/commands in audit logs ===".to_string());
        details.extend(collected_logs.iter().take(50).cloned());
        if finding.severity < Severity::Medium {
            finding.severity = Severity::Medium;
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

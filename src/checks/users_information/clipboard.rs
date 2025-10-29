use crate::{Category, Finding, Severity};
use regex::Regex;
use std::env;
use std::process::Command;

///  User Information - Clipboard and Highlighted Text
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Check clipboard and highlighted text for sensitive information.
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#clipboard
///  - Based on LinPEAS 6_users_information/6_Clipboard_highlighted_text.sh
pub async fn check() -> Option<Finding> {
    // This check is only relevant in a graphical environment
    if env::var("DISPLAY").is_err() && env::var("WAYLAND_DISPLAY").is_err() {
        return None;
    }

    let mut finding = Finding::new(
        Category::User,
        Severity::High, // Default to High, as any finding is significant
        "Sensitive Information in Clipboard",
        "Found sensitive patterns (password, key, secret) in clipboard or highlighted text.",
    )
    .with_reference(
        "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#clipboard",
    );

    let mut details = Vec::new();

    let tools = [
        ("xclip", vec!["-o", "-selection", "clipboard"], "Clipboard"),
        ("xclip", vec!["-o"], "Highlighted Text"),
        ("xsel", vec!["-ob"], "Clipboard"),
        ("xsel", vec!["-o"], "Highlighted Text"),
        ("wl-paste", vec![], "Clipboard"),
    ];

    let patterns = [
        Regex::new(r"(?i)(password|passwd|pwd)\s*[:=].+").unwrap(),
        Regex::new(r"(?i)(token|key|secret)\s*[:=].+").unwrap(),
        Regex::new(r"(?i)ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3} ?([^@]+@[^@]+)?").unwrap(),
    ];

    for (tool, args, source) in &tools {
        if let Ok(output) = Command::new(tool).args(args).output()
            && output.status.success()
        {
            let content = String::from_utf8_lossy(&output.stdout);
            if content.trim().is_empty() {
                continue;
            }

            for pattern in &patterns {
                if let Some(mat) = pattern.find(&content) {
                    details.push(format!(
                        "Found match in {} (using '{}'):\n---\n{}---",
                        source,
                        tool,
                        mat.as_str()
                    ));
                }
            }
        }
    }

    if details.is_empty() {
        return None;
    }

    finding.details = details;
    Some(finding)
}

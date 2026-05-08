use crate::{Category, Finding, Severity};
use nix::unistd::getuid;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

///  Software Information - Terminal Sessions (Screen/Tmux)
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for active screen and tmux sessions and writable sockets
///  Corresponds to LinPEAS: Screen_sessions.sh and Tmux.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Software,
        Severity::Info,
        "Terminal Sessions (Screen/Tmux)",
        "Searching for active screen/tmux sessions and potentially hijackable sockets",
    );

    let mut details = Vec::new();
    let current_uid = getuid().as_raw();

    // 1. Screen Sessions
    if let Ok(output) = Command::new("screen").arg("-ls").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("No Sockets found") && !stdout.trim().is_empty() {
            details.push("=== Active Screen Sessions ===".to_string());
            details.push(stdout.trim().to_string());
            finding.severity = Severity::Medium;
        }
    }

    // Check screen sockets
    let screen_run_dir = "/run/screen";
    if Path::new(screen_run_dir).exists() {
        for entry in WalkDir::new(screen_run_dir)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_socket() {
                if let Ok(metadata) = entry.metadata() {
                    let uid = metadata.uid();
                    if uid != current_uid {
                        // Check if writable by us
                        if nix::unistd::access(entry.path(), nix::unistd::AccessFlags::W_OK).is_ok()
                        {
                            details.push(format!(
                                "[!] CRITICAL: Other user screen socket is writable: {}",
                                entry.path().display()
                            ));
                            finding.severity = Severity::Critical;
                        }
                    }
                }
            }
        }
    }

    // 2. Tmux Sessions
    if let Ok(output) = Command::new("tmux").arg("ls").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("no server running") && !stdout.trim().is_empty() {
            details.push("=== Active Tmux Sessions ===".to_string());
            details.push(stdout.trim().to_string());
            if finding.severity < Severity::Medium {
                finding.severity = Severity::Medium;
            }
        }
    }

    // Check tmux sockets
    let tmux_socket_dirs = vec!["/tmp", "/run/tmux"];
    for dir in tmux_socket_dirs {
        if !Path::new(dir).exists() {
            continue;
        }
        for entry in WalkDir::new(dir)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path_str = entry.path().to_string_lossy();
            if entry.file_type().is_socket() && path_str.contains("tmux") {
                if let Ok(metadata) = entry.metadata() {
                    let uid = metadata.uid();
                    if uid != current_uid {
                        if nix::unistd::access(entry.path(), nix::unistd::AccessFlags::W_OK).is_ok()
                        {
                            details.push(format!(
                                "[!] CRITICAL: Other user tmux socket is writable: {}",
                                entry.path().display()
                            ));
                            finding.severity = Severity::Critical;
                        }
                    }
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

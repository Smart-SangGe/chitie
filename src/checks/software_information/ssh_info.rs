use crate::{Category, Finding, Severity};
use std::fs;
use std::os::unix::fs::{MetadataExt, FileTypeExt};
use std::path::Path;
use walkdir::WalkDir;

///  Software Information - SSH Information
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Searching for SSH keys, agent sockets, and auditing sshd_config
///  Corresponds to LinPEAS: Ssh.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Software,
        Severity::Info,
        "SSH Information",
        "SSH configuration audit and private key discovery",
    );

    let mut details = Vec::new();

    // 1. Audit /etc/ssh/sshd_config
    let sshd_config = "/etc/ssh/sshd_config";
    if Path::new(sshd_config).exists() {
        if let Ok(content) = fs::read_to_string(sshd_config) {
            details.push("=== sshd_config Audit ===".to_string());
            let interesting_keys = [
                "PermitRootLogin", "ChallengeResponseAuthentication", "PasswordAuthentication",
                "UsePAM", "Port", "PermitEmptyPasswords", "PubkeyAuthentication",
                "ListenAddress", "ForwardAgent", "AllowAgentForwarding", "AuthorizedKeysFile"
            ];
            
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
                
                for key in &interesting_keys {
                    if trimmed.to_lowercase().contains(&key.to_lowercase()) {
                        let is_bad = (trimmed.contains("PermitRootLogin") && trimmed.to_lowercase().contains("yes")) ||
                                    (trimmed.contains("PermitEmptyPasswords") && trimmed.to_lowercase().contains("yes")) ||
                                    (trimmed.contains("PasswordAuthentication") && trimmed.to_lowercase().contains("yes"));
                        
                        if is_bad {
                            details.push(format!("[!] DANGEROUS: {}", trimmed));
                            if finding.severity < Severity::Medium {
                                finding.severity = Severity::Medium;
                            }
                        } else {
                            details.push(format!("  {}", trimmed));
                        }
                    }
                }
            }
        }
    }

    // 2. Search for private keys
    let mut private_keys = Vec::new();
    let search_dirs = vec!["/etc/ssh", "/home", "/root", "/mnt", "/tmp"];
    
    for dir in search_dirs {
        if !Path::new(dir).exists() { continue; }
        for entry in WalkDir::new(dir)
            .max_depth(4)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    if content.contains("-----BEGIN") && content.contains("PRIVATE KEY-----") {
                        private_keys.push(entry.path().display().to_string());
                    }
                }
            }
            if private_keys.len() >= 20 { break; }
        }
        if private_keys.len() >= 20 { break; }
    }

    if !private_keys.is_empty() {
        details.push("=== Private SSH Keys Found ===".to_string());
        for key in private_keys {
            details.push(format!("[!] SENSITIVE: {}", key));
            finding.severity = Severity::High;
        }
    }

    // 3. Check for writable SSH Agent sockets
    let current_uid = nix::unistd::getuid().as_raw();
    for dir in &["/tmp", "/etc", "/home"] {
        if !Path::new(dir).exists() { continue; }
        for entry in WalkDir::new(dir)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_socket() {
                let name = entry.file_name().to_string_lossy();
                if name.contains("agent.") || name.contains("gpg-agent") {
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.uid() != current_uid && nix::unistd::access(entry.path(), nix::unistd::AccessFlags::W_OK).is_ok() {
                            details.push(format!("[!] CRITICAL: Writable SSH/GPG agent socket: {}", entry.path().display()));
                            finding.severity = Severity::Critical;
                        } else {
                            details.push(format!("Found agent socket: {}", entry.path().display()));
                        }
                    }
                }
            }
        }
    }

    // 4. hosts.allow / hosts.denied
    for f in &["/etc/hosts.allow", "/etc/hosts.deny"] {
        if Path::new(f).exists() {
            if let Ok(content) = fs::read_to_string(f) {
                details.push(format!("=== {} ===", f));
                for line in content.lines().filter(|l| !l.trim().starts_with('#')).take(10) {
                    details.push(format!("  {}", line.trim()));
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
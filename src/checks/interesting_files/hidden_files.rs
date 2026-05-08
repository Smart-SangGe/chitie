use crate::{Category, Finding, Severity};
use walkdir::WalkDir;

///  Interesting Files - Hidden Files
///  Author: Sangge
///  Last Update: 2026-01-03
///  Description: Find interesting hidden files (starting with .)
///
///  Checks for:
///  - Hidden files in /home, /root, /var/www, /tmp, /dev
///  - Excludes common noise (.git, .cache, .config, etc.)
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#hidden-files
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes (limited path)
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::File,
        Severity::Info,
        "Hidden Files",
        "Hidden files might contain configuration, scripts or credentials",
    );

    // Directories to search
    let search_paths = vec!["/home", "/root", "/var/www", "/tmp", "/dev", "/opt"];

    // Ignore list (exact names or starts with)
    let ignore_names = [
        ".",
        "..",
        ".git",
        ".cache",
        ".config",
        ".local",
        ".gnupg",
        ".ssh", // .ssh is interesting but handled elsewhere? No, hidden files usually reports it.
        // Actually .ssh IS interesting, let's not ignore it.
        // We filter out boring stuff.
        ".mozilla",
        ".bash_history",
        ".zsh_history",
        ".history", // History handled elsewhere
        ".viminfo",
        ".lesshst",
        ".sudo_as_admin_successful",
        ".profile",
        ".bashrc",
        ".bash_logout",
        ".zshrc", // These are common config, not necessarily "hidden secret" but interesting.
        ".cargo",
        ".rustup",
        ".npm",
        ".yarn",
        ".node_gyp",
        ".vscode",
        ".idea",
        ".DS_Store",
    ];

    let mut hidden_files = Vec::new();

    for search_path in search_paths {
        if !std::path::Path::new(search_path).exists() {
            continue;
        }

        // We only look at depth 1 or 2 for hidden files in these dirs, otherwise it's too much.
        // LinPEAS searches recursively but filters heavily.
        let walker = WalkDir::new(search_path)
            .max_depth(3) // Limit depth
            .follow_links(false)
            .into_iter();

        for entry in walker.filter_map(Result::ok) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with('.') {
                continue;
            }

            // Filter out ignored names
            if ignore_names.contains(&name) || name.ends_with(".swp") {
                continue;
            }

            // Filter out files inside ignored directories (simple heuristic)
            let path_str = path.to_string_lossy();
            if path_str.contains("/.git/")
                || path_str.contains("/.cache/")
                || path_str.contains("/.config/")
                || path_str.contains("/node_modules/")
            {
                continue;
            }

            hidden_files.push(path_str.to_string());
        }
    }

    if hidden_files.is_empty() {
        return None;
    }

    finding.details.push(format!(
        "Found {} interesting hidden files (showing top 30):",
        hidden_files.len()
    ));
    finding
        .details
        .extend(hidden_files.iter().take(30).cloned());

    if hidden_files.len() > 30 {
        finding
            .details
            .push(format!("... and {} more", hidden_files.len() - 30));
    }

    Some(finding)
}

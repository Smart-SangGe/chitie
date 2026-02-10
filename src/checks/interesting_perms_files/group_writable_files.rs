use crate::{Category, Finding, Severity};
use nix::unistd::{getgroups, getuid, Gid, Group};
use std::collections::{HashMap, HashSet};
use std::env;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use walkdir::WalkDir;

///  Interesting Permissions - Group Writable Files
///  Author: Sangge
///  Last Update: 2026-02-09
///  Description: Interesting GROUP writable files (not in Home)
///  Corresponds to LinPEAS: 15_Writable_files_group.sh
pub async fn check() -> Option<Finding> {
    let config = crate::config::config();

    // LinPEAS logic: if ! [ "$IAMROOT" ]; then
    if getuid().is_root() {
        return None;
    }

    let mut finding = Finding::new(
        Category::Permission,
        Severity::Medium,
        "Group Writable Files",
        "Interesting GROUP writable files (not in Home)",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files");

    // Get all groups the current user belongs to
    let gids: HashSet<Gid> = getgroups().unwrap_or_default().into_iter().collect();
    if gids.is_empty() {
        return None;
    }

    // Map GIDs to group names for display
    let mut gid_to_name = HashMap::new();
    for gid in &gids {
        if let Ok(Some(group)) = Group::from_gid(*gid) {
            gid_to_name.insert(*gid, group.name);
        } else {
            gid_to_name.insert(*gid, gid.to_string());
        }
    }

    let home_dir = env::var("HOME").unwrap_or_default();
    let exclude_dirs = vec!["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"];

    // Store results grouped by Group Name
    let mut group_results: HashMap<String, Vec<String>> = HashMap::new();
    // To implement the "max 5 per directory" logic
    let mut dir_counts: HashMap<String, usize> = HashMap::new();

    let search_paths = if config.stealth {
        vec!["/etc", "/usr", "/bin", "/sbin", "/opt", "/var"]
    } else {
        vec!["/"]
    };

    let max_depth = if config.stealth { 5 } else { 15 };

    for search_path in search_paths {
        for entry in WalkDir::new(search_path)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            let path_str = path.display().to_string();

            // Exclude common dirs and HOME
            if exclude_dirs.iter().any(|&d| path_str.starts_with(d)) {
                continue;
            }
            if !home_dir.is_empty() && path_str.starts_with(&home_dir) {
                continue;
            }

            if let Ok(metadata) = entry.metadata() {
                let gid = Gid::from_raw(metadata.gid());
                let mode = metadata.permissions().mode();

                // Logic: group is in user's groups AND group-writable bit is set
                if gids.contains(&gid) && (mode & 0o020 != 0) {
                    let parent = path.parent().unwrap_or_else(|| Path::new("/")).display().to_string();
                    let count = dir_counts.entry(parent.clone()).or_insert(0);
                    
                    let group_name = gid_to_name.get(&gid).cloned().unwrap_or_else(|| gid.to_string());
                    let results_list = group_results.entry(group_name).or_default();

                    if *count < 5 {
                        let type_str = if path.is_dir() { "DIR" } else { "FILE" };
                        results_list.push(format!("  {} {} (mode: {:o})", type_str, path_str, mode & 0o777));
                        *count += 1;
                    } else if *count == 5 {
                        results_list.push("  #) You can write even more files inside last directory".to_string());
                        *count += 1; // Ensure we only print the message once
                    }
                }
            }

            // Global limit to avoid extreme scenarios
            if group_results.values().map(|v| v.len()).sum::<usize>() >= 1000 {
                break;
            }
        }
    }

    if group_results.is_empty() {
        return None;
    }

    for (group_name, files) in group_results {
        finding.details.push(format!("Group {}:", group_name));
        finding.details.extend(files.into_iter().take(200)); // LinPEAS head -n 200
        finding.details.push("".to_string());
    }

    Some(finding)
}

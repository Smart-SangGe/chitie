use crate::{Category, Finding, Severity};
use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::fs::Metadata;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::SystemTime;
use walkdir::WalkDir;

///  Interesting Permissions - SUID Files
///  Author: Sangge
///  Last Update: 2025-10-25
///  Description: Find and analyze SUID binaries for privilege escalation
///
///  Checks for:
///  - SUID binaries on the system
///  - Owned/writable SUID files
///  - Known vulnerable SUID binaries
///  - Unknown SUID binaries
///
///  References:
///  - https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes (limit search)
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let config = crate::config::config();

    let mut finding = Finding::new(
        Category::Permission,
        Severity::Info,
        "SUID Files",
        "SUID binaries that could be exploited",
    )
    .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid");

    // LinPEAS sidB-style known SUID binaries with historical exploit notes.
    let known_suid_exploits = [
        (
            "apache2",
            "Read_root_passwd__apache2_-f_/etc/shadow(CVE-2019-0211)",
        ),
        ("at", "RTru64_UNIX_4.0g(CVE-2002-1614)"),
        ("chfn", "SuSE_9.3/10"),
        ("chkey", "Solaris_2.5.1"),
        ("chpass", "OpenBSD/FreeBSD historical vulnerabilities"),
        ("chpasswd", "SquirrelMail(2004-04)"),
        ("eject", "FreeBSD_mcweject_0.9/SGI_IRIX_6.2"),
        ("login", "IBM_AIX_3.2.5/SGI_IRIX_6.4"),
        ("lpc", "S.u.S.E_Linux_5.2"),
        (
            "lpr",
            "BSD/OS2.1/FreeBSD2.1.5/NeXTstep4.x/IRIX6.4/SunOS4.1.3/4.1.4(09-1996)",
        ),
        (
            "mount",
            "Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8",
        ),
        ("movemail", "Emacs(08-1986)"),
        ("newgrp", "HP-UX_10.20"),
        ("ntfs-3g", "Debian9/8/7/Ubuntu/Gentoo/others(02-2017)"),
        (
            "passwd",
            "Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)",
        ),
        (
            "pkexec",
            "Linux4.10_to_5.1.17(CVE-2019-13272)/Generic_CVE-2021-4034",
        ),
        ("pppd", "Apple_Mac_OSX_10.4.8(05-2007)"),
        ("screen", "GNU_Screen_4.5.0"),
        (
            "snap-confine",
            "Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)",
        ),
        ("sudo", "check_if_the_sudo_version_is_vulnerable"),
        ("sudoedit", "Sudo/SudoEdit_1.6.9p21/1.7.2p4/Sudo<=1.8.14"),
        ("tmux", "Tmux_1.3_1.4_privesc(CVE-2011-1496)"),
        ("traceroute", "LBL_Traceroute_[2000-11-15]"),
        ("ubuntu-core-launcher", "Before_1.0.27.1(CVE-2016-1580)"),
        ("umount", "BSD/Linux(08-1996)"),
        ("xorg", "Xorg_1.19_to_1.20.x(CVE_2018-14665)"),
        (
            "xterm",
            "Solaris_5.5.1_X11R6.3(05-1997)/Debian_xterm_version_222-1etch2(01-2009)",
        ),
    ];

    let path_privesc_suids = [
        "nmap", "vim", "vi", "nano", "find", "bash", "sh", "more", "less", "man", "awk", "gawk",
        "perl", "python", "ruby", "lua", "php", "tclsh", "wish", "rvim", "rview", "emacs", "git",
        "ftp", "socat", "taskset", "strace", "gdb", "docker", "kubectl",
    ];

    let mut suid_files = Vec::new();
    let mut dangerous_found = Vec::new();
    let mut writable_found = Vec::new();
    let users = load_name_map("/etc/passwd");
    let groups = load_name_map("/etc/group");

    // 限制搜索路径和深度
    let search_paths = if config.stealth {
        vec!["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    } else {
        vec!["/usr", "/bin", "/sbin", "/opt"]
    };

    let max_depth = if config.stealth { 3 } else { 10 };

    for search_path in search_paths {
        for entry in WalkDir::new(search_path)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if let Ok(metadata) = entry.metadata() {
                let mode = metadata.permissions().mode();

                // 检查 SUID 位 (mode & 0o4000)
                if mode & 0o4000 != 0 {
                    // 检查是否可写
                    if mode & 0o002 != 0 || mode & 0o020 != 0 {
                        writable_found.push(format!(
                            "You can write SUID file: {}",
                            format_ls_line(path, &metadata, &users, &groups)
                        ));
                        finding.severity = Severity::Critical;
                        continue;
                    }

                    // 检查是否是已知危险二进制
                    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                    if let Some((_, exploit)) = known_suid_exploits
                        .iter()
                        .find(|(name, _)| filename == *name || filename.contains(name))
                    {
                        dangerous_found.push(format!(
                            "{}  --->  {}",
                            format_ls_line(path, &metadata, &users, &groups),
                            exploit
                        ));
                        if finding.severity < Severity::High {
                            finding.severity = Severity::High;
                        }
                    } else if path_privesc_suids.iter().any(|&d| filename.contains(d)) {
                        dangerous_found.push(format!(
                            "{}  --->  GTFOBins/path hijack candidate",
                            format_ls_line(path, &metadata, &users, &groups)
                        ));
                        if finding.severity < Severity::High {
                            finding.severity = Severity::High;
                        }
                    } else {
                        suid_files.push(format_ls_line(path, &metadata, &users, &groups));
                    }
                }
            }
        }
    }

    if writable_found.is_empty() && dangerous_found.is_empty() && suid_files.is_empty() {
        finding.details.push("No SUID files found".to_string());
        return Some(finding);
    }

    if !writable_found.is_empty() {
        finding
            .details
            .push("=== WRITABLE SUID FILES ===".to_string());
        finding.details.extend(writable_found);
        finding.details.push("".to_string());
    }

    if !dangerous_found.is_empty() {
        finding
            .details
            .push("=== DANGEROUS SUID FILES ===".to_string());
        finding
            .details
            .extend(dangerous_found.iter().take(20).cloned());
        if dangerous_found.len() > 20 {
            finding
                .details
                .push(format!("... and {} more", dangerous_found.len() - 20));
        }
        finding.details.push("".to_string());
    }

    if !suid_files.is_empty() {
        finding.details.push("=== OTHER SUID FILES ===".to_string());
        finding.details.extend(suid_files.iter().take(30).cloned());
        if suid_files.len() > 30 {
            finding
                .details
                .push(format!("... and {} more", suid_files.len() - 30));
        }
    }

    Some(finding)
}

fn load_name_map(path: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let mut parts = line.split(':');
            if let (Some(name), Some(_), Some(id)) = (parts.next(), parts.next(), parts.next())
                && let Ok(id) = id.parse::<u32>()
            {
                map.insert(id, name.to_string());
            }
        }
    }
    map
}

fn format_ls_line(
    path: &Path,
    metadata: &Metadata,
    users: &HashMap<u32, String>,
    groups: &HashMap<u32, String>,
) -> String {
    let mode = metadata.permissions().mode();
    let perms = mode_to_string(mode);
    let owner = users
        .get(&metadata.uid())
        .cloned()
        .unwrap_or_else(|| metadata.uid().to_string());
    let group = groups
        .get(&metadata.gid())
        .cloned()
        .unwrap_or_else(|| metadata.gid().to_string());
    let size = human_size(metadata.len());
    let modified = metadata
        .modified()
        .map(format_mtime)
        .unwrap_or_else(|_| "??? ?? ????".to_string());

    format!(
        "{} 1 {} {} {} {} {}",
        perms,
        owner,
        group,
        size,
        modified,
        path.display()
    )
}

fn mode_to_string(mode: u32) -> String {
    let file_type = if mode & 0o040000 != 0 { 'd' } else { '-' };
    let mut chars = vec![file_type];
    let flags = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (bit, ch) in flags {
        chars.push(if mode & bit != 0 { ch } else { '-' });
    }
    if mode & 0o4000 != 0 {
        chars[3] = if mode & 0o100 != 0 { 's' } else { 'S' };
    }
    if mode & 0o2000 != 0 {
        chars[6] = if mode & 0o010 != 0 { 's' } else { 'S' };
    }
    if mode & 0o1000 != 0 {
        chars[9] = if mode & 0o001 != 0 { 't' } else { 'T' };
    }
    chars.into_iter().collect()
}

fn human_size(size: u64) -> String {
    if size >= 1024 * 1024 {
        format!("{}M", (size + 1024 * 1024 - 1) / (1024 * 1024))
    } else if size >= 1024 {
        format!("{}K", (size + 1023) / 1024)
    } else {
        size.to_string()
    }
}

fn format_mtime(time: SystemTime) -> String {
    let datetime: DateTime<Local> = time.into();
    datetime.format("%b %e %Y").to_string()
}

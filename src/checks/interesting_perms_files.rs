use crate::config::config;
use crate::{Category, Finding, Severity};
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

/// 运行权限检查
pub async fn run() -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let cfg = config();

    if cfg.stealth {
        // 隐蔽模式：跳过耗时的文件系统遍历
        return Ok(findings);
    }

    // 查找SUID文件
    let suid_files = find_suid_files(&cfg.root_folder)?;

    if !suid_files.is_empty() {
        findings.push(
            Finding::new(
                Category::Permission,
                Severity::Medium,
                "SUID Files Found",
                format!("Found {} SUID files", suid_files.len()),
            )
            .with_details(suid_files)
            .with_reference("https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid")
        );
    }

    Ok(findings)
}

/// 查找SUID文件
fn find_suid_files(root: &str) -> anyhow::Result<Vec<String>> {
    let mut suid_files = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .max_depth(if root == "/" { 10 } else { 20 })
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if let Ok(metadata) = entry.metadata() {
            if metadata.is_file() {
                let mode = metadata.permissions().mode();
                // 检查SUID位 (04000)
                if mode & 0o4000 != 0 {
                    suid_files.push(format!(
                        "{} ({})",
                        entry.path().display(),
                        format_mode(mode)
                    ));
                }
            }
        }
    }

    Ok(suid_files)
}

/// 格式化文件权限
fn format_mode(mode: u32) -> String {
    format!("{:o}", mode & 0o7777)
}

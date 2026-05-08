use crate::Finding;
use colored::Colorize;

/// 输出到终端（彩色）
pub fn output(findings: &[Finding]) -> anyhow::Result<()> {
    println!("{}", "=".repeat(80).bright_blue());
    println!(
        "{}",
        "chitie - Linux Privilege Escalation Enumeration"
            .bright_green()
            .bold()
    );
    println!("{}", "=".repeat(80).bright_blue());
    println!();

    if findings.is_empty() {
        println!("{}", "No findings to report.".yellow());
        return Ok(());
    }

    let mut current_category = None;

    for finding in findings {
        // 打印类别标题
        if current_category != Some(finding.category) {
            println!();
            println!(
                "{}",
                format!("[ {} ]", finding.category.as_str())
                    .bright_cyan()
                    .bold()
            );
            println!("{}", "-".repeat(80).bright_black());
            current_category = Some(finding.category);
        }

        // 打印严重程度和标题
        let severity_str = format!("[{}]", finding.severity.as_str());
        let colored_severity = severity_str.color(finding.severity.color()).bold();

        println!();
        println!("{} {}", colored_severity, finding.title.bold());
        println!("  {}", finding.description.italic());

        // 打印详细信息
        if !finding.details.is_empty() {
            println!();
            for detail in &finding.details {
                println!("    {}", detail);
            }
        }

        // 打印修复建议
        if let Some(remediation) = &finding.remediation {
            println!();
            println!("  {} {}", "Fix:".green().bold(), remediation);
        }

        // 打印参考链接
        if !finding.references.is_empty() {
            println!();
            for reference in &finding.references {
                println!("  {} {}", "Ref:".blue(), reference.bright_black());
            }
        }
    }

    println!();
    println!("{}", "=".repeat(80).bright_blue());
    println!("Total findings: {}", findings.len());
    println!("{}", "=".repeat(80).bright_blue());

    Ok(())
}

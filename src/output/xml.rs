use crate::Finding;
use crate::config::config;
use chrono::Utc;
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
#[serde(rename = "chitie_report")]
struct XmlReport<'a> {
    generated_at: String,
    total_findings: usize,
    findings: XmlFindings<'a>,
}

#[derive(Serialize)]
struct XmlFindings<'a> {
    #[serde(rename = "finding")]
    items: &'a [Finding],
}

/// 输出为XML格式
pub fn output(findings: &[Finding]) -> anyhow::Result<()> {
    let report = XmlReport {
        generated_at: Utc::now().to_rfc3339(),
        total_findings: findings.len(),
        findings: XmlFindings { items: findings },
    };

    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        quick_xml::se::to_string(&report)?
    );
    let cfg = config();

    if let Some(output_file) = &cfg.output_file {
        fs::write(output_file, xml)?;
        eprintln!("XML output written to: {}", output_file);
    } else {
        println!("{}", xml);
    }

    Ok(())
}

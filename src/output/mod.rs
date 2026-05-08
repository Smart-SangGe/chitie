pub mod html;
pub mod json;
pub mod terminal;
pub mod xml;

use crate::Finding;
use crate::config::{OutputFormat, config};

/// 输出结果
pub fn output_findings(findings: &[Finding]) -> anyhow::Result<()> {
    let cfg = config();
    match cfg.output_format {
        OutputFormat::Terminal => terminal::output(findings),
        OutputFormat::Json => json::output(findings),
        OutputFormat::Xml => xml::output(findings),
        OutputFormat::Html => html::output(findings),
    }
}

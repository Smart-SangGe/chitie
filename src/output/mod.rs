pub mod terminal;
pub mod json;

use crate::Finding;
use crate::config::{config, OutputFormat};

/// 输出结果
pub fn output_findings(findings: &[Finding]) -> anyhow::Result<()> {
    let cfg = config();
    match cfg.output_format {
        OutputFormat::Terminal => terminal::output(findings),
        OutputFormat::Json => json::output(findings),
        OutputFormat::Xml => todo!("XML output not yet implemented"),
        OutputFormat::Html => todo!("HTML output not yet implemented"),
    }
}

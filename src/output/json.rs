use crate::Finding;
use crate::config::config;
use std::fs;

/// 输出为JSON格式
pub fn output(findings: &[Finding]) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(findings)?;
    let cfg = config();

    if let Some(output_file) = &cfg.output_file {
        fs::write(output_file, json)?;
        eprintln!("JSON output written to: {}", output_file);
    } else {
        println!("{}", json);
    }

    Ok(())
}

use chitie::cli::Cli;
use chitie::config::CONFIG;
use chitie::output;
use chitie::runner;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 解析命令行参数并初始化全局配置
    let cli = Cli::parse();
    let config = cli.into_config()?;
    CONFIG.set(config).expect("Config already initialized");

    let config = chitie::config::config();

    if config.debug {
        eprintln!("[DEBUG] Running with config: {:?}", config);
    }

    // 运行所有检查
    let start = std::time::Instant::now();
    let findings = runner::run_all_checks().await?;
    let duration = start.elapsed();

    if config.debug {
        eprintln!("[DEBUG] Scan completed in {:?}", duration);
        eprintln!("[DEBUG] Found {} findings", findings.len());
    }

    // 输出结果
    output::output_findings(&findings)?;

    if config.debug {
        eprintln!("[DEBUG] Total execution time: {:?}", duration);
    }

    Ok(())
}

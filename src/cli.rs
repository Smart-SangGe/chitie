use clap::Parser;

use crate::config::{Config, OutputFormat};

/// chitie - 更快的LinPEAS Rust实现
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// 执行所有检查（包括进程监控和用户暴力破解）
    #[arg(short = 'a', long)]
    pub all: bool,

    /// 额外的详细枚举
    #[arg(short = 'e', long)]
    pub extra: bool,

    /// 正则搜索API密钥/密码
    #[arg(short = 'r', long)]
    pub regex: bool,

    /// 隐蔽/快速模式（跳过耗时检查）
    #[arg(short = 's', long)]
    pub stealth: bool,

    /// 用于sudo/用户暴力破解的密码
    #[arg(short = 'P', long)]
    pub password: Option<String>,

    /// 调试模式（显示时间信息）
    #[arg(short = 'D', long)]
    pub debug: bool,

    /// 分析固件/文件夹
    #[arg(short = 'f', long)]
    pub firmware: Option<String>,

    /// 只执行选定的检查模块（逗号分隔）
    /// 可选: system_information,container,cloud,procs_crons_timers_srvcs_sockets,
    ///      network_information,users_information,software_information,
    ///      interesting_perms_files,interesting_files,api_keys_regex
    #[arg(short = 'o', long)]
    pub only_modules: Option<String>,

    /// 输出格式 (terminal, json, xml, html)
    #[arg(long, default_value = "terminal")]
    pub output_format: String,

    /// 输出文件路径
    #[arg(long)]
    pub output_file: Option<String>,

    /// 根目录（用于容器/chroot环境）
    #[arg(long, default_value = "/")]
    pub root_folder: String,
}

impl Cli {
    /// 转换为Config
    pub fn into_config(self) -> anyhow::Result<Config> {
        let output_format: OutputFormat = self.output_format.parse()
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        Ok(Config {
            all_checks: self.all,
            extra: self.extra,
            regex_secrets: self.regex,
            stealth: self.stealth,
            password: self.password,
            debug: self.debug,
            firmware: self.firmware,
            only_modules: self.only_modules,
            output_format,
            output_file: self.output_file,
            root_folder: self.root_folder,
        })
    }
}

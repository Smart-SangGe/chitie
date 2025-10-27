use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// 全局配置实例
pub static CONFIG: OnceLock<Config> = OnceLock::new();

/// 运行配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// -a: 执行所有检查（包括进程监控和用户暴力破解）
    pub all_checks: bool,

    /// -e: 额外的详细枚举
    pub extra: bool,

    /// -r: 正则搜索API密钥/密码
    pub regex_secrets: bool,

    /// -s: 隐蔽/快速模式（跳过耗时检查）
    pub stealth: bool,

    /// -P: 用于sudo/用户暴力破解的密码
    pub password: Option<String>,

    /// -D: 调试模式（显示时间信息）
    pub debug: bool,

    /// -f: 分析固件/文件夹
    pub firmware: Option<String>,

    /// -o: 只执行选定的模块（逗号分隔）
    pub only_modules: Option<String>,

    /// 输出格式
    pub output_format: OutputFormat,

    /// 输出文件路径（可选）
    pub output_file: Option<String>,

    /// 根目录（用于容器/chroot环境）
    pub root_folder: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            all_checks: false,
            extra: false,
            regex_secrets: false,
            stealth: false,
            password: None,
            debug: false,
            firmware: None,
            only_modules: None,
            output_format: OutputFormat::Terminal,
            output_file: None,
            root_folder: "/".to_string(),
        }
    }
}

/// 输出格式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    /// 终端彩色输出
    Terminal,
    /// JSON格式
    Json,
    /// XML格式
    Xml,
    /// HTML报告
    Html,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" | "term" => Ok(OutputFormat::Terminal),
            "json" => Ok(OutputFormat::Json),
            "xml" => Ok(OutputFormat::Xml),
            "html" => Ok(OutputFormat::Html),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

/// 获取全局配置
pub fn config() -> &'static Config {
    CONFIG.get().expect("Config not initialized")
}

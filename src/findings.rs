use serde::{Deserialize, Serialize};

/// 发现的安全问题
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// 类别
    pub category: Category,
    /// 严重程度
    pub severity: Severity,
    /// 标题
    pub title: String,
    /// 描述
    pub description: String,
    /// 详细信息
    pub details: Vec<String>,
    /// 修复建议（可选）
    pub remediation: Option<String>,
    /// 参考链接
    pub references: Vec<String>,
}

impl Finding {
    pub fn new(
        category: Category,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            category,
            severity,
            title: title.into(),
            description: description.into(),
            details: Vec::new(),
            remediation: None,
            references: Vec::new(),
        }
    }

    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.details.push(detail.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }
}

/// 严重程度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// 关键 - 红色 - 直接提权
    Critical,
    /// 高危 - 黄红 - 可能提权
    High,
    /// 中危 - 黄色 - 值得关注
    Medium,
    /// 低危 - 蓝色 - 信息收集
    Low,
    /// 信息 - 无色 - 常规信息
    Info,
}

impl Severity {
    /// 获取终端颜色代码
    pub fn color(&self) -> colored::Color {
        use colored::Color;
        match self {
            Severity::Critical => Color::Red,
            Severity::High => Color::Yellow,
            Severity::Medium => Color::BrightYellow,
            Severity::Low => Color::Blue,
            Severity::Info => Color::White,
        }
    }

    /// 获取字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

/// 检查类别
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    /// 系统信息
    System,
    /// 容器
    Container,
    /// 云环境
    Cloud,
    /// 进程
    Process,
    /// 网络
    Network,
    /// 用户
    User,
    /// 软件
    Software,
    /// 权限
    Permission,
    /// 文件
    File,
    /// 密钥/密码
    Secret,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::System => "System Information",
            Category::Container => "Container",
            Category::Cloud => "Cloud",
            Category::Process => "Processes & Services",
            Category::Network => "Network",
            Category::User => "Users & Groups",
            Category::Software => "Software",
            Category::Permission => "Permissions",
            Category::File => "Files",
            Category::Secret => "Secrets",
        }
    }
}

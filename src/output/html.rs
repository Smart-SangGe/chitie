use crate::config::config;
use crate::{Category, Finding, Severity};
use chrono::Utc;
use std::fs;

const SEVERITIES: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

const CATEGORIES: [Category; 10] = [
    Category::System,
    Category::Container,
    Category::Cloud,
    Category::Process,
    Category::Network,
    Category::User,
    Category::Software,
    Category::Permission,
    Category::File,
    Category::Secret,
];

/// 输出为HTML格式
pub fn output(findings: &[Finding]) -> anyhow::Result<()> {
    let html = render_report(findings);
    let cfg = config();

    if let Some(output_file) = &cfg.output_file {
        fs::write(output_file, html)?;
        eprintln!("HTML output written to: {}", output_file);
    } else {
        println!("{}", html);
    }

    Ok(())
}

fn render_report(findings: &[Finding]) -> String {
    let generated_at = Utc::now().to_rfc3339();
    let mut html = String::new();

    html.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    html.push_str("<title>chitie report</title>\n");
    html.push_str("<style>\n");
    html.push_str(CSS);
    html.push_str("</style>\n</head>\n<body>\n");
    html.push_str("<main class=\"page\">\n");
    html.push_str("<header class=\"header\">\n");
    html.push_str(
        "<div><h1>chitie report</h1><p>Linux privilege escalation enumeration results</p></div>\n",
    );
    html.push_str(&format!(
        "<div class=\"meta\"><span>Generated</span><strong>{}</strong><span>Total findings</span><strong>{}</strong></div>\n",
        escape_html(&generated_at),
        findings.len()
    ));
    html.push_str("</header>\n");

    html.push_str("<section class=\"summary\" aria-label=\"Severity summary\">\n");
    for severity in SEVERITIES {
        let count = findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count();
        html.push_str(&format!(
            "<div class=\"summary-item\"><span class=\"dot {}\"></span><span>{}</span><strong>{}</strong></div>\n",
            severity_class(severity),
            severity.as_str(),
            count
        ));
    }
    html.push_str("</section>\n");

    html.push_str("<section class=\"categories\" aria-label=\"Category summary\">\n");
    for category in CATEGORIES {
        let count = findings
            .iter()
            .filter(|finding| finding.category == category)
            .count();
        if count > 0 {
            html.push_str(&format!(
                "<div><span>{}</span><strong>{}</strong></div>\n",
                escape_html(category.as_str()),
                count
            ));
        }
    }
    html.push_str("</section>\n");

    html.push_str("<section class=\"findings\" aria-label=\"Findings\">\n");
    if findings.is_empty() {
        html.push_str("<p class=\"empty\">No findings to report.</p>\n");
    } else {
        for finding in findings {
            render_finding(&mut html, finding);
        }
    }
    html.push_str("</section>\n");
    html.push_str("</main>\n</body>\n</html>\n");

    html
}

fn render_finding(html: &mut String, finding: &Finding) {
    html.push_str("<article class=\"finding\">\n");
    html.push_str("<div class=\"finding-head\">\n");
    html.push_str(&format!(
        "<span class=\"severity {}\">{}</span><span class=\"category\">{}</span>\n",
        severity_class(finding.severity),
        finding.severity.as_str(),
        escape_html(finding.category.as_str())
    ));
    html.push_str("</div>\n");
    html.push_str(&format!("<h2>{}</h2>\n", escape_html(&finding.title)));
    html.push_str(&format!(
        "<p class=\"description\">{}</p>\n",
        escape_html(&finding.description)
    ));

    if !finding.details.is_empty() {
        html.push_str("<ul class=\"details\">\n");
        for detail in &finding.details {
            html.push_str(&format!("<li>{}</li>\n", escape_html(detail)));
        }
        html.push_str("</ul>\n");
    }

    if let Some(remediation) = &finding.remediation {
        html.push_str("<div class=\"remediation\"><strong>Fix</strong>");
        html.push_str(&format!("<p>{}</p></div>\n", escape_html(remediation)));
    }

    if !finding.references.is_empty() {
        html.push_str("<div class=\"references\"><strong>References</strong><ul>\n");
        for reference in &finding.references {
            let escaped = escape_html(reference);
            html.push_str(&format!(
                "<li><a href=\"{}\" rel=\"noreferrer\">{}</a></li>\n",
                escaped, escaped
            ));
        }
        html.push_str("</ul></div>\n");
    }

    html.push_str("</article>\n");
}

fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

const CSS: &str = r#"
:root {
  color-scheme: light;
  --bg: #f6f7f9;
  --panel: #ffffff;
  --text: #1f2933;
  --muted: #657080;
  --line: #d8dee7;
  --critical: #b42318;
  --high: #b54708;
  --medium: #946200;
  --low: #175cd3;
  --info: #4b5563;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.5;
}
.page {
  width: min(1180px, calc(100% - 32px));
  margin: 0 auto;
  padding: 28px 0 48px;
}
.header {
  display: flex;
  justify-content: space-between;
  gap: 24px;
  align-items: flex-start;
  margin-bottom: 20px;
}
h1 {
  margin: 0;
  font-size: 30px;
  font-weight: 750;
}
.header p {
  margin: 6px 0 0;
  color: var(--muted);
}
.meta {
  display: grid;
  grid-template-columns: auto auto;
  gap: 4px 14px;
  min-width: 280px;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
}
.meta span { color: var(--muted); }
.summary, .categories {
  display: grid;
  gap: 10px;
  margin-bottom: 14px;
}
.summary {
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
}
.categories {
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
}
.summary-item, .categories div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
}
.summary-item {
  justify-content: flex-start;
}
.summary-item strong {
  margin-left: auto;
}
.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--info);
}
.dot.critical, .severity.critical { background: var(--critical); }
.dot.high, .severity.high { background: var(--high); }
.dot.medium, .severity.medium { background: var(--medium); }
.dot.low, .severity.low { background: var(--low); }
.dot.info, .severity.info { background: var(--info); }
.findings {
  display: grid;
  gap: 14px;
  margin-top: 20px;
}
.finding {
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  padding: 16px;
}
.finding-head {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 10px;
}
.severity, .category {
  display: inline-flex;
  align-items: center;
  min-height: 24px;
  padding: 3px 8px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
}
.severity {
  color: #ffffff;
}
.category {
  color: var(--muted);
  background: #eef2f6;
}
h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 720;
}
.description {
  margin: 6px 0 0;
  color: var(--muted);
}
.details {
  margin: 14px 0 0;
  padding: 0;
  list-style: none;
}
.details li {
  margin-top: 6px;
  padding: 7px 9px;
  border-radius: 6px;
  background: #f4f6f8;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}
.remediation, .references {
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid var(--line);
}
.remediation p {
  margin: 5px 0 0;
}
.references ul {
  margin: 6px 0 0;
  padding-left: 18px;
}
a {
  color: var(--low);
}
.empty {
  color: var(--muted);
}
@media (max-width: 720px) {
  .header {
    display: block;
  }
  .meta {
    margin-top: 14px;
    min-width: 0;
  }
}
"#;

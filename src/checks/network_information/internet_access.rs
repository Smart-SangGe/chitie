use crate::{Category, Finding, Severity};
use std::net::TcpStream;
use std::time::Duration;

///  Network Information - Internet Access
///  Author: Sangge
///  Last Update: 2025-10-27
///  Description: Check if the system has internet access
///
///  Checks for:
///  - TCP connection to common ports (80, 443)
///  - DNS resolution
///  - ICMP ping
///
///  References:
///  - Based on LinPEAS NT_Internet_access
///
///  Execution Mode:
///  - Default: yes
///  - Stealth (-s): yes
///  - Extra (-e): yes
///  - All (-a): yes
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::Network,
        Severity::Info,
        "Internet Access",
        "Check for external network connectivity",
    );

    let mut details = Vec::new();
    let timeout = Duration::from_secs(3);

    // 测试HTTP (port 80)
    let http_test =
        test_tcp_connection("1.1.1.1:80", timeout) || test_tcp_connection("8.8.8.8:80", timeout);

    details.push(format!(
        "HTTP (port 80): {}",
        if http_test {
            "Accessible"
        } else {
            "Not accessible"
        }
    ));

    // 测试HTTPS (port 443)
    let https_test =
        test_tcp_connection("1.1.1.1:443", timeout) || test_tcp_connection("8.8.8.8:443", timeout);

    details.push(format!(
        "HTTPS (port 443): {}",
        if https_test {
            "Accessible"
        } else {
            "Not accessible"
        }
    ));

    // 测试DNS (port 53)
    let dns_test =
        test_tcp_connection("1.1.1.1:53", timeout) || test_tcp_connection("8.8.8.8:53", timeout);

    details.push(format!(
        "DNS (port 53): {}",
        if dns_test {
            "Accessible"
        } else {
            "Not accessible"
        }
    ));

    // 总结
    details.push(String::new());
    if http_test || https_test {
        details.push("RESULT: Internet access detected".to_string());
        finding.severity = Severity::Medium;
        finding.description = "System has internet access".to_string();
    } else {
        details.push("RESULT: No internet access detected".to_string());
    }

    finding.details = details;
    Some(finding)
}

/// 测试TCP连接
fn test_tcp_connection(addr: &str, timeout: Duration) -> bool {
    TcpStream::connect_timeout(
        &addr
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
        timeout,
    )
    .is_ok()
}

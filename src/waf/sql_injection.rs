use pingora::prelude::*;
use regex::Regex;
use std::sync::LazyLock;

use super::rule::*;

/// Raw patterns loaded from file at compile time.
const SQL_INJECTION_PATTERNS: &str = include_str!("../regex_patterns/sql_injection_regex.txt");

/// Compiled master regex (case-insensitive, all patterns OR'd).
static SQL_INJECTION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    let pattern = SQL_INJECTION_PATTERNS
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("|");
    let full = format!("(?i)(?:{})", pattern);
    Regex::new(&full).expect("Failed to compile SQL injection regex")
});

pub struct SqlInjectionRule {
    pub enabled: bool,
    pub block_mode: bool,
}

impl SqlInjectionRule {
    /// URL-decode the input, then check against the SQL injection regex.
    fn is_malicious(input: &str) -> bool {
        let decoded = urlencoding::decode(input).unwrap_or(std::borrow::Cow::Borrowed(input));
        SQL_INJECTION_REGEX.is_match(&decoded)
    }

    fn make_violation(&self, description: String) -> SecurityViolation {
        SecurityViolation {
            threat_type: ThreatType::SqlInjection,
            threat_level: ThreatLevel::Critical,
            description,
            blocked: self.block_mode,
        }
    }
}

impl SecurityRule for SqlInjectionRule {
    fn name(&self) -> &str {
        "SQL Injection"
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn block_mode(&self) -> bool {
        self.block_mode
    }

    fn check_headers(&self, req: &RequestHeader) -> Vec<SecurityViolation> {
        let mut violations = Vec::new();

        // 1. Check URI (path + query string)
        let uri = req.uri.to_string();
        if Self::is_malicious(&uri) {
            violations.push(
                self.make_violation(format!("SQL injection detected in URI: {}", truncate(&uri, 200))),
            );
        }

        // 2. Check custom (non-safe) headers
        for (name, value) in req.headers.iter() {
            let name_lower = name.as_str().to_lowercase();
            if SAFE_HEADER_SET.contains(name_lower.as_str()) {
                continue;
            }
            if let Ok(val_str) = value.to_str() {
                if Self::is_malicious(val_str) {
                    violations.push(self.make_violation(format!(
                        "SQL injection detected in header '{}': {}",
                        name,
                        truncate(val_str, 200)
                    )));
                }
            }
        }

        violations
    }

    fn check_body(&self, body: &[u8]) -> Vec<SecurityViolation> {
        let mut violations = Vec::new();
        let body_str = String::from_utf8_lossy(body);
        if Self::is_malicious(&body_str) {
            violations.push(
                self.make_violation("SQL injection detected in request body".to_string()),
            );
        }
        violations
    }
}

/// Truncate a string for log output.
fn truncate(s: &str, max_len: usize) -> &str {
    match s.char_indices().nth(max_len) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

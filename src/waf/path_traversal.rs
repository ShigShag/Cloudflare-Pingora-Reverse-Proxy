use pingora::prelude::*;
use regex::Regex;
use std::sync::LazyLock;

use super::rule::{truncate, SecurityRule, SecurityViolation, ThreatLevel, ThreatType, SAFE_HEADER_SET};

/// Raw patterns loaded from file at compile time.
const PATH_TRAVERSAL_PATTERNS: &str = include_str!("../regex_patterns/path_traversal_regex.txt");

/// Compiled master regex (case-insensitive, all patterns OR'd).
static PATH_TRAVERSAL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    let pattern = PATH_TRAVERSAL_PATTERNS
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("|");
    let full = format!("(?i)(?:{})", pattern);
    Regex::new(&full).expect("Failed to compile path traversal regex")
});

pub struct PathTraversalRule {
    pub enabled: bool,
    pub block_mode: bool,
}

impl PathTraversalRule {
    /// URL-decode the input, then check against the path traversal regex.
    fn is_malicious(input: &str) -> bool {
        let decoded = urlencoding::decode(input).unwrap_or(std::borrow::Cow::Borrowed(input));
        PATH_TRAVERSAL_REGEX.is_match(&decoded)
    }

    fn make_violation(&self, description: String) -> SecurityViolation {
        SecurityViolation {
            threat_type: ThreatType::PathTraversal,
            threat_level: ThreatLevel::High,
            description,
            blocked: self.block_mode,
        }
    }
}

impl SecurityRule for PathTraversalRule {
    fn name(&self) -> &str {
        "Path Traversal"
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
                self.make_violation(format!("Path traversal detected in URI: {}", truncate(&uri, 200))),
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
                        "Path traversal detected in header '{}': {}",
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
                self.make_violation("Path traversal detected in request body".to_string()),
            );
        }
        violations
    }
}

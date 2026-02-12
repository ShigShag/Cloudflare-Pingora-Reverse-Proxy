use pingora::prelude::*;
use std::collections::HashSet;
use std::fmt;
use std::sync::LazyLock;

/// Threat severity levels, ordered from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatLevel::Low => write!(f, "Low"),
            ThreatLevel::Medium => write!(f, "Medium"),
            ThreatLevel::High => write!(f, "High"),
            ThreatLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Categorization of detected threats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ThreatType {
    SqlInjection,
    Xss,
    CommandInjection,
    PathTraversal,
}

impl fmt::Display for ThreatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatType::SqlInjection => write!(f, "SQL Injection"),
            ThreatType::Xss => write!(f, "XSS"),
            ThreatType::CommandInjection => write!(f, "Command Injection"),
            ThreatType::PathTraversal => write!(f, "Path Traversal"),
        }
    }
}

/// A single security violation detected by a rule.
#[derive(Debug, Clone)]
pub struct SecurityViolation {
    pub threat_type: ThreatType,
    pub threat_level: ThreatLevel,
    pub description: String,
    pub blocked: bool,
}

/// The trait that all WAF detectors implement.
#[allow(dead_code)]
pub trait SecurityRule: Send + Sync {
    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// Whether this rule is currently enabled.
    fn enabled(&self) -> bool;

    /// Whether this rule is in block mode (true) or log-only mode (false).
    fn block_mode(&self) -> bool;

    /// Inspect request headers (URI path+query, custom headers).
    /// Called during `request_filter()`.
    fn check_headers(&self, req: &RequestHeader) -> Vec<SecurityViolation>;

    /// Inspect the complete request body.
    /// Called during `request_body_filter()` when `end_of_stream` is true.
    fn check_body(&self, body: &[u8]) -> Vec<SecurityViolation>;
}

/// Headers that should NOT be inspected by WAF rules.
/// These are standard browser-set headers unlikely to contain attacks.
static SAFE_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "host",
    "if-modified-since",
    "if-none-match",
    "origin",
    "pragma",
    "referer",
    "user-agent",
    // Sec-* headers (Fetch metadata)
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    // Other standard headers
    "upgrade-insecure-requests",
    "x-requested-with",
];

/// O(1) lookup set for safe headers.
pub static SAFE_HEADER_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| SAFE_HEADERS.iter().copied().collect());

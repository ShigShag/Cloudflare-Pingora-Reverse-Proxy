use regex::Regex;
use std::sync::LazyLock;

const CRAWLER_PATTERN: &str = include_str!("regex_patterns/user_agent_regex.txt");

static BAD_UA_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    let pattern = format!("(?i)(?:{})", CRAWLER_PATTERN.trim());
    Regex::new(&pattern).expect("Failed to compile user-agent regex")
});

pub fn is_bad_user_agent(ua: &str) -> bool {
    BAD_UA_REGEX.is_match(ua)
}

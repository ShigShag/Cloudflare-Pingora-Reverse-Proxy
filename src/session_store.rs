use log::debug;
use moka::policy::Expiry;
use moka::sync::Cache;
use pingora::prelude::Session;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

use crate::config::{BindAttribute, SessionBindingConfig};

pub static SESSION_STORE: LazyLock<SessionStore> = LazyLock::new(SessionStore::new);

#[derive(Clone, Debug)]
struct SessionEntry {
    fingerprint: u64,
    ttl: Duration,
}

/// Per-entry expiration: each entry expires after its own TTL.
struct SessionExpiry;

impl Expiry<(String, String), SessionEntry> for SessionExpiry {
    fn expire_after_create(
        &self,
        _key: &(String, String),
        value: &SessionEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

#[derive(Debug)]
pub struct SessionStore {
    cache: Cache<(String, String), SessionEntry>,
}

impl SessionStore {
    fn new() -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(100_000)
                .expire_after(SessionExpiry)
                .build(),
        }
    }

    pub fn insert(&self, host: String, cookie_value: String, fingerprint: u64, ttl: Duration) {
        self.cache.insert(
            (host, cookie_value),
            SessionEntry { fingerprint, ttl },
        );
    }

    /// Returns the stored fingerprint if it exists and hasn't expired.
    pub fn get_fingerprint(&self, host: &str, cookie_value: &str) -> Option<u64> {
        let key = (host.to_string(), cookie_value.to_string());
        self.cache.get(&key).map(|entry| entry.fingerprint)
    }

    pub fn remove(&self, host: &str, cookie_value: &str) {
        self.cache
            .invalidate(&(host.to_string(), cookie_value.to_string()));
    }

    /// Remove all entries for a given hostname (used on config reload).
    pub fn clear_host(&self, host: &str) {
        let host = host.to_string();
        self.cache
            .invalidate_entries_if(move |k, _| k.0 == host)
            .ok();
        self.cache.run_pending_tasks();
    }
}

/// Extract a named cookie's value from a `Cookie` request header.
/// Format: `name1=value1; name2=value2`
pub fn extract_cookie_value(cookie_header: &str, cookie_name: &str) -> Option<String> {
    cookie_header
        .split(';')
        .map(|pair| pair.trim())
        .find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let name = parts.next()?.trim();
            let value = parts.next()?.trim();
            if name == cookie_name {
                Some(value.to_string())
            } else {
                None
            }
        })
}

/// Extract a named cookie's value from a `Set-Cookie` response header.
/// Format: `name=value; Path=/; HttpOnly; Expires=...; Max-Age=...; ...`
/// Returns None if the cookie name doesn't match.
/// Parses `Max-Age` and `Expires` to determine TTL (Max-Age takes precedence per RFC 6265).
pub fn extract_set_cookie_value(set_cookie_header: &str, cookie_name: &str) -> Option<SetCookieResult> {
    let name_value = set_cookie_header.split(';').next()?;
    let mut parts = name_value.splitn(2, '=');
    let name = parts.next()?.trim();
    let value = parts.next()?.trim();
    if name != cookie_name {
        return None;
    }

    // Parse attributes for Max-Age and Expires
    let mut max_age: Option<u64> = None;
    let mut expires_ttl: Option<u64> = None;
    let mut is_cleared = value.is_empty();

    for attr in set_cookie_header.split(';').skip(1) {
        let attr = attr.trim();
        let attr_lower = attr.to_lowercase();

        if let Some(val) = attr_lower.strip_prefix("max-age=") {
            match val.trim().parse::<i64>() {
                Ok(v) if v <= 0 => {
                    is_cleared = true;
                }
                Ok(v) => {
                    max_age = Some(v as u64);
                }
                Err(_) => {}
            }
        } else if let Some(val) = attr_lower.strip_prefix("expires=") {
            // The actual value (preserving original case) for date parsing
            let date_str = attr.trim_start_matches(|c: char| c != '=').trim_start_matches('=').trim();
            if let Some(ttl) = parse_http_date_to_ttl(date_str) {
                expires_ttl = Some(ttl);
            } else if val.contains("thu, 01 jan 1970") || val.contains("thu, 01-jan-1970") {
                is_cleared = true;
            }
        }
    }

    if is_cleared {
        return Some(SetCookieResult::Cleared);
    }

    // Max-Age takes precedence over Expires (RFC 6265 Section 5.3)
    let ttl = max_age.or(expires_ttl);

    Some(SetCookieResult::Value {
        cookie_value: value.to_string(),
        ttl: ttl.map(Duration::from_secs),
    })
}

/// Parse an HTTP date string (e.g. "Tue, 10 Feb 2026 22:35:34 GMT") into
/// a TTL (seconds from now). Returns None if the date can't be parsed or is in the past.
fn parse_http_date_to_ttl(date_str: &str) -> Option<u64> {
    // Try RFC 2822 / HTTP date formats
    // Common format: "Tue, 10 Feb 2026 22:35:34 GMT"
    let months = [
        ("Jan", 1), ("Feb", 2), ("Mar", 3), ("Apr", 4),
        ("May", 5), ("Jun", 6), ("Jul", 7), ("Aug", 8),
        ("Sep", 9), ("Oct", 10), ("Nov", 11), ("Dec", 12),
    ];

    // Strip leading day-of-week if present (e.g. "Tue, ")
    let rest = if let Some(pos) = date_str.find(',') {
        date_str[pos + 1..].trim()
    } else {
        date_str.trim()
    };

    // Parse "10 Feb 2026 22:35:34 GMT" or "10-Feb-2026 22:35:34 GMT"
    let rest = rest.replace('-', " ");
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let day: u32 = parts[0].parse().ok()?;
    let month: u32 = months.iter().find(|(m, _)| m.eq_ignore_ascii_case(parts[1]))?.1;
    let year: i64 = parts[2].parse().ok()?;

    let time_parts: Vec<&str> = parts[3].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u64 = time_parts[0].parse().ok()?;
    let min: u64 = time_parts[1].parse().ok()?;
    let sec: u64 = time_parts[2].parse().ok()?;

    // Convert to seconds since Unix epoch
    // Simple calculation — good enough for cookie expiry
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[m as usize] as i64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    days += (day as i64) - 1;

    let target_epoch = (days as u64) * 86400 + hour * 3600 + min * 60 + sec;

    // Get current epoch
    let now_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();

    if target_epoch > now_epoch {
        Some(target_epoch - now_epoch)
    } else {
        None // Already expired
    }
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub enum SetCookieResult {
    Value {
        cookie_value: String,
        /// TTL derived from Max-Age or Expires. None means use config default.
        ttl: Option<Duration>,
    },
    Cleared,
}

/// Compute a fingerprint hash from the configured bind attributes.
pub fn compute_fingerprint(session: &Session, config: &SessionBindingConfig) -> u64 {
    let mut hasher = DefaultHasher::new();

    for attr in &config.bind_attributes {
        match attr {
            BindAttribute::Ip => {
                if let Some(ip) = session
                    .client_addr()
                    .and_then(|a| a.as_inet().map(|inet| inet.ip()))
                {
                    ip.to_string().hash(&mut hasher);
                    debug!("Fingerprint component: IP={}", ip);
                }
            }
            BindAttribute::Tls => {
                if let Some(digest) = session.digest() {
                    if let Some(ssl) = &digest.ssl_digest {
                        ssl.version.hash(&mut hasher);
                        ssl.cipher.hash(&mut hasher);
                        debug!(
                            "Fingerprint component: TLS version={:?}, cipher={:?}",
                            ssl.version, ssl.cipher
                        );
                    }
                }
            }
            BindAttribute::UserAgent => {
                if let Some(ua) = session.req_header().headers.get("User-Agent") {
                    ua.as_bytes().hash(&mut hasher);
                    debug!("Fingerprint component: User-Agent={:?}", ua);
                }
            }
        }
    }

    hasher.finish()
}

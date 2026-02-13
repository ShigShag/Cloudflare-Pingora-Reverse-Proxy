use log::error;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use url::Url;

fn default_true() -> bool {
    true
}

fn default_max_inspection_size_mb() -> usize {
    1
}

#[derive(Debug, Deserialize, Clone)]
pub struct SqlInjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub block_mode: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CommandInjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub block_mode: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PathTraversalConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub block_mode: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct XssConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub block_mode: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WafConfig {
    #[serde(default)]
    pub sql_injection: Option<SqlInjectionConfig>,
    #[serde(default)]
    pub xss: Option<XssConfig>,
    #[serde(default)]
    pub command_injection: Option<CommandInjectionConfig>,
    #[serde(default)]
    pub path_traversal: Option<PathTraversalConfig>,
    #[serde(default = "default_max_inspection_size_mb")]
    pub max_inspection_size_mb: usize,
}

impl WafConfig {
    /// Max inspection size in bytes (converts from MB config value).
    pub fn max_inspection_size(&self) -> usize {
        self.max_inspection_size_mb * 1_048_576
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_requests")]
    pub requests: u32,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
}

fn default_rate_limit_enabled() -> bool {
    true
}

fn default_requests() -> u32 {
    100
}

fn default_window_seconds() -> u64 {
    1
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            requests: default_requests(),
            window_seconds: default_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct UserAgentFilterConfig {
    #[serde(default = "default_ua_filter_enabled")]
    pub enabled: bool,
}

fn default_ua_filter_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BindAttribute {
    Ip,
    Tls,
    UserAgent,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct SessionBindingConfig {
    pub cookie_name: String,
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    pub bind_attributes: Vec<BindAttribute>,
}

fn default_ttl_seconds() -> u64 {
    86400
}

// Flexible host entry that supports both simple string and extended format
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum HostEntry {
    Simple(String),
    Extended {
        upstream: String,
        #[serde(default)]
        rate_limit: Option<RateLimitConfig>,
        #[serde(default)]
        session_binding: Option<SessionBindingConfig>,
        #[serde(default)]
        user_agent_filter: Option<UserAgentFilterConfig>,
        #[serde(default)]
        waf: Option<WafConfig>,
        #[serde(default)]
        max_request_body_mb: Option<usize>,
    },
}

fn default_max_request_body_mb() -> usize {
    0 // 0 = no limit
}

#[derive(Debug, Deserialize, Clone)]
pub struct RawConfig {
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub user_agent_filter: Option<UserAgentFilterConfig>,
    #[serde(default)]
    pub waf: Option<WafConfig>,
    #[serde(default = "default_max_request_body_mb")]
    pub max_request_body_mb: usize,
    pub hosts: HashMap<String, HostEntry>,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub sni: String,
    pub rate_limit: Option<RateLimitConfig>,
    pub session_binding: Option<SessionBindingConfig>,
    pub user_agent_filter: Option<UserAgentFilterConfig>,
    pub waf: Option<WafConfig>,
    pub max_request_body_mb: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub hosts: HashMap<String, UpstreamConfig>,
    pub global_rate_limit: Option<RateLimitConfig>,
    pub global_user_agent_filter: Option<UserAgentFilterConfig>,
    pub global_waf: Option<WafConfig>,
    pub global_max_request_body_mb: usize,
}

pub struct ProxyConfig {
    pub host: String,
    pub port: String,
    pub cert_dir: String,
    pub config_path: String,
}

impl ProxyConfig {
    pub fn from_env() -> Self {
        Self {
            host: env::var("PROXY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PROXY_PORT").unwrap_or_else(|_| "6188".to_string()),
            cert_dir: env::var("CERT_DIR").unwrap_or_else(|_| "./certificate".to_string()),
            config_path: env::var("CONFIG_PATH").unwrap_or_else(|_| "config/config.yaml".to_string()),
        }
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl AppConfig {
    pub fn from_raw(raw: RawConfig) -> Self {
        let hosts = raw
            .hosts
            .into_iter()
            .map(|(hostname, entry)| {
                let (upstream_addr, host_rate_limit, host_session_binding, host_ua_filter, host_waf, host_max_body) =
                    match entry {
                        HostEntry::Simple(addr) => (addr, None, None, None, None, None),
                        HostEntry::Extended {
                            upstream,
                            rate_limit,
                            session_binding,
                            user_agent_filter,
                            waf,
                            max_request_body_mb,
                        } => (upstream, rate_limit, session_binding, user_agent_filter, waf, max_request_body_mb),
                    };
                let mut upstream_config = Self::parse_upstream(&upstream_addr);
                upstream_config.rate_limit = host_rate_limit;
                upstream_config.session_binding = host_session_binding;
                upstream_config.user_agent_filter = host_ua_filter;
                upstream_config.waf = host_waf;
                upstream_config.max_request_body_mb = host_max_body;
                (hostname, upstream_config)
            })
            .collect();

        AppConfig {
            hosts,
            global_rate_limit: raw.rate_limit,
            global_user_agent_filter: raw.user_agent_filter,
            global_waf: raw.waf,
            global_max_request_body_mb: raw.max_request_body_mb,
        }
    }

    fn parse_upstream(upstream_addr: &str) -> UpstreamConfig {
        // Try to parse URL to detect http:// or https://
        let parsed_url =
            if upstream_addr.starts_with("http://") || upstream_addr.starts_with("https://") {
                Url::parse(upstream_addr).ok()
            } else {
                // If no scheme, add http:// temporarily for parsing
                Url::parse(&format!("http://{}", upstream_addr)).ok()
            };

        let (use_tls, sni, host, port) = match parsed_url {
            Some(parsed) => {
                let tls = parsed.scheme() == "https";
                let host = parsed.host_str().unwrap_or("").to_string();
                let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });

                // For IPs, SNI should be empty to avoid TLS issues
                let sni = if host.parse::<std::net::IpAddr>().is_ok() {
                    "".to_string()
                } else {
                    host.clone()
                };
                (tls, sni, host, port)
            }
            None => {
                error!("Failed to parse upstream URL '{}'", upstream_addr);
                // Fallback: assume it's already in host:port format
                let tls = upstream_addr.starts_with("https://");
                let clean = upstream_addr
                    .strip_prefix("https://")
                    .or_else(|| upstream_addr.strip_prefix("http://"))
                    .unwrap_or(upstream_addr);

                // Split host:port
                let parts: Vec<&str> = clean.split(':').collect();
                let host = parts.get(0).unwrap_or(&"localhost").to_string();
                let port =
                    parts
                        .get(1)
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(if tls { 443 } else { 80 });

                (tls, "".to_string(), host, port)
            }
        };

        UpstreamConfig {
            host,
            port,
            use_tls,
            sni,
            rate_limit: None,
            session_binding: None,
            user_agent_filter: None,
            waf: None,
            max_request_body_mb: None,
        }
    }

    /// Resolve max request body size (in bytes) for a host.
    /// Per-host overrides global. Returns 0 if no limit is set.
    pub fn resolve_max_request_body(&self, host: &str) -> usize {
        let mb = self
            .hosts
            .get(host)
            .and_then(|u| u.max_request_body_mb)
            .unwrap_or(self.global_max_request_body_mb);
        mb * 1_048_576
    }

    /// Resolve WAF config for a given host: per-host overrides global.
    pub fn resolve_waf_config(&self, host: &str) -> Option<WafConfig> {
        if let Some(upstream) = self.hosts.get(host) {
            if upstream.waf.is_some() {
                return upstream.waf.clone();
            }
        }
        self.global_waf.clone()
    }
}

use log::error;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use url::Url;

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
    },
}

#[derive(Debug, Deserialize, Clone)]
pub struct RawConfig {
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
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
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub hosts: HashMap<String, UpstreamConfig>,
    pub global_rate_limit: Option<RateLimitConfig>,
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
            config_path: env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string()),
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
                let (upstream_addr, host_rate_limit, host_session_binding) = match entry {
                    HostEntry::Simple(addr) => (addr, None, None),
                    HostEntry::Extended {
                        upstream,
                        rate_limit,
                        session_binding,
                    } => (upstream, rate_limit, session_binding),
                };
                let mut upstream_config = Self::parse_upstream(&upstream_addr);
                upstream_config.rate_limit = host_rate_limit;
                upstream_config.session_binding = host_session_binding;
                (hostname, upstream_config)
            })
            .collect();

        AppConfig {
            hosts,
            global_rate_limit: raw.rate_limit,
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
        }
    }
}

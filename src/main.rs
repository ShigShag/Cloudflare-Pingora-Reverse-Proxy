use async_trait::async_trait;
use env_logger::Env;
use log::{error, info};
use pingora::prelude::*;
use pingora::services::background::{background_service, BackgroundService};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::ShutdownWatch;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use url::Url;

// --- Configuration Structs ---
#[derive(Debug, Deserialize, Clone)]
struct RawConfig {
    hosts: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct UpstreamConfig {
    host: String,
    port: u16,
    use_tls: bool,
    sni: String,
}

#[derive(Debug, Clone)]
struct AppConfig {
    hosts: HashMap<String, UpstreamConfig>,
}

struct ProxyConfig {
    host: String,
    port: String,
    cert_dir: String,
    config_path: String,
}

impl ProxyConfig {
    fn from_env() -> Self {
        Self {
            host: env::var("PROXY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PROXY_PORT").unwrap_or_else(|_| "6188".to_string()),
            cert_dir: env::var("CERT_DIR").unwrap_or_else(|_| "./certificate".to_string()),
            config_path: env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string()),
        }
    }

    fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl AppConfig {
    fn from_raw(raw: RawConfig) -> Self {
        let hosts = raw
            .hosts
            .into_iter()
            .map(|(hostname, upstream_addr)| {
                let upstream_config = Self::parse_upstream(&upstream_addr);
                (hostname, upstream_config)
            })
            .collect();

        AppConfig { hosts }
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
        }
    }
}

// --- Background Service: Config Watcher ---
struct ConfigWatcher {
    path: String,
    config: Arc<RwLock<AppConfig>>,
    last_mtime: Arc<RwLock<SystemTime>>,
}

#[async_trait]
impl BackgroundService for ConfigWatcher {
    fn start<'life0, 'async_trait>(
        &'life0 self,
        mut shutdown: ShutdownWatch,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let path = Path::new(&self.path);

            loop {
                // 1. Perform the check and reload logic
                if path.exists() {
                    if let Ok(metadata) = std::fs::metadata(path) {
                        if let Ok(mtime) = metadata.modified() {
                            let needs_reload = {
                                let last = self.last_mtime.read().unwrap();
                                mtime > *last
                            };

                            if needs_reload {
                                info!("Config change detected, reloading...");
                                if let Ok(file) = File::open(path) {
                                    if let Ok(raw_config) =
                                        serde_yaml::from_reader::<_, RawConfig>(file)
                                    {
                                        let new_config = AppConfig::from_raw(raw_config);
                                        *self.config.write().unwrap() = new_config;
                                        *self.last_mtime.write().unwrap() = mtime;
                                        info!("Configuration reloaded.");
                                    }
                                }
                            }
                        }
                    }
                }

                // 2. Wait for either the interval OR the shutdown signal
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        // Continue loop
                    }
                    _ = shutdown.changed() => {
                        info!("Config watcher shutting down.");
                        break;
                    }
                }
            }
        })
    }
}
// --- Proxy Logic ---
struct HostSwitchProxy {
    // Wrapped in RwLock to allow updates while running
    config: Arc<RwLock<AppConfig>>,
}

#[async_trait]
impl ProxyHttp for HostSwitchProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let host = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| session.req_header().uri.host())
            .unwrap_or("");

        // ACQUIRE READ LOCK - This is fast and allows multiple threads to read
        let upstream_config = {
            let conf = self.config.read().unwrap();
            conf.hosts.get(host).cloned()
        };

        if let Some(config) = upstream_config {
            info!(
                "Routing {} -> {}:{} (TLS: {}, SNI: '{}')",
                host, config.host, config.port, config.use_tls, config.sni
            );

            // Create peer with parsed config
            let mut peer: Box<HttpPeer> = Box::new(HttpPeer::new(
                (config.host.as_str(), config.port),
                config.use_tls,
                config.sni,
            ));

            // Disable certificate verification for HTTPS upstreams
            if config.use_tls {
                peer.options.verify_cert = false;
                peer.options.verify_hostname = false;
            }

            Ok(peer)
        } else {
            error!("Unknown host: {}", host);
            Err(Error::explain(
                HTTPStatus(404),
                format!("Host {} not configured", host),
            ))
        }
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        let ip_address = session
            .client_addr()
            .and_then(|a| a.as_inet().map(|inet| inet.ip()))
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "<unknown>".into());

        // If header already exists, append (common proxy behavior),
        // otherwise insert a fresh one
        if let Some(existing) = upstream_request.headers.get("X-Forwarded-For") {
            let mut new_val = existing.to_str().unwrap_or("").to_string();
            if !new_val.is_empty() {
                new_val.push_str(", ");
            }
            new_val.push_str(&ip_address);

            if let Err(err) = upstream_request.insert_header("X-Forwarded-For", &new_val) {
                log::error!("Failed to set X-Forwarded-For header: {:?}", err);
            }
        } else if let Err(err) = upstream_request.insert_header("X-Forwarded-For", &ip_address) {
            log::error!("Failed to set X-Forwarded-For header: {:?}", err);
        }

        log::debug!("Set X-Forwarded-For: {}", ip_address);

        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        _ctx: &mut Self::CTX,
    ) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        info!(
            "{} {} {}",
            session.req_header().method,
            session.req_header().uri.path(),
            response_code
        );
    }
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // 1. Load Env Vars
    let env_conf = ProxyConfig::from_env();

    // 2. Initial Config Load
    info!("Loading config from: {}", env_conf.config_path);
    let config_file = File::open(&env_conf.config_path).expect("Could not open config file");
    let raw_config: RawConfig =
        serde_yaml::from_reader(config_file).expect("Could not parse config file");
    let initial_config = AppConfig::from_raw(raw_config);

    // Create the shared state
    let config_wrapper = Arc::new(RwLock::new(initial_config));

    // 3. Initialize Pingora Server
    let mut my_server = Server::new(None).expect("Failed to create server");
    my_server.bootstrap();

    // 4. Setup Background Config Watcher
    // We create a new "Service" that runs every 5 seconds
    let watcher_logic = ConfigWatcher {
        path: env_conf.config_path.clone(),
        config: config_wrapper.clone(),
        last_mtime: Arc::new(RwLock::new(SystemTime::now())),
    };

    let watcher_service = background_service("config_watcher", watcher_logic);
    my_server.add_service(watcher_service);

    // 5. Create Proxy Service
    let proxy_logic = HostSwitchProxy {
        config: config_wrapper,
    };
    let mut lb_service = http_proxy_service(&my_server.configuration, proxy_logic);

    // 6. Configure TLS
    let cert_path = format!("{}/server.crt", env_conf.cert_dir);
    let key_path = format!("{}/server.key", env_conf.cert_dir);

    if !Path::new(&cert_path).exists() || !Path::new(&key_path).exists() {
        panic!(
            "TLS Certificates not found at: {} and {}",
            cert_path, key_path
        );
    }

    let mut tls_settings = TlsSettings::intermediate(&cert_path, &key_path).unwrap();
    tls_settings.enable_h2();

    info!("Listening on {} with TLS enabled", env_conf.address());
    lb_service.add_tls_with_settings(&env_conf.address(), None, tls_settings);

    // 7. Add Services to Server and Run
    my_server.add_service(lb_service); // Add the proxy
    my_server.run_forever();
}

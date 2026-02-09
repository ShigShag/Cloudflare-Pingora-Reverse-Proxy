use async_trait::async_trait;
use log::{debug, error, info, warn};
use pingora::prelude::*;
use pingora_limits::rate::Rate;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

use crate::config::AppConfig;

// Global rate limiter with 1-second window
static RATE_LIMITER: LazyLock<Rate> = LazyLock::new(|| Rate::new(Duration::from_secs(1)));

pub struct HostSwitchProxy {
    pub config: Arc<RwLock<AppConfig>>,
}

#[async_trait]
impl ProxyHttp for HostSwitchProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        if let Some(digest) = session.digest() {
            if let Some(ssl) = &digest.ssl_digest {
                debug!("--- TLS STATIC ANALYSIS ---");
                debug!("Version: {:?}", ssl.version);
                debug!("Negotiated Cipher: {:?}", ssl.cipher);
                debug!("Cert SN: {:?}", ssl.serial_number);
            } else {
                debug!("Request is not TLS (Plaintext)");
            }
        }

        // Extract client IP for rate limiting key
        let client_ip = session
            .client_addr()
            .and_then(|a| a.as_inet().map(|inet| inet.ip()))
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Get host header to determine which rate limit config to use
        let host = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| session.req_header().uri.host())
            .unwrap_or("");

        // Get rate limit config (per-host overrides global)
        let rate_limit_config = {
            let conf = self.config.read().unwrap_or_else(|e| e.into_inner());

            // First check for per-host rate limit
            if let Some(upstream) = conf.hosts.get(host) {
                if upstream.rate_limit.is_some() {
                    upstream.rate_limit.clone()
                } else {
                    conf.global_rate_limit.clone()
                }
            } else {
                conf.global_rate_limit.clone()
            }
        };

        // Apply rate limiting if configured
        if let Some(rl_config) = rate_limit_config {
            if rl_config.enabled {
                // Observe the request and get current count
                let current_count = RATE_LIMITER.observe(&client_ip, 1);

                // Check if limit exceeded
                if current_count > rl_config.requests_per_second as isize {
                    warn!(
                        "Rate limit exceeded for {} on host {}: {}/{}",
                        client_ip, host, current_count, rl_config.requests_per_second
                    );

                    return Err(Error::explain(HTTPStatus(429), "Rate limit exceeded"));
                }
            }
        }

        Ok(false) // false = continue processing, true = response already sent
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

        let upstream_config = {
            let conf = self.config.read().unwrap_or_else(|e| e.into_inner());
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

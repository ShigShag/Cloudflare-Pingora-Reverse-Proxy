use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, error, info, warn};
use pingora::prelude::*;
use pingora_limits::rate::Rate;
use pingora_proxy::FailToProxy;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

use crate::config::{AppConfig, SessionBindingConfig};
use crate::session_store::{
    compute_fingerprint, extract_cookie_value, extract_set_cookie_value, SetCookieResult,
    SESSION_STORE,
};

// Global rate limiter with 1-second window
static RATE_LIMITER: LazyLock<Rate> = LazyLock::new(|| Rate::new(Duration::from_secs(1)));

// Custom 503 error page loaded from static/503.html at first use
static ERROR_503_HTML: LazyLock<Bytes> = LazyLock::new(|| {
    let dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "./static".to_string());
    let path = format!("{}/503.html", dir);
    std::fs::read(&path)
        .map(Bytes::from)
        .unwrap_or_else(|_| Bytes::from_static(b"<h1>503 Service Unavailable</h1>"))
});

/// Extract the hostname from a request, stripping the port if present.
/// e.g. "test.com:6188" -> "test.com"
fn extract_host(session: &Session) -> String {
    let raw = session
        .req_header()
        .headers
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .or_else(|| session.req_header().uri.host())
        .unwrap_or("");
    // Strip port suffix (e.g. ":6188")
    raw.split(':').next().unwrap_or(raw).to_string()
}

pub struct HostSwitchProxy {
    pub config: Arc<RwLock<AppConfig>>,
}

pub struct RequestCtx {
    pub fingerprint: Option<u64>,
    pub host: String,
    pub session_binding: Option<SessionBindingConfig>,
}

#[async_trait]
impl ProxyHttp for HostSwitchProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            fingerprint: None,
            host: String::new(),
            session_binding: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
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

        // Get host header (strip port if present)
        let host = extract_host(session);

        // Read config once for this request
        let (rate_limit_config, session_binding_config) = {
            let conf = self.config.read().unwrap_or_else(|e| e.into_inner());

            if let Some(upstream) = conf.hosts.get(&host) {
                let rl = if upstream.rate_limit.is_some() {
                    upstream.rate_limit.clone()
                } else {
                    conf.global_rate_limit.clone()
                };
                (rl, upstream.session_binding.clone())
            } else {
                (conf.global_rate_limit.clone(), None)
            }
        };

        // Store host and session binding config in CTX for later phases
        ctx.host = host.clone();
        ctx.session_binding = session_binding_config.clone();

        // Session binding verification
        if let Some(ref sb_config) = session_binding_config {
            if let Some(cookie_header) = session
                .req_header()
                .headers
                .get("Cookie")
                .and_then(|h| h.to_str().ok())
            {
                if let Some(cookie_value) =
                    extract_cookie_value(cookie_header, &sb_config.cookie_name)
                {
                    let fingerprint = compute_fingerprint(session, sb_config);
                    ctx.fingerprint = Some(fingerprint);

                    let user_agent = session
                        .req_header()
                        .headers
                        .get("User-Agent")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("<none>");

                    match SESSION_STORE.get_fingerprint(&host, &cookie_value) {
                        Some(stored_fp) if stored_fp != fingerprint => {
                            warn!(
                                "Session binding mismatch for {} on host {}: cookie={} (expected fp={}, got fp={}, UA={})",
                                client_ip, host, sb_config.cookie_name, stored_fp, fingerprint, user_agent
                            );
                            return Err(Error::explain(
                                HTTPStatus(403),
                                "Session binding mismatch",
                            ));
                        }
                        Some(_) => {
                            debug!("Session binding verified for {} on host {}", client_ip, host);
                        }
                        None => {
                            // No stored fingerprint — cookie exists but we haven't bound it yet.
                            // Don't bind here; only bind in upstream_response_filter when the
                            // upstream actually sets the cookie via Set-Cookie header.
                            debug!(
                                "No binding found for {} on host {}, allowing through",
                                client_ip, host
                            );
                        }
                    }
                }
            }
        }

        // Apply rate limiting if configured
        if let Some(rl_config) = rate_limit_config {
            if rl_config.enabled {
                let current_count = RATE_LIMITER.observe(&client_ip, 1);

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
        let host = extract_host(session);

        let upstream_config = {
            let conf = self.config.read().unwrap_or_else(|e| e.into_inner());
            conf.hosts.get(&host).cloned()
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

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let sb_config = match &ctx.session_binding {
            Some(c) => c,
            None => return Ok(()),
        };

        for value in upstream_response.headers.get_all("set-cookie") {
            let header_str = match value.to_str() {
                Ok(s) => s,
                Err(_) => continue,
            };

            match extract_set_cookie_value(header_str, &sb_config.cookie_name) {
                Some(SetCookieResult::Cleared) => {
                    // Upstream is clearing the cookie (logout)
                    // Remove the old binding if the request carried the cookie
                    if let Some(old_cookie) = session
                        .req_header()
                        .headers
                        .get("Cookie")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|h| extract_cookie_value(h, &sb_config.cookie_name))
                    {
                        SESSION_STORE.remove(&ctx.host, &old_cookie);
                        info!(
                            "Session binding cleared (logout) for host {}",
                            ctx.host
                        );
                    }
                }
                Some(SetCookieResult::Value { cookie_value, ttl: cookie_ttl }) => {
                    // Upstream is setting/refreshing the session cookie — bind it
                    let fingerprint = ctx.fingerprint.unwrap_or_else(|| {
                        compute_fingerprint(session, sb_config)
                    });
                    // Use TTL from cookie (Max-Age/Expires), fall back to config
                    let ttl = cookie_ttl.unwrap_or(Duration::from_secs(sb_config.ttl_seconds));
                    SESSION_STORE.insert(
                        ctx.host.clone(),
                        cookie_value,
                        fingerprint,
                        ttl,
                    );
                    info!(
                        "Session bound for host {} (ttl={}s)",
                        ctx.host, ttl.as_secs()
                    );
                }
                None => {}
            }
        }

        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        _ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let code = match e.etype() {
            HTTPStatus(code) => {
                session.respond_error(*code).await.ok();
                *code
            }
            ConnectRefused | ConnectTimedout | ConnectNoRoute | ConnectError => {
                // Upstream unreachable — serve styled 503 page
                let mut resp = ResponseHeader::build(503, Some(3)).unwrap();
                resp.insert_header("Content-Type", "text/html; charset=utf-8")
                    .ok();
                resp.insert_header("Cache-Control", "no-store").ok();
                session
                    .write_response_header(Box::new(resp), false)
                    .await
                    .ok();
                session
                    .write_response_body(Some(ERROR_503_HTML.clone()), true)
                    .await
                    .ok();
                503
            }
            _ => {
                let code = match e.esource() {
                    ErrorSource::Upstream => 502,
                    ErrorSource::Downstream => match e.etype() {
                        WriteError | ReadError | ConnectionClosed => 0,
                        _ => 400,
                    },
                    ErrorSource::Internal | ErrorSource::Unset => 500,
                };
                if code > 0 {
                    session.respond_error(code).await.ok();
                }
                code
            }
        };

        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
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

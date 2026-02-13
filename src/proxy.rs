use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, error, info, warn};
use pingora::prelude::*;
use pingora_limits::rate::Rate;
use pingora_proxy::FailToProxy;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

use crate::config::{AppConfig, SessionBindingConfig};
use crate::session_store::{
    compute_fingerprint, extract_cookie_value, extract_set_cookie_value, SetCookieResult,
    SESSION_STORE,
};
use crate::waf::command_injection::CommandInjectionRule;
use crate::waf::path_traversal::PathTraversalRule;
use crate::waf::sql_injection::SqlInjectionRule;
use crate::waf::xss::XssRule;
use crate::waf::{SecurityViolation, WafEngine};

// Per-window-duration rate limiters (keyed by window_seconds)
static RATE_LIMITERS: LazyLock<RwLock<HashMap<u64, Arc<Rate>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Get (or create) a Rate instance for the given window duration in seconds.
fn get_rate_limiter(window_seconds: u64) -> Arc<Rate> {
    let window_seconds = window_seconds.max(1);
    // Fast path: read lock
    {
        let map = RATE_LIMITERS.read().unwrap_or_else(|e| e.into_inner());
        if let Some(rate) = map.get(&window_seconds) {
            return Arc::clone(rate);
        }
    }
    // Slow path: write lock, insert if missing
    let mut map = RATE_LIMITERS.write().unwrap_or_else(|e| e.into_inner());
    Arc::clone(map.entry(window_seconds).or_insert_with(|| {
        Arc::new(Rate::new(Duration::from_secs(window_seconds)))
    }))
}

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
    pub  config: Arc<RwLock<AppConfig>>,
}

pub struct RequestCtx {
    pub fingerprint: Option<u64>,
    pub host: String,
    pub session_binding: Option<SessionBindingConfig>,
    // WAF state
    pub waf_body_buffer: Vec<u8>,
    pub waf_max_inspection_size: usize,
    pub waf_body_overlimit: bool,
    pub waf_violations: Vec<SecurityViolation>,
}

#[async_trait]
impl ProxyHttp for HostSwitchProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            fingerprint: None,
            host: String::new(),
            session_binding: None,
            waf_body_buffer: Vec::new(),
            waf_max_inspection_size: 1_048_576,
            waf_body_overlimit: false,
            waf_violations: Vec::new(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Extract client IP for rate limiting key
        let client_ip = session
            .client_addr()
            .and_then(|a| a.as_inet().map(|inet| inet.ip()))
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Get host header (strip port if present)
        let host = extract_host(session);

        // Read config once for this request
        let (rate_limit_config, session_binding_config, ua_filter_enabled) = {
            let conf = self.config.read().unwrap_or_else(|e| e.into_inner());

            if let Some(upstream) = conf.hosts.get(&host) {
                let rl = if upstream.rate_limit.is_some() {
                    upstream.rate_limit.clone()
                } else {
                    conf.global_rate_limit.clone()
                };

                // Per-host overrides global (same pattern as rate_limit)
                let ua_enabled = if let Some(ref host_ua) = upstream.user_agent_filter {
                    host_ua.enabled
                } else if let Some(ref global_ua) = conf.global_user_agent_filter {
                    global_ua.enabled
                } else {
                    false
                };

                (rl, upstream.session_binding.clone(), ua_enabled)
            } else {
                let ua_enabled = conf
                    .global_user_agent_filter
                    .as_ref()
                    .map(|f| f.enabled)
                    .unwrap_or(false);
                (conf.global_rate_limit.clone(), None, ua_enabled)
            }
        };

        // Store host and session binding config in CTX for later phases
        ctx.host = host.clone();
        ctx.session_binding = session_binding_config.clone();

        // Max request body size enforcement (413 if Content-Length exceeds limit)
        {
            let max_body = {
                let conf = self.config.read().unwrap_or_else(|e| e.into_inner());
                conf.resolve_max_request_body(&host)
            };
            if max_body > 0 {
                if let Some(cl) = session
                    .req_header()
                    .headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok())
                {
                    if cl > max_body {
                        warn!(
                            "Request body too large ({} > {}) from {} on host {}",
                            cl, max_body, client_ip, host
                        );
                        return Err(Error::explain(
                            HTTPStatus(413),
                            "Request body too large",
                        ));
                    }
                }
            }
        }

        // User-agent filtering (before session binding and rate limiting)
        if ua_filter_enabled {
            let user_agent = session
                .req_header()
                .headers
                .get("User-Agent")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            if crate::ua_regex::is_bad_user_agent(user_agent) {
                warn!(
                    "Blocked bad user-agent from {} on host {}: UA={}",
                    client_ip, host, user_agent
                );
                return Err(Error::explain(
                    HTTPStatus(403),
                    "Forbidden: blocked user agent",
                ));
            }
        }

        // --- WAF header inspection ---
        {
            let waf_config = {
                let conf = self.config.read().unwrap_or_else(|e| e.into_inner());
                conf.resolve_waf_config(&host)
            };

            if let Some(ref waf_conf) = waf_config {
                // Store max_inspection_size for body phase
                ctx.waf_max_inspection_size = waf_conf.max_inspection_size();

                // Early Content-Length check
                if let Some(cl) = session
                    .req_header()
                    .headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok())
                {
                    if cl > waf_conf.max_inspection_size() {
                        ctx.waf_body_overlimit = true;
                        warn!(
                            "WAF: Request body too large ({} > {}) from {} on host {}",
                            cl, waf_conf.max_inspection_size(), client_ip, host
                        );
                    }
                }

                // Build WAF engine from current config
                let mut engine = WafEngine::new();

                if let Some(ref sql_conf) = waf_conf.sql_injection {
                    if sql_conf.enabled {
                        engine.add_rule(Box::new(SqlInjectionRule {
                            enabled: true,
                            block_mode: sql_conf.block_mode,
                        }));
                    }
                }

                if let Some(ref xss_conf) = waf_conf.xss {
                    if xss_conf.enabled {
                        engine.add_rule(Box::new(XssRule {
                            enabled: true,
                            block_mode: xss_conf.block_mode,
                        }));
                    }
                }

                if let Some(ref cmd_conf) = waf_conf.command_injection {
                    if cmd_conf.enabled {
                        engine.add_rule(Box::new(CommandInjectionRule {
                            enabled: true,
                            block_mode: cmd_conf.block_mode,
                        }));
                    }
                }

                if let Some(ref pt_conf) = waf_conf.path_traversal {
                    if pt_conf.enabled {
                        engine.add_rule(Box::new(PathTraversalRule {
                            enabled: true,
                            block_mode: pt_conf.block_mode,
                        }));
                    }
                }

                // Run header-phase checks
                let violations = engine.check_headers(session.req_header());

                for v in &violations {
                    warn!(
                        "WAF violation from {} on host {}: [{}/{}] {} (blocked: {})",
                        client_ip, host, v.threat_type, v.threat_level, v.description, v.blocked
                    );
                }

                let should_block = violations.iter().any(|v| v.blocked);
                ctx.waf_violations.extend(violations);

                if should_block {
                    return Err(Error::explain(
                        HTTPStatus(403),
                        "Forbidden: WAF policy violation",
                    ));
                }
            }
        }

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
                let limiter = get_rate_limiter(rl_config.window_seconds);
                let current_count = limiter.observe(&client_ip, 1);

                if current_count > rl_config.requests as isize {
                    warn!(
                        "Rate limit exceeded for {} on host {}: {}/{} per {}s",
                        client_ip, host, current_count, rl_config.requests, rl_config.window_seconds
                    );

                    return Err(Error::explain(HTTPStatus(429), "Rate limit exceeded"));
                }
            }
        }

        Ok(false) // false = continue processing, true = response already sent
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Accumulate body chunks (only if WAF is relevant and not overlimit)
        if !ctx.waf_body_overlimit {
            if let Some(ref chunk) = body {
                let new_len = ctx.waf_body_buffer.len() + chunk.len();
                if new_len > ctx.waf_max_inspection_size {
                    ctx.waf_body_overlimit = true;
                    ctx.waf_body_buffer.clear();
                    warn!(
                        "WAF: Accumulated body exceeds max_inspection_size ({}) for host {}",
                        ctx.waf_max_inspection_size, ctx.host
                    );
                } else {
                    ctx.waf_body_buffer.extend_from_slice(chunk);
                }
            }
        }

        // When stream is complete and we have a body, run WAF rules
        if end_of_stream && !ctx.waf_body_buffer.is_empty() {
            let waf_config = {
                let conf = self.config.read().unwrap_or_else(|e| e.into_inner());
                conf.resolve_waf_config(&ctx.host)
            };

            if let Some(ref waf_conf) = waf_config {
                let client_ip = session
                    .client_addr()
                    .and_then(|a| a.as_inet().map(|inet| inet.ip()))
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let mut engine = WafEngine::new();
                if let Some(ref sql_conf) = waf_conf.sql_injection {
                    if sql_conf.enabled {
                        engine.add_rule(Box::new(SqlInjectionRule {
                            enabled: true,
                            block_mode: sql_conf.block_mode,
                        }));
                    }
                }

                if let Some(ref xss_conf) = waf_conf.xss {
                    if xss_conf.enabled {
                        engine.add_rule(Box::new(XssRule {
                            enabled: true,
                            block_mode: xss_conf.block_mode,
                        }));
                    }
                }

                if let Some(ref cmd_conf) = waf_conf.command_injection {
                    if cmd_conf.enabled {
                        engine.add_rule(Box::new(CommandInjectionRule {
                            enabled: true,
                            block_mode: cmd_conf.block_mode,
                        }));
                    }
                }

                if let Some(ref pt_conf) = waf_conf.path_traversal {
                    if pt_conf.enabled {
                        engine.add_rule(Box::new(PathTraversalRule {
                            enabled: true,
                            block_mode: pt_conf.block_mode,
                        }));
                    }
                }

                let violations = engine.check_body(&ctx.waf_body_buffer);

                for v in &violations {
                    warn!(
                        "WAF body violation from {} on host {}: [{}/{}] {} (blocked: {})",
                        client_ip, ctx.host, v.threat_type, v.threat_level, v.description, v.blocked
                    );
                }

                let should_block = violations.iter().any(|v| v.blocked);
                ctx.waf_violations.extend(violations);

                if should_block {
                    return Err(Error::explain(
                        HTTPStatus(403),
                        "Forbidden: WAF body inspection blocked request",
                    ));
                }
            }
        }

        Ok(())
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
        ctx: &mut Self::CTX,
    ) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());

        // Log WAF summary if there were violations
        if !ctx.waf_violations.is_empty() {
            let blocked_count = ctx.waf_violations.iter().filter(|v| v.blocked).count();
            let logged_count = ctx.waf_violations.len() - blocked_count;
            info!(
                "WAF summary for {} {}: {} violations ({} blocked, {} logged)",
                session.req_header().method,
                session.req_header().uri.path(),
                ctx.waf_violations.len(),
                blocked_count,
                logged_count,
            );
        }

        info!(
            "{} {} {}",
            session.req_header().method,
            session.req_header().uri.path(),
            response_code
        );

        // Clear WAF body buffer for connection reuse
        ctx.waf_body_buffer.clear();
        ctx.waf_body_buffer.shrink_to_fit();
        ctx.waf_violations.clear();
    }
}

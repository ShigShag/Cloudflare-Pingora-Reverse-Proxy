# WAF Features

## Architecture

Standalone `pingora-waf` subcrate with a pluggable `SecurityRule` trait. Each detector implements `check(&RequestHeader, Option<&[u8]>) -> Result<(), SecurityViolation>`. The `RuleEngine` evaluates all rules per request and collects violations with threat type, threat level, description, and blocked status. Every rule supports `enabled` and `block_mode` (block vs log-only) toggles.

Threat levels: **Critical** (SQL injection, command injection, blacklisted IP), **High** (XSS, path traversal, bad bots), **Medium** (rate limit, suspicious bots), **Low** (protocol violations).

---

## Attack Detection

- **SQL injection** — 17 regex patterns: union/select, boolean injection (`' OR 1=1`), data manipulation (INSERT/DELETE/DROP/UPDATE), statement termination, comment injection (`--`), stored procedures (`xp_`, `sp_`), time-based blind (`BENCHMARK`, `SLEEP`, `WAITFOR DELAY`), hex encoding bypass. URL-decodes before matching. Skips safe headers (Accept, Host, Content-Type, etc.). Inspects URI, custom headers, and full request body. Critical threat level (403 on block)
- **XSS** — 13 regex patterns: `<script>` tags, event handlers (`onload`, `onerror`, `onclick`), `javascript:` protocol, dangerous tags (`<iframe>`, `<object>`, `<embed>`), JS functions (`eval()`, `alert()`, `expression()`), `data:text/html` URLs. Same inspection pipeline as SQL injection. High threat level (403 on block)
- **Command injection** — 40+ regex patterns: command chaining (`;`, `|`, `||`, `&&`), command substitution (`$()`, backticks), shell redirections (`>`, `>>`, `<`, `2>&1`), dangerous commands (wget, curl, nc, rm, chmod, sudo, whoami, passwd, etc.), shell paths (`/bin/bash`, `cmd.exe`, `powershell`), environment variables (`$PATH`, `$HOME`, `%systemroot%`), URL-encoded variants (`%3b`, `%7c`, `%26`). Critical threat level (403 on block)
- **Path traversal** — Two detection categories. Traversal patterns (17): `../`, `..\`, URL-encoded `%2e%2e%2f`, double-encoded `%252e%252e`, unicode/overlong `%c0%ae`, null byte `%00`, bypass variants (`..../`, `..//`, `.././`). Sensitive file patterns (28): `/etc/passwd`, `/etc/shadow`, `/proc/`, `.ssh/`, `.env`, `id_rsa`, Windows system files (`win.ini`, `system32`), web server configs (`.htaccess`, `nginx.conf`, `httpd.conf`), app configs (`wp-config.php`, `database.yml`, `settings.py`). High threat level (403 on block)

---

## Access Control

- **IP filtering** — Whitelist/blacklist with CIDR notation for IPv4 and IPv6. Whitelist takes priority: if non-empty, only whitelisted IPs pass. Blacklist overrides whitelist for specific IPs. Supports individual addresses (`192.168.1.100`) and ranges (`10.0.0.0/8`, `2001:db8::/32`). Parses `X-Forwarded-For` with fallback to socket address (403 on block)
- **Bot detection** — 38 bad bot regex patterns covering security scanners (sqlmap, nikto, nmap, masscan, metasploit, burpsuite, acunetix), web scrapers (scrapy, httrack, webcopier), SEO spam bots (semrush, ahrefs, mj12bot, dotbot), and library defaults (python-requests, curl/, wget/, Go-http-client). 22 good bot identifiers (Googlebot, Bingbot, DuckDuckBot, social media bots, monitoring services). Missing, empty, or short (<10 char) User-Agent flagged as suspicious. Custom patterns via `custom_bad_bots` and `custom_good_bots` config. High/Medium threat level (403 on block)
- **Rate limiting** — Per-IP sliding window using DashMap. Configurable `max_requests` and `window_secs` (default: 100 req/60s). Automatic cleanup of expired entries. Medium threat level (429 on exceed)

---

## Request Inspection

- **Body inspection** — Streams request body chunks into a buffer with configurable `max_body_size` (default 1MB). Early rejection via `Content-Length` header check in `request_filter()`. Runs all four attack detectors (SQL, XSS, path traversal, command injection) against the complete body in `request_body_filter()` when `end_of_stream` is true. Buffer cleared in `logging()` for connection reuse
- **URL decoding** — All detectors URL-decode input before pattern matching, catching encoded bypass attempts (`%27`, `%3C`, `%2e%2e%2f`, etc.). Double-encoded and unicode/overlong variants handled by path traversal detector
- **Safe header filtering** — Each detector maintains a set of safe headers (Accept, Host, Content-Type, User-Agent, cache/connection headers, Sec-* headers) that are skipped during inspection to reduce false positives. Only custom/non-standard headers are scanned

---

## Monitoring & Observability

- **Prometheus metrics** — Three counters registered with Pingora's built-in Prometheus service: `waf_total_requests`, `waf_allowed_requests`, `waf_blocked_requests` (labeled by reason: `ip_blacklist`, `rate_limit`, `sql_injection`, `xss`, `path_traversal`, `command_injection`, `bad_bot`, `suspicious_bot`). Exposed on configurable metrics port (default `:6190`)
- **Violation logging** — Per-request violation tracking via `ProxyContext.violations`. Each violation logged at WARN level with full context: client IP, threat type, threat level, blocked status, description. Separate from general request logging (INFO level for allowed, ERROR for failures)

---

## Configuration

YAML-based config at `config/waf_rules.yaml` (override via `WAF_CONFIG` env var or `--config` flag).

```yaml
sql_injection:
  enabled: true
  block_mode: true       # false = log-only

xss:
  enabled: true
  block_mode: true

path_traversal:
  enabled: true
  block_mode: true

command_injection:
  enabled: true
  block_mode: true

rate_limit:
  enabled: true
  max_requests: 100
  window_secs: 60

ip_filter:
  enabled: true
  whitelist: []
  blacklist:
    - "192.168.1.100"
    - "10.0.0.0/8"

bot_detection:
  enabled: true
  block_mode: true
  allow_known_bots: true
  custom_bad_bots: []
  custom_good_bots: []

max_body_size: 1048576   # 1MB

hot_reload:
  enabled: true
  watch_interval_secs: 5 # Zero-downtime rule updates
```

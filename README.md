# Pingora Reverse Proxy

A TLS-enabled reverse proxy built with [Pingora](https://github.com/cloudflare/pingora) that routes requests based on Host headers.

## Features

- Host-based routing with TLS termination and SNI support
- Hot-reload configuration (5s poll interval, no downtime)
- Per-host rate limiting (IP-based, sliding window)
- Session binding to prevent session hijacking (fingerprints IP, TLS, User-Agent)
- Custom 503 error page
- X-Forwarded-For header injection
- HTTP/2 support

## Quick Start

### Configuration

Edit [config.yaml](config.yaml) to define your routing:

```yaml
# Global rate limit (applies to all hosts unless overridden)
rate_limit:
  enabled: false
  requests: 100
  window_seconds: 1

hosts:
  # Simple: just map host -> upstream
  "example.local": "http://127.0.0.1:8081"
  "api.local": "https://192.168.99.23:8082"

  # Advanced: per-host rate limit and session binding
  "app.local":
    upstream: "http://127.0.0.1:3000"
    rate_limit:
      enabled: true
      requests: 5000
      window_seconds: 60
    session_binding:
      cookie_name: "session_token"
      ttl_seconds: 86400
      bind_attributes:
        - user_agent
        - tls
        - ip
```

### TLS Certificates

Place `server.crt` and `server.key` in the `certificate/` directory. To generate a self-signed cert:

```bash
openssl req -x509 -newkey rsa:4096 -keyout certificate/server.key -out certificate/server.crt -days 365 -nodes -subj "/CN=localhost"
```

### Environment Variables

Configure in [.env](.env):

```env
PROXY_HOST=0.0.0.0
PROXY_PORT=6188
CERT_DIR=./certificate
CONFIG_PATH=./config.yaml
RUST_LOG=info
```

### Run

```bash
# Locally
cargo run --release

# Docker
docker build -t pingora-proxy .
docker run -p 6188:6188 pingora-proxy
```

### Test

```bash
curl -k -H "Host: example.local" https://localhost:6188
```

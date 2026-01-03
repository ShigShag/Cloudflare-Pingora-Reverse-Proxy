# Pingora Reverse Proxy

A TLS-enabled reverse proxy built with Pingora that routes requests based on Host headers.

## Quick Start

### Configuration

1. Edit [config.yaml](config.yaml) to define host mappings:
```yaml
hosts:
  "example.local": "http://127.0.0.1:8081"
  "api.local": "https://127.0.0.1:8082"
```

2. Place TLS certificates in the `certificate/` directory:
   - `server.crt`
   - `server.key`

To create a self signed certificate

```bash
openssl req -x509 -newkey rsa:4096 -keyout certificate/server.key -out certificate/server.crt -days 365 -nodes -subj "/CN=localhost"
```

3. Configure environment variables in [.env](.env):
```env
# Host and Port for Pingora to listen on
PROXY_HOST=0.0.0.0
PROXY_PORT=6188

# Directory containing server.crt and server.key
CERT_DIR=./certificate

# Path to the YAML routing configuration
CONFIG_PATH=./config.yaml

# Logging Level (info, debug, warn, error)
RUST_LOG=info
```

### Run Locally

```bash
cargo run --release
```

### Run with Docker

```bash
docker build -t pingora-proxy .
docker run -p 6188:6188 pingora-proxy
```

## Testing

```bash
curl -k -H "Host: example.local" https://localhost:6188
```

## Features

- Hot-reload configuration (5s check interval)
- HTTP/2 support
- TLS termination
- Automatic SNI handling

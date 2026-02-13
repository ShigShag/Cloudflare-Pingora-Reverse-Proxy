# Builder stage
FROM rust:bookworm as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    libclang-dev \
    clang \
    nodejs \
    npm \
 && npm install -g html-minifier-terser \
 && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /usr/src/pingora_proxy

# Copy Cargo.toml and Cargo.lock for dependency caching
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

# Create dummy main.rs to compile dependencies
RUN mkdir -p src \
    && echo "fn main() {println!(\"if you see this, the build broke\");}" > src/main.rs

# Build the application to cache the dependencies
RUN cargo build --release

# Remove the dummy source and compiled artifacts, then copy the actual source code
RUN rm -rf ./src ./target/release/deps/simple_pingora_proxy*
COPY ./src ./src

# Rebuild the application with the actual source code
RUN cargo build --release

# Minify static HTML assets
COPY ./static ./static-src
RUN mkdir -p ./static \
 && for f in ./static-src/*.html; do \
      html-minifier-terser \
        --collapse-whitespace \
        --remove-comments \
        --minify-css true \
        --minify-js true \
        "$f" -o "./static/$(basename "$f")"; \
    done \
 && cp -n ./static-src/* ./static/ 2>/dev/null || true

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies (CA certificates for TLS)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m proxyuser

# Create necessary directories
RUN mkdir -p /usr/src/pingora_proxy/certificate

# Copy binary from builder
COPY --from=builder /usr/src/pingora_proxy/target/release/simple_pingora_proxy /usr/local/bin/simple_pingora_proxy

# Copy minified static assets from builder
COPY --from=builder /usr/src/pingora_proxy/static /usr/src/pingora_proxy/static

# Fix permissions
RUN chown -R proxyuser:proxyuser /usr/src/pingora_proxy \
 && chmod -R 755 /usr/src/pingora_proxy

# Switch to non-root user
USER proxyuser

# Set working directory
WORKDIR /usr/src/pingora_proxy

# Expose the proxy port (default from .env)
EXPOSE 6188

# Set environment variables (these can be overridden at runtime)
ENV PROXY_HOST=0.0.0.0
ENV PROXY_PORT=6188
ENV CERT_DIR=/usr/src/pingora_proxy/certificate
ENV CONFIG_PATH=/usr/src/pingora_proxy/config/config.yaml
ENV STATIC_DIR=/usr/src/pingora_proxy/static
ENV RUST_LOG=info

CMD ["/usr/local/bin/simple_pingora_proxy"]

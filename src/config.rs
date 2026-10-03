//! Runtime configuration (CLI flags with environment-variable fallbacks).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Parser)]
#[command(version, about = "Arkion identity-aware mTLS reverse proxy")]
pub struct Config {
    /// mTLS listener.
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:8443")]
    pub listen_addr: SocketAddr,

    /// Plain-HTTP admin listener (health, readiness, status). Keep it off the public network.
    #[arg(long, env = "ADMIN_ADDR", default_value = "127.0.0.1:9901")]
    pub admin_addr: SocketAddr,

    /// Upstream base URL, scheme + authority only (e.g. http://backend:8080).
    #[arg(long, env = "UPSTREAM_URL", default_value = "http://127.0.0.1:8080")]
    pub upstream_url: String,

    /// Server certificate chain (PEM).
    #[arg(long, env = "TLS_CERT", default_value = "pki/server.crt")]
    pub tls_cert: PathBuf,

    /// Server private key (PEM, PKCS#8).
    #[arg(long, env = "TLS_KEY", default_value = "pki/server.key")]
    pub tls_key: PathBuf,

    /// Trusted CA bundle for client certificates (PEM, one or more CAs). Hot-reloaded.
    #[arg(long, env = "CLIENT_CA_BUNDLE", default_value = "pki/trust-bundle.pem")]
    pub client_ca_bundle: PathBuf,

    /// Authorization policy (YAML). Hot-reloaded.
    #[arg(long, env = "POLICY_FILE", default_value = "config/policy.yaml")]
    pub policy_file: PathBuf,

    /// How often trust/policy files are checked for changes (SIGHUP forces a check).
    #[arg(long, env = "RELOAD_INTERVAL_MS", default_value_t = 2000)]
    pub reload_interval_ms: u64,

    /// Only accept certificates with a SPIFFE URI SAN (no DNS-SAN fallback identity).
    #[arg(long, env = "REQUIRE_SPIFFE_ID", default_value_t = false, action = clap::ArgAction::Set)]
    pub require_spiffe_id: bool,

    /// Allowed SPIFFE trust domains (comma-separated). Empty = any trust domain the CA vouches for.
    #[arg(long, env = "TRUST_DOMAINS", value_delimiter = ',', default_value = "")]
    pub trust_domains: Vec<String>,

    /// Timeout for the upstream to return response headers.
    #[arg(long, env = "UPSTREAM_TIMEOUT_MS", default_value_t = 10_000)]
    pub upstream_timeout_ms: u64,

    /// Maximum request body forwarded upstream.
    #[arg(long, env = "MAX_BODY_BYTES", default_value_t = 10 * 1024 * 1024)]
    pub max_body_bytes: u64,

    /// Maximum concurrent requests being proxied; above this the proxy answers 503.
    #[arg(long, env = "MAX_CONCURRENCY", default_value_t = 1024)]
    pub max_concurrency: usize,

    /// Per-identity rate limit (requests/second). 0 disables rate limiting.
    #[arg(long, env = "RATE_LIMIT_RPS", default_value_t = 0)]
    pub rate_limit_rps: u32,

    /// Per-identity burst size.
    #[arg(long, env = "RATE_LIMIT_BURST", default_value_t = 100)]
    pub rate_limit_burst: u32,

    /// TLS handshake timeout.
    #[arg(long, env = "HANDSHAKE_TIMEOUT_MS", default_value_t = 5_000)]
    pub handshake_timeout_ms: u64,

    /// How long in-flight requests get to finish on shutdown.
    #[arg(long, env = "SHUTDOWN_GRACE_SECS", default_value_t = 20)]
    pub shutdown_grace_secs: u64,

    /// Identifier used in the Via header for loop detection. Defaults to a random id.
    #[arg(long, env = "INSTANCE_ID")]
    pub instance_id: Option<String>,

    #[arg(long, env = "LOG_FORMAT", value_enum, default_value = "text")]
    pub log_format: LogFormat,
}

impl Config {
    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_millis(self.upstream_timeout_ms)
    }

    pub fn reload_interval(&self) -> Duration {
        Duration::from_millis(self.reload_interval_ms)
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }

    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(self.shutdown_grace_secs)
    }

    pub fn trust_domains(&self) -> Vec<String> {
        self.trust_domains.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    }
}

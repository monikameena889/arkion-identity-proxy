//! Arkion identity-aware mTLS reverse proxy.
//!
//! Request flow: `Client --mTLS--> [Intercept -> Identify -> Authorize -> Observe] --> upstream`.
//!
//! - [`tls`]       — TLS server config, trust store, hot rotation (TLS-layer validation).
//! - [`identity`]  — certificate parsing and SPIFFE identity extraction (application-layer validation).
//! - [`policy`]    — file-based authorization policy and request-path safety checks.
//! - [`proxy`]     — upstream forwarding, header hygiene, loop detection, safe retries.
//! - [`middleware`]— request id, audit, identity, rate limit, authorization, concurrency limit.
//! - [`audit`]     — structured audit events and sinks.
//! - [`server`]    — accept loop, per-connection state, admin endpoints, reload loop, shutdown.
//! - [`devpki`]    — generates a throw-away PKI for tests and demos.
//! - [`echo`]      — tiny upstream used by tests, the demo and the benchmark.

pub mod audit;
pub mod config;
pub mod devpki;
pub mod echo;
pub mod error;
pub mod identity;
pub mod middleware;
pub mod policy;
pub mod proxy;
pub mod server;
pub mod tls;

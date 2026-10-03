//! The request pipeline. Layers run outermost first:
//!
//! ```text
//! request_id ─► observe (audit) ─► identify ─► rate_limit ─► authorize ─► proxy_handler
//!   Intercept       Observe          Identify                 Authorize     (concurrency limit,
//!                                                                             forward upstream)
//! ```
//!
//! `observe` wraps everything after it, so *every* outcome — allowed, denied by any layer, or
//! failed upstream — produces exactly one audit event. Inner layers record what they learned in a
//! shared [`AuditCtx`] placed in the request extensions.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota};
use rustls::pki_types::{CertificateDer, UnixTime};
use tokio::sync::Semaphore;

use crate::audit::{self, AuditEvent, AuditSink, CertSummary, Decision};
use crate::error::{error_response, with_connection_close, with_retry_after};
use crate::identity::{CertDetails, ClientIdentity, IdentityError, IdentityOptions, cert_details, extract_identity};
use crate::policy::{self, PolicyStore, check_request_path};
use crate::proxy::{ForwardContext, Upstream};
use crate::tls::TlsState;

/// Per-TLS-connection state, created after a successful handshake and attached to every request
/// on that connection.
pub struct ConnInfo {
    pub peer_addr: SocketAddr,
    /// Chain presented by the client (leaf first), already verified by rustls.
    pub chain: Vec<CertificateDer<'static>>,
    pub tls_version: String,
    /// Trust generation this connection's chain was last verified against.
    pub verified_generation: AtomicU64,
    /// Identity is derived once per connection (the certificate cannot change mid-connection).
    pub identity: OnceLock<Result<ClientIdentity, IdentityError>>,
}

#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// What the inner layers learned, for the audit event.
#[derive(Default)]
pub struct AuditCtx {
    pub identity: Option<String>,
    pub cert: Option<CertSummary>,
    pub decision: Option<Decision>,
    pub reason: String,
    pub upstream_status: Option<u16>,
    pub upstream_latency: Option<Duration>,
}

type SharedAuditCtx = Arc<Mutex<AuditCtx>>;

pub struct RateLimiter {
    limiter: DefaultKeyedRateLimiter<String>,
    clock: DefaultClock,
}

impl RateLimiter {
    pub fn new(rps: u32, burst: u32) -> Option<Self> {
        let rps = NonZeroU32::new(rps)?;
        let burst = NonZeroU32::new(burst.max(1))?;
        Some(Self {
            limiter: DefaultKeyedRateLimiter::keyed(Quota::per_second(rps).allow_burst(burst)),
            clock: DefaultClock::default(),
        })
    }

    /// `Err(wait)` if the identity is over its quota.
    pub fn check(&self, identity: &str) -> Result<(), Duration> {
        self.limiter.check_key(&identity.to_string()).map_err(|nu| nu.wait_time_from(self.clock.now()))
    }

    pub fn housekeeping(&self) {
        self.limiter.retain_recent();
    }
}

/// Shared state. A single `Arc` so that the per-request, per-layer clones axum makes cost one
/// atomic increment instead of one per field (that showed up as ~13% of CPU under load).
#[derive(Clone)]
pub struct AppState(Arc<AppInner>);

impl AppState {
    pub fn new(inner: AppInner) -> Self {
        Self(Arc::new(inner))
    }
}

impl std::ops::Deref for AppState {
    type Target = AppInner;
    fn deref(&self) -> &AppInner {
        &self.0
    }
}

pub struct AppInner {
    pub tls: Arc<TlsState>,
    pub policy: Arc<PolicyStore>,
    pub upstream: Arc<Upstream>,
    pub audit: Arc<dyn AuditSink>,
    pub limiter: Option<Arc<RateLimiter>>,
    pub concurrency: Arc<Semaphore>,
    pub identity_opts: Arc<IdentityOptions>,
    pub draining: Arc<AtomicBool>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .fallback(proxy_handler)
        .layer(middleware::from_fn_with_state(state.clone(), authorize))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(middleware::from_fn_with_state(state.clone(), identify))
        .layer(middleware::from_fn_with_state(state.clone(), observe))
        .layer(middleware::from_fn(request_id))
        .with_state(state)
}

// ---------------------------------------------------------------- Intercept

fn valid_request_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// Propagates a well-formed incoming `X-Request-Id`, otherwise generates a UUIDv4.
async fn request_id(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| valid_request_id(s))
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    req.extensions_mut().insert(RequestId(id.clone()));
    let mut resp = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

fn rid(req: &Request) -> String {
    req.extensions().get::<RequestId>().map(|r| r.0.clone()).unwrap_or_default()
}

fn ctx(req: &Request) -> Option<SharedAuditCtx> {
    req.extensions().get::<SharedAuditCtx>().cloned()
}

fn record(req: &Request, f: impl FnOnce(&mut AuditCtx)) {
    if let Some(c) = ctx(req) {
        f(&mut c.lock().unwrap());
    }
}

fn deny(req: &Request, status: StatusCode, code: &'static str, message: &str) -> Response {
    record(req, |c| {
        c.decision = Some(Decision::Deny);
        c.reason = code.to_string();
    });
    error_response(status, code, message, &rid(req))
}

// ---------------------------------------------------------------- Observe

async fn observe(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let started = Instant::now();
    let shared: SharedAuditCtx = Arc::new(Mutex::new(AuditCtx::default()));
    req.extensions_mut().insert(shared.clone());

    let request_id = rid(&req);
    let method = req.method().to_string();
    let path = req.uri().path().to_string(); // never the query: it may carry tokens
    let host = crate::proxy::original_host(req.headers(), req.uri());
    let headers = audit::safe_headers(req.headers());
    let http_version = format!("{:?}", req.version());
    let conn = req.extensions().get::<Arc<ConnInfo>>().cloned();
    let policy_generation = st.policy.generation();

    let resp = next.run(req).await;

    let elapsed = started.elapsed();
    let c = shared.lock().unwrap();
    let event = AuditEvent {
        timestamp: policy::now(),
        event: "http_request",
        request_id,
        identity: c.identity.clone(),
        cert: c.cert.clone(),
        client_addr: conn.as_ref().map(|c| c.peer_addr.to_string()).unwrap_or_default(),
        tls_version: conn.as_ref().map(|c| c.tls_version.clone()),
        http_version,
        method,
        path,
        host,
        headers,
        decision: c.decision.unwrap_or(Decision::Deny),
        reason: if c.reason.is_empty() { "unprocessed".into() } else { c.reason.clone() },
        status: resp.status().as_u16(),
        upstream_status: c.upstream_status,
        latency_ms: elapsed.as_millis() as u64,
        latency_us: elapsed.as_micros() as u64,
        upstream_latency_us: c.upstream_latency.map(|d| d.as_micros() as u64),
        policy_generation,
    };
    drop(c);
    st.audit.request(&event);
    resp
}

// ---------------------------------------------------------------- Identify

async fn identify(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let Some(conn) = req.extensions().get::<Arc<ConnInfo>>().cloned() else {
        // Only reachable if the router is served without the TLS accept loop.
        return deny(&req, StatusCode::UNAUTHORIZED, "no_client_certificate", "client certificate required");
    };

    // 1. Trust store rotated since this connection was verified? Re-verify its chain against the
    //    current verifier so that removing a CA takes effect on existing keep-alive connections.
    let snapshot = st.tls.current();
    if conn.verified_generation.load(Ordering::Acquire) != snapshot.generation {
        let (leaf, intermediates) = conn.chain.split_first().expect("verified connections always have a chain");
        match snapshot.verifier.verify_client_cert(leaf, intermediates, UnixTime::now()) {
            Ok(_) => conn.verified_generation.store(snapshot.generation, Ordering::Release),
            Err(e) => {
                tracing::warn!(peer = %conn.peer_addr, error = %e, "connection's certificate is no longer trusted after rotation");
                let resp = deny(
                    &req,
                    StatusCode::UNAUTHORIZED,
                    "certificate_no_longer_trusted",
                    "client certificate is not trusted by the current trust store",
                );
                return with_connection_close(resp);
            }
        }
    }

    // 2. Connections can outlive certificates: re-check the validity window on every request.
    let identity = conn.identity.get_or_init(|| extract_identity(&conn.chain, &st.identity_opts)).clone();
    let identity = match identity {
        Ok(id) => id,
        Err(e) => {
            let code = match e {
                IdentityError::TrustDomainNotAllowed(_) => "trust_domain_not_allowed",
                IdentityError::NoIdentity(_) => "no_identity",
                _ => "malformed_identity",
            };
            // Still record which certificate was presented: that is what an investigator needs.
            if let Ok(details) = cert_details(&conn.chain) {
                let summary = cert_summary(&details, conn.verified_generation.load(Ordering::Acquire));
                record(&req, |c| c.cert = Some(summary));
            }
            return deny(&req, StatusCode::UNAUTHORIZED, code, &e.to_string());
        }
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let summary = cert_summary(&identity.cert, conn.verified_generation.load(Ordering::Acquire));
    record(&req, |c| {
        c.identity = Some(identity.id.clone());
        c.cert = Some(summary);
    });
    if now > identity.cert.not_after_unix || now < identity.cert.not_before_unix {
        let resp = deny(
            &req,
            StatusCode::UNAUTHORIZED,
            "certificate_expired",
            "client certificate is outside its validity period",
        );
        return with_connection_close(resp);
    }

    req.extensions_mut().insert(identity);
    next.run(req).await
}

fn cert_summary(cert: &CertDetails, trust_generation: u64) -> CertSummary {
    CertSummary {
        subject: cert.subject.clone(),
        issuer: cert.issuer.clone(),
        serial: cert.serial.clone(),
        not_before: cert.not_before.clone(),
        not_after: cert.not_after.clone(),
        uri_sans: cert.uri_sans.clone(),
        dns_sans: cert.dns_sans.clone(),
        chain_len: cert.chain_len,
        leaf_sha256: cert.chain_sha256.first().cloned().unwrap_or_default(),
        trust: "verified",
        trust_generation,
    }
}

// ---------------------------------------------------------------- Rate limit

async fn rate_limit(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if let (Some(limiter), Some(identity)) = (&st.limiter, req.extensions().get::<ClientIdentity>())
        && let Err(wait) = limiter.check(&identity.id)
    {
        let resp = deny(&req, StatusCode::TOO_MANY_REQUESTS, "rate_limited", "per-identity rate limit exceeded");
        return with_retry_after(resp, wait.as_secs_f64().ceil() as u64);
    }
    next.run(req).await
}

// ---------------------------------------------------------------- Authorize

async fn authorize(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if st.upstream.is_loop(req.headers()) {
        return deny(&req, StatusCode::LOOP_DETECTED, "proxy_loop", "request already passed through this proxy");
    }
    if req.method() == Method::CONNECT {
        return deny(&req, StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "CONNECT is not supported");
    }
    if let Err(e) = check_request_path(req.uri().path()) {
        return deny(&req, StatusCode::BAD_REQUEST, "ambiguous_path", &e.to_string());
    }
    let Some(identity) = req.extensions().get::<ClientIdentity>() else {
        return deny(&req, StatusCode::UNAUTHORIZED, "no_identity", "no authenticated identity");
    };
    match st.policy.current().evaluate(&identity.id, req.method().as_str(), req.uri().path()) {
        policy::Decision::Allow { rule } => {
            record(&req, |c| {
                c.decision = Some(Decision::Allow);
                c.reason = format!("rule: {rule}");
            });
            next.run(req).await
        }
        policy::Decision::Deny(reason) => {
            deny(&req, StatusCode::FORBIDDEN, reason.as_str(), "identity is not authorized for this method and path")
        }
    }
}

// ---------------------------------------------------------------- Forward

async fn proxy_handler(State(st): State<AppState>, req: Request) -> Response {
    let request_id = rid(&req);
    let fail = |status: StatusCode, code: &'static str, msg: &str| {
        record(&req, |c| c.reason = format!("{} | {code}", c.reason));
        error_response(status, code, msg, &request_id)
    };
    if req.headers().contains_key(header::UPGRADE) {
        return fail(
            StatusCode::NOT_IMPLEMENTED,
            "upgrade_not_supported",
            "protocol upgrades (e.g. WebSocket) are not proxied",
        );
    }
    let Ok(_permit) = st.concurrency.clone().try_acquire_owned() else {
        return with_retry_after(
            fail(StatusCode::SERVICE_UNAVAILABLE, "proxy_overloaded", "too many concurrent requests"),
            1,
        );
    };
    let (Some(identity), Some(conn)) =
        (req.extensions().get::<ClientIdentity>().cloned(), req.extensions().get::<Arc<ConnInfo>>().cloned())
    else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", "missing request context");
    };
    let audit = ctx(&req);

    let fwd = ForwardContext { client_addr: conn.peer_addr, identity: &identity, request_id: &request_id };
    match st.upstream.forward(req.map(Body::new), &fwd).await {
        Ok((resp, upstream_latency)) => {
            if let Some(c) = audit {
                let mut c = c.lock().unwrap();
                c.upstream_status = Some(resp.status().as_u16());
                c.upstream_latency = Some(upstream_latency);
            }
            resp
        }
        Err(e) => {
            tracing::warn!(request_id, error = %e, "upstream request failed");
            if let Some(c) = audit {
                let mut c = c.lock().unwrap();
                c.reason = format!("{} | {}", c.reason, e.code());
            }
            let resp = error_response(e.status(), e.code(), &e.to_string(), &request_id);
            if e.status() == StatusCode::GATEWAY_TIMEOUT || e.status() == StatusCode::BAD_GATEWAY {
                with_retry_after(resp, 1)
            } else {
                resp
            }
        }
    }
}

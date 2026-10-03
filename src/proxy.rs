//! Forwarding to the upstream.
//!
//! - Method, path + query (byte-for-byte what was authorised), body and status are passed through.
//! - Request and response bodies are **streamed** (never buffered). The request body is capped at
//!   `max_body_bytes`: a larger `Content-Length` is refused up front with 413; a chunked body that
//!   crosses the limit is cut off (upstream sees an aborted request, client gets 413).
//!   Response bodies are not size-limited.
//! - Hop-by-hop headers (RFC 9110 §7.6.1) and any header named in `Connection` are dropped in both
//!   directions.
//! - Client-supplied `Forwarded`, `X-Forwarded-*`, `X-Real-IP` and identity headers are dropped and
//!   re-generated from what the proxy itself observed: clients connect directly, so nothing they
//!   send about "who/where they are" is trusted.
//! - `Via` carries this instance's token; a request that already contains it is a loop (508).
//! - Upstream is HTTP/1.1 over a pooled keep-alive connection; inbound may be HTTP/1.1 or HTTP/2.
//! - Retries: only when the TCP connection to the upstream could not be *established*, and only for
//!   idempotent methods without a body. A request that may have reached the upstream is never
//!   retried (see README §Retries).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::body::Body;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body::Body as _;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, LengthLimitError, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::identity::ClientIdentity;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

/// RFC 9110 §7.6.1 connection-specific headers, plus legacy ones. Never forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers the proxy owns. Client-supplied values are removed before ours are added.
const PROXY_OWNED: &[&str] = &[
    "host",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "x-real-ip",
    "x-forwarded-client-cert",
    "x-client-identity",
    "x-request-id",
];

pub const IDENTITY_HEADER: &str = "x-client-identity";
pub const XFCC_HEADER: &str = "x-forwarded-client-cert";

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("request body exceeds {0} bytes")]
    BodyTooLarge(u64),
    #[error("upstream did not respond within {0:?}")]
    Timeout(Duration),
    #[error("could not connect to upstream: {0}")]
    Connect(String),
    #[error("upstream request failed: {0}")]
    Upstream(String),
}

impl ProxyError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BodyTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Self::Connect(_) | Self::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::BodyTooLarge(_) => "body_too_large",
            Self::Timeout(_) => "upstream_timeout",
            Self::Connect(_) => "upstream_unreachable",
            Self::Upstream(_) => "upstream_error",
        }
    }
}

/// Per-request facts the proxy observed itself (as opposed to what the client claims).
pub struct ForwardContext<'a> {
    pub client_addr: SocketAddr,
    pub identity: &'a ClientIdentity,
    pub request_id: &'a str,
}

pub struct Upstream {
    client: Client<HttpConnector, ProxyBody>,
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
    timeout: Duration,
    max_body_bytes: u64,
    via_token: String,
}

impl Upstream {
    pub fn new(base: &str, timeout: Duration, max_body_bytes: u64, instance_id: &str) -> anyhow::Result<Self> {
        let uri: Uri = base.parse().map_err(|e| anyhow::anyhow!("UPSTREAM_URL '{base}': {e}"))?;
        let (Some(scheme), Some(authority)) = (uri.scheme().cloned(), uri.authority().cloned()) else {
            anyhow::bail!("UPSTREAM_URL must be absolute, e.g. http://backend:8080");
        };
        anyhow::ensure!(scheme == http::uri::Scheme::HTTP, "only http:// upstreams are supported");
        anyhow::ensure!(
            uri.path() == "/" && uri.query().is_none(),
            "UPSTREAM_URL must not contain a path or query (got '{base}')"
        );

        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(Duration::from_secs(3)));
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(512)
            .build(connector);
        Ok(Self {
            client,
            scheme,
            authority,
            timeout,
            max_body_bytes,
            via_token: format!("arkion-proxy-{instance_id}"),
        })
    }

    pub fn authority(&self) -> &http::uri::Authority {
        &self.authority
    }

    pub fn via_token(&self) -> &str {
        &self.via_token
    }

    /// True if this request already passed through this proxy instance.
    pub fn is_loop(&self, headers: &HeaderMap) -> bool {
        headers
            .get_all(header::VIA)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|hop| hop.split_whitespace().nth(1) == Some(self.via_token.as_str()))
    }

    /// Forwards the request. Returns the upstream response (body still streaming) and the time
    /// to response headers.
    pub async fn forward(
        &self,
        req: Request<Body>,
        ctx: &ForwardContext<'_>,
    ) -> Result<(Response<Body>, Duration), ProxyError> {
        let (parts, body) = req.into_parts();

        if let Some(len) = content_length(&parts.headers)
            && len > self.max_body_bytes
        {
            return Err(ProxyError::BodyTooLarge(self.max_body_bytes));
        }

        let path_and_query = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let uri = Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(path_and_query)
            .build()
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;
        let original_host = original_host(&parts.headers, &parts.uri);
        let headers =
            upstream_request_headers(&parts.headers, ctx, &self.authority, original_host.as_deref(), &self.via_token);

        let bodyless = body.size_hint().exact() == Some(0);
        let retryable = bodyless && is_idempotent(&parts.method);
        let build = |body: ProxyBody| {
            let mut r = Request::new(body);
            *r.method_mut() = parts.method.clone();
            *r.uri_mut() = uri.clone();
            *r.headers_mut() = headers.clone();
            r
        };

        let started = Instant::now();
        let response = if retryable {
            // Bodyless idempotent request: safe to rebuild and retry once if the connection could
            // not even be established (nothing was sent to the upstream).
            match self.send(build(empty_body())).await {
                Err(ProxyError::Connect(e)) => {
                    tracing::warn!(error = %e, "upstream connect failed, retrying once");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    self.send(build(empty_body())).await
                }
                other => other,
            }
        } else {
            let limited = Limited::new(body, self.max_body_bytes as usize).map_err(BoxError::from).boxed_unsync();
            self.send(build(limited)).await
        }?;
        let elapsed = started.elapsed();

        let (mut resp_parts, resp_body) = response.into_parts();
        resp_parts.headers = downstream_response_headers(&resp_parts.headers, &self.via_token);
        Ok((Response::from_parts(resp_parts, Body::new(resp_body)), elapsed))
    }

    async fn send(&self, req: Request<ProxyBody>) -> Result<Response<hyper::body::Incoming>, ProxyError> {
        match tokio::time::timeout(self.timeout, self.client.request(req)).await {
            Err(_) => Err(ProxyError::Timeout(self.timeout)),
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(self.classify(e)),
        }
    }

    fn classify(&self, e: hyper_util::client::legacy::Error) -> ProxyError {
        if is_body_limit(&e) {
            return ProxyError::BodyTooLarge(self.max_body_bytes);
        }
        if e.is_connect() {
            return ProxyError::Connect(error_chain(&e));
        }
        ProxyError::Upstream(error_chain(&e))
    }
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed_unsync()
}

fn is_idempotent(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE)
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

fn is_body_limit(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if err.is::<LengthLimitError>() {
            return true;
        }
        cur = err.source();
    }
    false
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut cur = e.source();
    while let Some(err) = cur {
        parts.push(err.to_string());
        cur = err.source();
    }
    parts.join(": ")
}

/// The host the client addressed: `Host` (HTTP/1.1) or the URI authority (`:authority`, HTTP/2).
pub fn original_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    let raw = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| uri.authority().map(|a| a.to_string()))?;
    // Only forward something that is a syntactically valid authority.
    raw.parse::<http::uri::Authority>().ok().map(|a| a.to_string())
}

/// Names listed in `Connection: a, b` — these are hop-by-hop for this message (RFC 9110 §7.6.1).
fn connection_listed(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect()
}

fn copy_end_to_end(src: &HeaderMap, extra_drop: &[&str]) -> HeaderMap {
    let listed = connection_listed(src);
    let mut out = HeaderMap::with_capacity(src.len() + 8);
    for (name, value) in src {
        let n = name.as_str();
        if HOP_BY_HOP.contains(&n) || extra_drop.contains(&n) || listed.contains(name) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn append_via(out: &mut HeaderMap, src: &HeaderMap, via_token: &str) {
    // Keep the existing chain (needed for loop detection further along) and add ourselves.
    let mut hops: Vec<String> =
        src.get_all(header::VIA).iter().filter_map(|v| v.to_str().ok()).map(str::to_string).collect();
    hops.push(format!("1.1 {via_token}"));
    out.remove(header::VIA);
    if let Ok(v) = HeaderValue::from_str(&hops.join(", ")) {
        out.insert(header::VIA, v);
    }
}

/// Builds the header map sent upstream. Pure function, unit-tested below.
pub fn upstream_request_headers(
    src: &HeaderMap,
    ctx: &ForwardContext<'_>,
    upstream_authority: &http::uri::Authority,
    original_host: Option<&str>,
    via_token: &str,
) -> HeaderMap {
    let mut out = copy_end_to_end(src, PROXY_OWNED);

    let ip = ctx.client_addr.ip();
    let set = |out: &mut HeaderMap, name: &'static str, value: &str| {
        if let Ok(v) = HeaderValue::from_str(value) {
            out.insert(name, v);
        }
    };
    set(&mut out, "host", upstream_authority.as_str());
    set(&mut out, "x-forwarded-for", &ip.to_string());
    set(&mut out, "x-forwarded-proto", "https");
    if let Some(h) = original_host {
        set(&mut out, "x-forwarded-host", h);
    }
    // RFC 7239: quote values containing ':' / '[' (IPv6, host:port).
    let for_value = match ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => format!("\"[{v6}]\""),
    };
    let mut forwarded = format!("for={for_value};proto=https");
    if let Some(h) = original_host {
        forwarded.push_str(&format!(";host=\"{h}\""));
    }
    set(&mut out, "forwarded", &forwarded);

    set(&mut out, IDENTITY_HEADER, &ctx.identity.id);
    // Envoy-style XFCC so upstreams can see certificate details without parsing certificates.
    let cert = &ctx.identity.cert;
    let mut xfcc = format!(
        "Hash={};Subject=\"{}\"",
        cert.chain_sha256.first().map(String::as_str).unwrap_or(""),
        cert.subject.replace('"', "'")
    );
    for u in &cert.uri_sans {
        xfcc.push_str(&format!(";URI={u}"));
    }
    for d in &cert.dns_sans {
        xfcc.push_str(&format!(";DNS={d}"));
    }
    set(&mut out, XFCC_HEADER, &xfcc);
    set(&mut out, "x-request-id", ctx.request_id);
    append_via(&mut out, src, via_token);
    out
}

/// Headers sent back to the client.
pub fn downstream_response_headers(src: &HeaderMap, via_token: &str) -> HeaderMap {
    let mut out = copy_end_to_end(src, &[]);
    append_via(&mut out, src, via_token);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CertDetails, IdentityKind};

    fn identity() -> ClientIdentity {
        ClientIdentity {
            id: "spiffe://acme/prod/payment".into(),
            kind: IdentityKind::Spiffe,
            cert: CertDetails {
                subject: "CN=pay".into(),
                issuer: "CN=root".into(),
                serial: "01".into(),
                not_before: String::new(),
                not_after: String::new(),
                not_after_unix: 0,
                not_before_unix: 0,
                uri_sans: vec!["spiffe://acme/prod/payment".into()],
                dns_sans: vec![],
                chain_len: 1,
                chain_sha256: vec!["abc".into()],
            },
        }
    }

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn strips_hop_by_hop_spoofed_and_connection_listed_headers() {
        let src = hm(&[
            ("connection", "keep-alive, x-secret-hop"),
            ("x-secret-hop", "1"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("upgrade", "websocket"),
            ("proxy-authorization", "Basic xyz"),
            ("x-forwarded-for", "6.6.6.6"),
            ("forwarded", "for=6.6.6.6"),
            ("x-client-identity", "spiffe://acme/prod/admin"),
            ("x-forwarded-client-cert", "URI=spiffe://acme/prod/admin"),
            ("x-request-id", "spoofed"),
            ("host", "proxy.example:8443"),
            ("authorization", "Bearer keep-me"),
            ("content-type", "application/json"),
        ]);
        let id = identity();
        let ctx = ForwardContext { client_addr: "10.1.2.3:5555".parse().unwrap(), identity: &id, request_id: "rid-1" };
        let auth: http::uri::Authority = "backend:8080".parse().unwrap();
        let out = upstream_request_headers(&src, &ctx, &auth, Some("proxy.example:8443"), "arkion-proxy-test");

        for gone in ["connection", "x-secret-hop", "keep-alive", "te", "upgrade", "proxy-authorization"] {
            assert!(out.get(gone).is_none(), "{gone} must not be forwarded");
        }
        assert_eq!(out["x-forwarded-for"], "10.1.2.3");
        assert_eq!(out["x-forwarded-proto"], "https");
        assert_eq!(out["x-forwarded-host"], "proxy.example:8443");
        assert_eq!(out["forwarded"], "for=10.1.2.3;proto=https;host=\"proxy.example:8443\"");
        assert_eq!(out["x-client-identity"], "spiffe://acme/prod/payment");
        assert!(out["x-forwarded-client-cert"].to_str().unwrap().starts_with("Hash=abc;"));
        assert_eq!(out["x-request-id"], "rid-1");
        assert_eq!(out["host"], "backend:8080");
        assert_eq!(out["via"], "1.1 arkion-proxy-test");
        // End-to-end headers (including the app's own Authorization) pass through untouched.
        assert_eq!(out["authorization"], "Bearer keep-me");
        assert_eq!(out["content-type"], "application/json");
        assert_eq!(out.get_all("x-forwarded-for").iter().count(), 1);
    }

    #[test]
    fn ipv6_forwarded_is_quoted() {
        let id = identity();
        let ctx = ForwardContext { client_addr: "[::1]:5555".parse().unwrap(), identity: &id, request_id: "r" };
        let out = upstream_request_headers(&HeaderMap::new(), &ctx, &"b:1".parse().unwrap(), None, "t");
        assert_eq!(out["forwarded"], "for=\"[::1]\";proto=https");
    }

    #[test]
    fn loop_detection_and_via_chain() {
        let up = Upstream::new("http://127.0.0.1:1", Duration::from_secs(1), 10, "abc").unwrap();
        assert!(up.is_loop(&hm(&[("via", "1.1 other, 1.1 arkion-proxy-abc")])));
        assert!(!up.is_loop(&hm(&[("via", "1.1 arkion-proxy-abcd")])));
        assert!(!up.is_loop(&HeaderMap::new()));
        let resp = downstream_response_headers(&hm(&[("via", "1.0 cdn"), ("transfer-encoding", "chunked")]), "me");
        assert_eq!(resp["via"], "1.0 cdn, 1.1 me");
        assert!(resp.get("transfer-encoding").is_none());
    }

    #[test]
    fn rejects_bad_upstream_urls() {
        for bad in ["backend:8080", "https://b:1", "http://b:1/api", "http://b:1/?x=1"] {
            assert!(Upstream::new(bad, Duration::from_secs(1), 1, "x").is_err(), "{bad}");
        }
    }
}

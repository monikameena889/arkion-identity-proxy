//! Structured audit events.
//!
//! One `http_request` event per request (allowed, denied or failed) and one `tls_handshake_rejected`
//! event per refused connection. Events contain identities, certificate metadata, method, path,
//! host, an allowlist of safe headers, the decision and timings. They never contain
//! `Authorization`, cookies, query strings, bodies or any header not on the allowlist.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;

use serde::Serialize;

/// Request headers that are safe and useful to record. Everything else is dropped.
pub const SAFE_HEADERS: &[&str] = &["user", "content-type", "content-length", "accept", "traceparent"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Decision {
    #[serde(rename = "ALLOW")]
    Allow,
    #[serde(rename = "DENY")]
    Deny,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub uri_sans: Vec<String>,
    pub dns_sans: Vec<String>,
    pub chain_len: usize,
    pub leaf_sha256: String,
    /// "verified" — the chain was validated by rustls/webpki against `trust_generation`.
    pub trust: &'static str,
    pub trust_generation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub event: &'static str,
    pub request_id: String,
    pub identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertSummary>,
    pub client_addr: String,
    pub tls_version: Option<String>,
    pub http_version: String,
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub decision: Decision,
    /// Why the request was denied/failed, or the matching rule when allowed.
    pub reason: String,
    /// Status returned to the client.
    pub status: u16,
    pub upstream_status: Option<u16>,
    /// Time from request received to response headers sent.
    pub latency_ms: u64,
    pub latency_us: u64,
    pub upstream_latency_us: Option<u64>,
    pub policy_generation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HandshakeRejected {
    pub timestamp: String,
    pub event: &'static str,
    pub client_addr: String,
    pub reason: String,
    pub trust_generation: u64,
}

pub trait AuditSink: Send + Sync + 'static {
    fn request(&self, event: &AuditEvent);
    fn handshake_rejected(&self, event: &HandshakeRejected);
    /// Blocks until everything emitted so far has been written. Called on shutdown.
    fn flush(&self) {}
}

/// Writes one JSON object per line to stdout (picked up by the container log pipeline).
///
/// Events are serialised on the request's own thread, then handed to a dedicated writer thread
/// over a bounded channel. The writer batches lines in a `BufWriter` and flushes whenever the
/// queue drains, so request threads never contend on the stdout lock or block in `write(2)`.
/// If the queue is full, `send` blocks (backpressure) rather than dropping audit events.
pub struct StdoutSink {
    tx: std::sync::mpsc::SyncSender<Msg>,
}

enum Msg {
    Line(Vec<u8>),
    Flush(std::sync::mpsc::Sender<()>),
}

impl StdoutSink {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Msg>(64 * 1024);
        std::thread::Builder::new()
            .name("audit-writer".into())
            .spawn(move || {
                let mut out = std::io::BufWriter::with_capacity(256 * 1024, std::io::stdout().lock());
                while let Ok(msg) = rx.recv() {
                    let mut next = Some(msg);
                    // Drain whatever is queued, then flush once.
                    while let Some(m) = next {
                        match m {
                            Msg::Line(l) => {
                                let _ = out.write_all(&l);
                            }
                            Msg::Flush(ack) => {
                                let _ = out.flush();
                                let _ = ack.send(());
                            }
                        }
                        next = rx.try_recv().ok();
                    }
                    let _ = out.flush();
                }
                let _ = out.flush();
            })
            .expect("spawn audit writer");
        Self { tx }
    }

    fn send<T: Serialize>(&self, value: &T) {
        if let Ok(mut line) = serde_json::to_vec(value) {
            line.push(b'\n');
            let _ = self.tx.send(Msg::Line(line));
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for StdoutSink {
    fn request(&self, event: &AuditEvent) {
        self.send(event)
    }

    fn handshake_rejected(&self, event: &HandshakeRejected) {
        self.send(event)
    }

    fn flush(&self) {
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        if self.tx.send(Msg::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(std::time::Duration::from_secs(5));
        }
    }
}

/// Keeps events in memory; used by tests.
#[derive(Default)]
pub struct MemorySink {
    pub requests: Mutex<Vec<AuditEvent>>,
    pub handshakes: Mutex<Vec<HandshakeRejected>>,
}

impl AuditSink for MemorySink {
    fn request(&self, event: &AuditEvent) {
        self.requests.lock().unwrap().push(event.clone());
    }

    fn handshake_rejected(&self, event: &HandshakeRejected) {
        self.handshakes.lock().unwrap().push(event.clone());
    }
}

pub fn safe_headers(headers: &http::HeaderMap) -> BTreeMap<String, String> {
    SAFE_HEADERS
        .iter()
        .filter_map(|name| {
            let v = headers.get(*name)?.to_str().ok()?;
            Some((name.to_string(), v.chars().take(256).collect()))
        })
        .collect()
}

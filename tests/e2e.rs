//! End-to-end tests: real TLS listener, real upstream, real certificates (generated per test).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arkion_identity_proxy::audit::{Decision, MemorySink};
use arkion_identity_proxy::config::Config;
use arkion_identity_proxy::server::{self, ProxyHandle};
use arkion_identity_proxy::{devpki, echo};
use clap::Parser;
use serde_json::Value;

const POLICY: &str = r#"
policies:
  - identity: "spiffe://acme/prod/payment"
    allow:
      - method: POST
        path: "/payments"
      - method: GET
        path: "/slow/*"
  - identity: "spiffe://acme/prod/reporting"
    allow:
      - method: GET
        path: "/reports/*"
  - identity: "dns:batch.acme.internal"
    allow:
      - method: GET
        path: "/batch"
"#;

struct Env {
    _dir: tempfile::TempDir,
    pki: PathBuf,
    policy_path: PathBuf,
    proxy: ProxyHandle,
    audit: Arc<MemorySink>,
}

impl Env {
    fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.proxy.addr.port())
    }

    fn client(&self, name: &str) -> reqwest::Client {
        client(&self.pki, Some(name), false)
    }

    fn h1_client(&self, name: &str) -> reqwest::Client {
        client(&self.pki, Some(name), true)
    }

    fn last_event(&self) -> arkion_identity_proxy::audit::AuditEvent {
        self.audit.requests.lock().unwrap().last().cloned().expect("an audit event")
    }

    async fn wait_handshake_events(&self, n: usize) -> Vec<String> {
        for _ in 0..100 {
            let reasons: Vec<String> = self.audit.handshakes.lock().unwrap().iter().map(|h| h.reason.clone()).collect();
            if reasons.len() >= n {
                return reasons;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("expected {n} handshake events");
    }
}

fn client(pki: &Path, name: Option<&str>, http1: bool) -> reqwest::Client {
    let ca = std::fs::read(pki.join("ca-v1.crt")).unwrap();
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .timeout(Duration::from_secs(10));
    if let Some(name) = name {
        let mut pem = std::fs::read(pki.join(format!("{name}.crt"))).unwrap();
        pem.extend(std::fs::read(pki.join(format!("{name}.key"))).unwrap());
        b = b.identity(reqwest::Identity::from_pem(&pem).unwrap());
    }
    if http1 {
        b = b.http1_only();
    }
    b.build().unwrap()
}

async fn setup(tweak: impl FnOnce(&mut Config)) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let pki = dir.path().join("pki");
    devpki::write_demo_pki(&pki).unwrap();
    let policy_path = dir.path().join("policy.yaml");
    std::fs::write(&policy_path, POLICY).unwrap();
    let upstream = echo::spawn("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let mut cfg = Config::try_parse_from(["proxy"]).unwrap();
    cfg.listen_addr = "127.0.0.1:0".parse().unwrap();
    cfg.admin_addr = "127.0.0.1:0".parse().unwrap();
    cfg.upstream_url = format!("http://{upstream}");
    cfg.tls_cert = pki.join("server.crt");
    cfg.tls_key = pki.join("server.key");
    cfg.client_ca_bundle = pki.join("trust-bundle.pem");
    cfg.policy_file = policy_path.clone();
    cfg.reload_interval_ms = 3_600_000; // tests trigger reloads explicitly
    cfg.instance_id = Some("test".into());
    tweak(&mut cfg);

    let audit = Arc::new(MemorySink::default());
    let proxy = server::start(&cfg, audit.clone()).await.unwrap();
    Env { _dir: dir, pki, policy_path, proxy, audit }
}

async fn json(resp: reqwest::Response) -> Value {
    resp.json().await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_request_is_forwarded_faithfully() {
    let env = setup(|_| {}).await;
    let body = vec![7u8; 4096];
    let resp = env
        .h1_client("payment")
        .post(env.url("/payments?amount=10&currency=EUR"))
        .header("authorization", "Bearer app-level-token")
        .header("cookie", "session=supersecret")
        .header("x-forwarded-for", "6.6.6.6")
        .header("x-client-identity", "spiffe://acme/prod/admin")
        .header("connection", "x-drop-me")
        .header("x-drop-me", "hop")
        .header("x-request-id", "client-req-42")
        .header("content-type", "application/octet-stream")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["x-request-id"], "client-req-42");
    assert_eq!(resp.headers()["x-upstream"], "echo");
    assert!(resp.headers().get("x-upstream-hop").is_none(), "upstream's Connection-listed header must be dropped");
    assert_eq!(resp.headers()["via"], "1.1 arkion-proxy-test");

    let echo = json(resp).await;
    assert_eq!(echo["method"], "POST");
    assert_eq!(echo["path"], "/payments");
    assert_eq!(echo["query"], "amount=10&currency=EUR");
    assert_eq!(echo["body_len"], 4096);
    let h = &echo["headers"];
    assert_eq!(h["x-client-identity"], serde_json::json!(["spiffe://acme/prod/payment"]));
    assert_eq!(h["x-forwarded-for"], serde_json::json!(["127.0.0.1"]));
    assert_eq!(h["x-forwarded-proto"], serde_json::json!(["https"]));
    assert_eq!(h["x-request-id"], serde_json::json!(["client-req-42"]));
    assert_eq!(h["authorization"], serde_json::json!(["Bearer app-level-token"]), "end-to-end headers pass through");
    assert!(h["x-forwarded-client-cert"][0].as_str().unwrap().contains("URI=spiffe://acme/prod/payment"));
    assert!(h.get("x-drop-me").is_none());
    assert!(h["forwarded"][0].as_str().unwrap().starts_with("for=127.0.0.1;proto=https"));

    let ev = env.last_event();
    assert_eq!(ev.identity.as_deref(), Some("spiffe://acme/prod/payment"));
    assert_eq!(ev.decision, Decision::Allow);
    assert_eq!(ev.upstream_status, Some(200));
    assert_eq!(ev.path, "/payments", "query string must not be audited");
    assert_eq!(ev.request_id, "client-req-42");
    let cert = ev.cert.as_ref().unwrap();
    assert_eq!(cert.trust, "verified");
    assert!(cert.subject.contains("payment"));
    let line = serde_json::to_string(&ev).unwrap();
    for secret in ["app-level-token", "supersecret", "authorization", "cookie", "amount=10"] {
        assert!(!line.contains(secret), "audit event leaked '{secret}': {line}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn http2_inbound_http1_upstream() {
    let env = setup(|_| {}).await;
    let resp = env.client("payment").post(env.url("/payments")).body("x").send().await.unwrap();
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(resp.status(), 200);
    let echo = json(resp).await;
    assert_eq!(echo["version"], "HTTP/1.1");
    assert_eq!(echo["headers"]["x-forwarded-host"][0], format!("localhost:{}", env.proxy.addr.port()));
}

#[tokio::test(flavor = "multi_thread")]
async fn authorization_decisions() {
    let env = setup(|_| {}).await;
    let pay = env.client("payment");
    let rep = env.client("reporting");

    let r = pay.get(env.url("/payments")).send().await.unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(json(r).await["error"]["code"], "no_matching_rule");

    let r = env.client("unknown").get(env.url("/payments")).send().await.unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(json(r).await["error"]["code"], "no_policy_for_identity");
    assert_eq!(env.last_event().decision, Decision::Deny);

    let r = rep.get(env.url("/reports/2024/q1")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(env.last_event().cert.unwrap().chain_len, 2, "reporting presents leaf + intermediate");

    for (path, status) in [
        ("/reports", 403),
        ("/reports/", 403),
        ("/reportsX/a", 403),
        ("/reports/..;/payments", 400),
        ("/reports/x%2f..%2fpayments", 400),
        ("/reports/%2e%2e;/payments", 400),
        ("/reports//x", 400),
    ] {
        let r = rep.get(env.url(path)).send().await.unwrap();
        assert_eq!(r.status(), status, "{path}");
    }

    let r = env.client("dns").get(env.url("/batch")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(env.last_event().identity.as_deref(), Some("dns:batch.acme.internal"));
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_layer_rejections() {
    let env = setup(|_| {}).await;
    let no_cert = client(&env.pki, None, false);
    for c in [&no_cert, &env.client("expired"), &env.client("not-yet-valid"), &env.client("untrusted")] {
        assert!(c.get(env.url("/payments")).send().await.is_err(), "handshake must fail");
    }
    let reasons = env.wait_handshake_events(4).await.join(" | ");
    for expected in ["no certificates", "certificate expired", "not valid yet", "UnknownIssuer"] {
        assert!(reasons.contains(expected), "missing '{expected}' in: {reasons}");
    }
    assert!(env.audit.requests.lock().unwrap().is_empty(), "no HTTP request may be processed");
}

#[tokio::test(flavor = "multi_thread")]
async fn application_layer_identity_rejections() {
    let env = setup(|c| c.trust_domains = vec!["acme".into()]).await;
    for (name, code) in [("malformed-spiffe", "malformed_identity"), ("multi-spiffe", "malformed_identity")] {
        let r = env.client(name).post(env.url("/payments")).send().await.unwrap();
        assert_eq!(r.status(), 401, "{name}");
        assert_eq!(json(r).await["error"]["code"], code, "{name}");
        let ev = env.last_event();
        assert!(ev.identity.is_none());
        assert!(!ev.cert.expect("presented cert is audited").uri_sans.is_empty(), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn require_spiffe_id_rejects_dns_identities() {
    let env = setup(|c| c.require_spiffe_id = true).await;
    let r = env.client("dns").get(env.url("/batch")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(json(r).await["error"]["code"], "no_identity");
}

#[tokio::test(flavor = "multi_thread")]
async fn trust_store_rotation_without_restart() {
    let env = setup(|_| {}).await;
    let bundle = env.pki.join("trust-bundle.pem");
    let v1 = env.h1_client("payment"); // keep-alive connection that will outlive the rotation
    let v2 = env.h1_client("payment-v2");

    assert_eq!(v1.post(env.url("/payments")).send().await.unwrap().status(), 200);
    assert!(v2.post(env.url("/payments")).send().await.is_err(), "v2 not trusted yet");
    assert_eq!(env.proxy.tls.generation(), 1);

    // v1 -> v2
    std::fs::copy(env.pki.join("trust-bundle-v2.pem"), &bundle).unwrap();
    env.proxy.trigger_reload().await;
    wait_for(|| env.proxy.tls.generation() == 2).await;

    // The existing v1 connection is re-validated on its next request and refused.
    let r = v1.post(env.url("/payments")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(json(r).await["error"]["code"], "certificate_no_longer_trusted");
    // New v1 connections fail at the TLS layer; v2 now works.
    assert!(env.h1_client("payment").post(env.url("/payments")).send().await.is_err());
    assert_eq!(v2.post(env.url("/payments")).send().await.unwrap().status(), 200);

    // A bad update is rejected; v2 keeps working (last-known-good).
    std::fs::write(&bundle, "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n").unwrap();
    env.proxy.trigger_reload().await;
    wait_for(|| env.proxy.tls.status().last_error.is_some()).await;
    assert_eq!(env.proxy.tls.generation(), 2);
    assert_eq!(v2.post(env.url("/payments")).send().await.unwrap().status(), 200);

    // A leaf certificate instead of a CA is also rejected.
    std::fs::copy(env.pki.join("payment.crt"), &bundle).unwrap();
    env.proxy.trigger_reload().await;
    wait_for(|| env.proxy.tls.status().last_error.as_deref().is_some_and(|e| e.contains("not a CA"))).await;
    assert_eq!(env.proxy.tls.generation(), 2);

    // Roll forward to an overlap bundle (v1 + v2): both work again.
    std::fs::copy(env.pki.join("trust-bundle-v1-v2.pem"), &bundle).unwrap();
    env.proxy.trigger_reload().await;
    wait_for(|| env.proxy.tls.generation() == 3).await;
    assert!(env.proxy.tls.status().last_error.is_none());
    assert_eq!(env.h1_client("payment").post(env.url("/payments")).send().await.unwrap().status(), 200);
    assert_eq!(v2.post(env.url("/payments")).send().await.unwrap().status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_hot_reload() {
    let env = setup(|_| {}).await;
    let pay = env.client("payment");
    assert_eq!(pay.get(env.url("/payments")).send().await.unwrap().status(), 403);
    std::fs::write(&env.policy_path, POLICY.replace("method: POST", "method: GET")).unwrap();
    env.proxy.trigger_reload().await;
    wait_for(|| env.proxy.policy.generation() == 2).await;
    assert_eq!(pay.get(env.url("/payments")).send().await.unwrap().status(), 200);
    assert_eq!(pay.post(env.url("/payments")).send().await.unwrap().status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn resilience_body_limit_timeout_loop() {
    let env = setup(|c| {
        c.max_body_bytes = 1024;
        c.upstream_timeout_ms = 300;
    })
    .await;
    let pay = env.h1_client("payment");

    let r = pay.post(env.url("/payments")).body(vec![0u8; 2048]).send().await.unwrap();
    assert_eq!(r.status(), 413);
    assert_eq!(pay.post(env.url("/payments")).body(vec![0u8; 1024]).send().await.unwrap().status(), 200);

    // Chunked body (no Content-Length) that crosses the limit mid-stream.
    let chunks = futures_stream(3, 600);
    let r = pay.post(env.url("/payments")).body(reqwest::Body::wrap_stream(chunks)).send().await.unwrap();
    assert_eq!(r.status(), 413);

    let r = pay.get(env.url("/slow/2000")).send().await.unwrap();
    assert_eq!(r.status(), 504);
    assert_eq!(json(r).await["error"]["code"], "upstream_timeout");

    let r = pay.post(env.url("/payments")).header("via", "1.1 arkion-proxy-test").send().await.unwrap();
    assert_eq!(r.status(), 508);
}

fn futures_stream(
    n: usize,
    size: usize,
) -> impl futures_util::Stream<Item = Result<Vec<u8>, std::io::Error>> + Send + Sync + 'static {
    futures_util::stream::iter((0..n).map(move |_| Ok::<_, std::io::Error>(vec![1u8; size])))
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_and_concurrency_limit() {
    let env = setup(|c| {
        c.rate_limit_rps = 1;
        c.rate_limit_burst = 2;
    })
    .await;
    let pay = env.client("payment");
    assert_eq!(pay.post(env.url("/payments")).send().await.unwrap().status(), 200);
    assert_eq!(pay.post(env.url("/payments")).send().await.unwrap().status(), 200);
    let r = pay.post(env.url("/payments")).send().await.unwrap();
    assert_eq!(r.status(), 429);
    assert!(r.headers().contains_key("retry-after"));
    // Limits are per identity: another identity is unaffected.
    assert_eq!(env.client("reporting").get(env.url("/reports/x")).send().await.unwrap().status(), 200);

    let env = setup(|c| c.max_concurrency = 1).await;
    let pay = env.client("payment");
    let (a, b) = tokio::join!(pay.get(env.url("/slow/400")).send(), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        pay.get(env.url("/slow/1")).send().await
    });
    assert_eq!(a.unwrap().status(), 200);
    assert_eq!(b.unwrap().status(), 503);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_down_and_self_loop_config() {
    let dead: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let env = setup(|c| c.upstream_url = format!("http://{dead}")).await;
    let r = env.client("payment").get(env.url("/slow/1")).send().await.unwrap();
    assert_eq!(r.status(), 502);
    assert_eq!(json(r).await["error"]["code"], "upstream_unreachable");

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    devpki::write_demo_pki(dir.path()).unwrap();
    std::fs::write(dir.path().join("policy.yaml"), POLICY).unwrap();
    let mut cfg = Config::try_parse_from(["proxy"]).unwrap();
    cfg.listen_addr = format!("127.0.0.1:{port}").parse().unwrap();
    cfg.admin_addr = "127.0.0.1:0".parse().unwrap();
    cfg.upstream_url = format!("http://127.0.0.1:{port}");
    cfg.tls_cert = dir.path().join("server.crt");
    cfg.tls_key = dir.path().join("server.key");
    cfg.client_ca_bundle = dir.path().join("trust-bundle.pem");
    cfg.policy_file = dir.path().join("policy.yaml");
    let err = server::start(&cfg, Arc::new(MemorySink::default())).await.err().expect("must refuse to start");
    assert!(err.to_string().contains("own listener"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn graceful_shutdown_drains_in_flight_requests() {
    let env = setup(|_| {}).await;
    let admin = format!("http://{}", env.proxy.admin_addr);
    let plain = reqwest::Client::new();
    assert_eq!(plain.get(format!("{admin}/readyz")).send().await.unwrap().status(), 200);
    let status: Value = plain.get(format!("{admin}/status")).send().await.unwrap().json().await.unwrap();
    assert_eq!(status["trust"]["status"]["generation"], 1);

    let pay = env.client("payment");
    let url = env.url("/slow/500");
    let in_flight = tokio::spawn(async move { pay.get(url).send().await.map(|r| r.status().as_u16()) });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let addr = env.proxy.addr;
    let Env { proxy, .. } = env;
    proxy.shutdown().await;
    assert_eq!(in_flight.await.unwrap().unwrap(), 200, "in-flight request completes during drain");
    assert!(tokio::net::TcpStream::connect(addr).await.is_err(), "listener closed after shutdown");
}

async fn wait_for(cond: impl Fn() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not met in time");
}

# Arkion Identity-Aware mTLS Reverse Proxy

A Rust (Tokio + hyper + rustls + axum middleware) reverse proxy that sits in front of an existing
API. It authenticates non-human identities with mutual TLS, authorizes each request against a
file-based policy, writes a structured audit event, and forwards allowed traffic upstream.

```
Client ──TLS/mTLS──► [ Intercept ─► Identify ─► Authorize ─► Observe ] ──HTTP/1.1──► Existing API
                     https://localhost:8443                                 UPSTREAM_URL (e.g. http://backend:8080)
```

**What's included**
- mTLS with a mandatory client certificate, validated by rustls/webpki. The identity comes from the SPIFFE URI SAN, with a DNS-SAN fallback.
- A YAML policy engine (default deny, exact and `/*` prefix rules) with request-path hardening against traversal and encoding bypasses.
- Hot reload of the **trust bundle** (and server certificate) and of the **policy**, without a restart. Bad updates are rejected and the previous version stays active (last-known-good). Existing keep-alive connections are re-validated after a rotation.
- Careful proxying: hop-by-hop headers are stripped, `Forwarded` / `X-Forwarded-*` are regenerated, `Via`-based loop detection, streamed bodies with a size cap, HTTP/1.1 and HTTP/2 inbound.
- Resilience: upstream timeout, request body limit, concurrency limit, per-identity rate limit, safe retry policy, graceful shutdown, and health/readiness endpoints (7 of the 8 listed).
- One JSON audit event per request, and one per rejected TLS handshake. Secrets are never logged.
- **29 automated tests:** 17 unit tests plus 12 end-to-end tests that use real TLS, real certificates and a real upstream.
- A container image that includes the proxy, a demo upstream, a PKI generator and a load generator.

---

## Contents
1. [Quick start (Docker)](#1-quick-start-docker)
2. [Local build, run, test](#2-local-build-run-test)
3. [Configuration](#3-configuration)
4. [Code layout and request flow](#4-code-layout-and-request-flow)
5. [TLS / mTLS and identity design](#5-tls--mtls-and-identity-design)
6. [Authorization design and path matching](#6-authorization-design-and-path-matching)
7. [Reverse-proxy behaviour](#7-reverse-proxy-behaviour)
8. [Dynamic trust store rotation](#8-dynamic-trust-store-rotation)
9. [Resilience](#9-resilience)
10. [Audit events](#10-audit-events)
11. [Performance results](#11-performance-results)
12. [Security considerations](#12-security-considerations)
13. [Architectural decisions, assumptions, known limitations](#13-architectural-decisions-assumptions-known-limitations)
14. [Production considerations](#14-production-considerations)

---

## 1. Quick start (Docker)

```bash
# Build the image (contains: arkion-identity-proxy, echo-upstream, pki-gen, loadgen)
docker build -t arkion-identity-proxy .

# Optional: run all unit + end-to-end tests inside the build toolchain
docker build --target test .

# 1) Trust/identity material for testing: a demo PKI written to ./pki
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/pki:/pki" arkion-identity-proxy pki-gen /pki

# 2) An upstream to protect (any HTTP/1.1 service works; this one echoes what it receives)
docker network create arkion-net
docker run -d --name arkion-backend --network arkion-net --network-alias backend \
  arkion-identity-proxy echo-upstream 0.0.0.0:8080

# 3) The proxy: configure the upstream with UPSTREAM_URL, mount PKI + policy
docker run -d --name arkion-proxy --network arkion-net -p 8443:8443 -p 127.0.0.1:9901:9901 \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/pki:/pki:ro" -v "$PWD/config:/config:ro" \
  -e UPSTREAM_URL=http://backend:8080 -e TRUST_DOMAINS=acme \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  arkion-identity-proxy
```

To point the proxy at your own service, set `UPSTREAM_URL=http://<host>:<port>`. Use
`docker compose up --build` as an alternative (see `docker-compose.yml`).

> `--user "$(id -u):$(id -g)"` lets the container read the 0600 private keys that `pki-gen` wrote as
> your user. With real secrets (Kubernetes / Docker secrets), run as the image's default uid 10001.

**Try it**

```bash
C="curl -s --cacert pki/ca-v1.crt"
PAY="--cert pki/payment.crt --key pki/payment.key"
REP="--cert pki/reporting.crt --key pki/reporting.key"

$C $PAY -X POST https://localhost:8443/payments -d '{"amount":5}'        # 200 (upstream echo JSON)
$C $PAY https://localhost:8443/payments                                  # 403 no_matching_rule
$C $REP https://localhost:8443/reports/2024/q1                           # 200 (chain: leaf + intermediate)
$C $REP --path-as-is https://localhost:8443/reports/../payments          # 400 ambiguous_path
$C https://localhost:8443/payments                                       # TLS handshake fails: no client cert
$C --cert pki/expired.crt --key pki/expired.key https://localhost:8443/  # TLS handshake fails: expired
$C --cert pki/untrusted.crt --key pki/untrusted.key https://localhost:8443/  # TLS fails: UnknownIssuer
$C --cert pki/malformed-spiffe.crt --key pki/malformed-spiffe.key https://localhost:8443/payments  # 401 malformed_identity

# Trust rotation without restart (v1 -> v2):
cp pki/trust-bundle-v2.pem pki/trust-bundle.pem && sleep 3
$C $PAY -X POST https://localhost:8443/payments                          # now fails (v1 no longer trusted)
$C --cert pki/payment-v2.crt --key pki/payment-v2.key -X POST https://localhost:8443/payments  # 200
curl -s localhost:9901/status                                            # trust generation, CAs, last_error

docker logs arkion-proxy        # audit events (JSON on stdout) + operational logs (stderr)
```

**Demo PKI** (`pki-gen`): `ca-v1` (initial trust bundle), an intermediate under v1, `ca-v2` (for rotation), an untrusted CA, a server cert for `localhost`/`proxy`/127.0.0.1, and client certs:

| File | Identity | Purpose |
|---|---|---|
| `payment` | `spiffe://acme/prod/payment` | allowed `POST /payments` |
| `reporting` | `spiffe://acme/prod/reporting` | allowed `GET /reports/*`; issued by the intermediate (chain of 2) |
| `unknown` | `spiffe://acme/prod/unknown` | valid certificate, not in the policy → 403 |
| `dns` | `dns:batch.acme.internal` | no SPIFFE ID, DNS-SAN fallback |
| `expired`, `not-yet-valid`, `untrusted` | – | rejected at the TLS layer |
| `malformed-spiffe`, `multi-spiffe` | – | rejected in middleware (401) |
| `payment-v2` | payment signed by `ca-v2` | rotation demo |

Bundles: `trust-bundle.pem` (active, initially v1), `trust-bundle-v2.pem`, and `trust-bundle-v1-v2.pem` (the overlap bundle used for zero-downtime CA migration).

---

## 2. Local build, run, test

```bash
cargo test                                   # 17 unit + 12 end-to-end tests (~1 s)
cargo build --release
./target/release/pki-gen pki                 # demo PKI
./target/release/echo-upstream 127.0.0.1:8080 &
UPSTREAM_URL=http://127.0.0.1:8080 ./target/release/arkion-identity-proxy   # uses ./pki and ./config by default
```

---

## 3. Configuration

All options are CLI flags with environment-variable fallbacks (`arkion-identity-proxy --help`).

| Env var | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8443` | mTLS listener |
| `UPSTREAM_URL` | `http://127.0.0.1:8080` | upstream; scheme + authority only |
| `TLS_CERT` / `TLS_KEY` | `pki/server.crt` / `pki/server.key` | server chain and PKCS#8 key (hot-reloaded) |
| `CLIENT_CA_BUNDLE` | `pki/trust-bundle.pem` | trusted client CAs (hot-reloaded) |
| `POLICY_FILE` | `config/policy.yaml` | authorization policy (hot-reloaded) |
| `RELOAD_INTERVAL_MS` | `2000` | file change check; `SIGHUP` forces an immediate check |
| `REQUIRE_SPIFFE_ID` | `false` | if true, certificates without a SPIFFE ID are rejected (no DNS fallback) |
| `TRUST_DOMAINS` | *(any)* | comma-separated allowed SPIFFE trust domains |
| `UPSTREAM_TIMEOUT_MS` | `10000` | time allowed for upstream response headers → 504 |
| `MAX_BODY_BYTES` | `10485760` | request body cap → 413 |
| `MAX_CONCURRENCY` | `1024` | concurrent proxied requests → 503 |
| `RATE_LIMIT_RPS` / `RATE_LIMIT_BURST` | `0` (off) / `100` | per-identity token bucket → 429 |
| `HANDSHAKE_TIMEOUT_MS` | `5000` | slow-handshake (slowloris) protection |
| `SHUTDOWN_GRACE_SECS` | `20` | drain time on SIGTERM |
| `ADMIN_ADDR` | `127.0.0.1:9901` | plain-HTTP `/healthz`, `/readyz`, `/status` |
| `INSTANCE_ID` | random | used in the `Via` token for loop detection |
| `LOG_FORMAT` | `text` (image: `json`) | operational log format (stderr) |

Policy example (`config/policy.yaml`):

```yaml
policies:
  - identity: "spiffe://acme/prod/payment"
    allow:
      - method: POST
        path: "/payments"
  - identity: "spiffe://acme/prod/reporting"
    allow:
      - method: GET
        path: "/reports/*"
```

---

## 4. Code layout and request flow

```
src/
  server.rs      accept loop: TCP → TLS handshake (current trust snapshot) → per-connection state →
                 hyper auto (h1/h2) → axum router; admin server; reload loop; graceful shutdown
  tls.rs         TLS-layer validation: rustls ServerConfig + WebPkiClientVerifier, CA bundle checks,
                 ArcSwap'd TrustSnapshot, last-known-good reload
  identity.rs    application-layer identity: x509 parsing, strict SPIFFE ID parser, DNS fallback
  middleware.rs  request_id → observe(audit) → identify → rate_limit → authorize → proxy_handler
  policy.rs      YAML policy compile/validate/evaluate, request-path safety, hot-reload store
  proxy.rs       upstream client, header hygiene, Forwarded/X-Forwarded-*, Via loop detection,
                 body limit, timeout, safe retry
  audit.rs       audit event types, async stdout sink, in-memory sink for tests
  config.rs      CLI/env configuration
  devpki.rs      demo/test PKI generator (rcgen)
  echo.rs        demo upstream
  bin/           pki-gen, echo-upstream, loadgen
tests/e2e.rs     12 end-to-end scenarios
```

**One request, step by step**

1. **TCP accept.** The accept loop loads the *current* trust snapshot (one atomic pointer load) and runs the TLS handshake with it, bounded by `HANDSHAKE_TIMEOUT_MS`. Any certificate problem aborts the handshake and emits a `tls_handshake_rejected` audit event.
2. **Per-connection state.** The verified peer chain, the TLS version, and the trust generation it was verified against are attached to every request on that connection.
3. **`request_id` (intercept).** Propagates a well-formed `X-Request-Id`, otherwise generates a UUIDv4. It is returned to the client and forwarded upstream.
4. **`observe` (observe).** Starts the timer and wraps everything below, so every outcome produces exactly one audit event.
5. **`identify` (identify).** Re-verifies the chain if the trust store rotated since the handshake, checks the validity window (connections can outlive certificates), and extracts the identity. The identity is parsed once per connection.
6. **`rate_limit`.** Per-identity token bucket.
7. **`authorize` (authorize).** Loop check (`Via`), method check, path-safety check, then policy evaluation. Default deny.
8. **`proxy_handler`.** Concurrency permit, then forwarding: header rewrite, body cap, timeout, safe retry. The response is streamed back.

---

## 5. TLS / mTLS and identity design

### What is validated where

| Check | Layer | Result on failure |
|---|---|---|
| Client certificate present | **TLS** (`WebPkiClientVerifier`, client auth mandatory) | handshake aborted |
| Chain builds to a CA in the current bundle (client may send intermediates) | **TLS** (webpki) | handshake aborted (`UnknownIssuer`) |
| Signatures, basic constraints, path length | **TLS** (webpki) | handshake aborted |
| NotBefore / NotAfter of every certificate in the chain | **TLS** (webpki) | handshake aborted (`expired` / `not valid yet`) |
| Leaf EKU permits `clientAuth` | **TLS** (webpki) | handshake aborted |
| Proof of private-key possession (CertificateVerify) | **TLS** (rustls) | handshake aborted |
| CA bundle is well-formed: only CAs, unexpired, non-empty | **reload** (`tls::parse_ca_bundle`) | update rejected, old bundle kept |
| Chain still trusted after a trust rotation (existing connections) | **middleware** (re-runs the verifier) | 401 `certificate_no_longer_trusted` + `Connection: close` |
| Leaf still within its validity window on *this* request | **middleware** | 401 `certificate_expired` + `Connection: close` |
| Exactly one SPIFFE ID, strictly well-formed | **middleware** (`identity.rs`) | 401 `malformed_identity` |
| SPIFFE trust domain allowed (`TRUST_DOMAINS`) | **middleware** | 401 `trust_domain_not_allowed` |
| A usable identity exists (SPIFFE, or DNS SAN if allowed) | **middleware** | 401 `no_identity` |
| Identity allowed to call method + path | **middleware** (policy) | 403 |

**Why this split.** The TLS layer answers "is this a genuine certificate from a CA we trust?",
using a hardened, well-tested library, before any HTTP parsing happens. It can't answer "who is
this, in our naming scheme?" or "is the name well-formed?". webpki ignores URI SANs, so SPIFFE
semantics have to live in the application. Re-checks that depend on time or configuration changes
(rotation, expiry during a long-lived connection) also have to happen per request, because the
handshake happened only once.

### Extracted certificate information
Parsed with `x509-parser` into the audit event (`cert` object) and partly forwarded upstream:
subject, issuer, serial, NotBefore/NotAfter, URI SANs, DNS SANs, chain length, SHA-256 of every
certificate in the presented chain, and the trust result (`verified` + trust-store generation).

### Identity rules
1. **Exactly one** URI SAN that looks like a SPIFFE ID (scheme compared case-insensitively, so `SPIFFE://` is caught as malformed rather than ignored). It must pass a strict parser: lowercase `spiffe://`, a trust domain of `[a-z0-9._-]`, path segments of `[A-Za-z0-9._-]`, no empty / `.` / `..` segments, no port, userinfo, query, fragment or percent-encoding, and at most 2048 bytes. Two SPIFFE IDs → rejected. We never "pick the first".
2. No SPIFFE ID and `REQUIRE_SPIFFE_ID=false` → the first DNS SAN, as `dns:<name>` (must be lowercase LDH).
3. Otherwise → 401. The subject CN is never used as an identity: it is unstructured and not covered by name constraints.

Upstream receives `X-Client-Identity: <id>` and an Envoy-style
`X-Forwarded-Client-Cert: Hash=…;Subject="…";URI=…`. Both are stripped from incoming requests first,
so a client can't spoof them.

---

## 6. Authorization design and path matching

- **Default deny.** Only `allow` rules exist. There are no deny rules, rule ordering or priorities, so there are no conflicts to resolve.
- **Identity:** exact, case-sensitive match. Each identity may appear only once (duplicates are a load error).
- **Method:** exact match against `GET HEAD POST PUT PATCH DELETE OPTIONS` (uppercase). `GET` does **not** imply `HEAD`. `CONNECT` is rejected (405); protocol upgrades are rejected (501).
- **Path patterns:**
  - `"/payments"` is **exact**: it matches only `/payments`. Not `/payments/`, `/payments/1`, `/Payments` or `/paymentsX`.
  - `"/reports/*"` is a **segment prefix**: it matches `/reports/a` and `/reports/a/b`, but never `/reports`, `/reports/` or `/reportsX`. Internally it's stored as `starts_with("/reports/") && len > 9`, so the boundary is always a `/`.
  - `*` is only allowed as the **entire last segment**. Patterns with `%`, `?`, `#`, `\`, `;`, spaces, empty segments or dot segments are load-time errors. A bad policy file never becomes active.
- **Query strings** are not part of matching (and are never logged).

### Preventing ambiguous matches and bypasses
The core rule: **authorize exactly the bytes that will be forwarded, and refuse anything the upstream
might interpret differently.** Before evaluation, `check_request_path` rejects (400 `ambiguous_path`):

| Rejected | Why |
|---|---|
| `.` / `..` segments, including `..;` | traversal: `/reports/../admin` → `/admin` upstream |
| `%2e`, `%2f`, `%5c`, `%00` (any case) | encoded traversal or separators that the upstream decodes after we authorize |
| `//` (empty segments) | many servers collapse them, so `/reports//x` ≠ what the policy saw |
| `\`, `#`, control characters, spaces | backslash-as-separator servers, fragment confusion |
| non-origin-form targets | the client never chooses the upstream authority |

We **reject rather than normalise**. Normalising would mean forwarding something other than what
the client sent, and you'd have to normalise exactly the way the upstream does, which you can't
guarantee. Because there are only allow rules, any remaining encoding difference (e.g. `/pay%6dents`)
can only cause a false *deny*, never a false allow. Absolute-form requests (`GET http://evil/…`)
are safe too, because only the path and query are taken from the request; the upstream authority
always comes from configuration.

---

## 7. Reverse-proxy behaviour

| Aspect | Behaviour |
|---|---|
| Method, path, query | forwarded unchanged (byte-for-byte what was authorized) |
| Request body | **streamed** to the upstream (not buffered). `Content-Length` > `MAX_BODY_BYTES` → 413 before contacting the upstream. A chunked body that crosses the limit is cut off mid-stream: the upstream sees an aborted request and the client gets 413 |
| Response body / status | **streamed** back unchanged; not size-limited (the upstream is trusted) |
| End-to-end headers | forwarded, including the application's own `Authorization` (it's the app's credential, not ours) |
| Hop-by-hop headers | `Connection`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, **and any header listed in `Connection`** are dropped in both directions |
| `Host` | set to the upstream authority; the original goes in `X-Forwarded-Host` |
| `Forwarded` / `X-Forwarded-*` / `X-Real-IP` | client-supplied values are **dropped** (clients connect directly, so we don't trust what they claim) and regenerated: `X-Forwarded-For: <peer ip>`, `X-Forwarded-Proto: https`, `X-Forwarded-Host`, and RFC 7239 `Forwarded: for=…;proto=https;host="…"` (IPv6 quoted). Behind a trusted L7 load balancer you would append instead (see §14) |
| Identity headers | `X-Client-Identity`, `X-Forwarded-Client-Cert`: stripped from input, set by the proxy |
| Request id | `X-Request-Id` propagated or generated; returned to the client too |
| Loop prevention | every hop appends `Via: 1.1 arkion-proxy-<instance-id>`. A request whose `Via` already contains our token → **508 Loop Detected**. At startup, the proxy also refuses an `UPSTREAM_URL` that points at its own listener |
| HTTP versions | **inbound:** HTTP/1.1 and HTTP/2 (ALPN `h2`, `http/1.1`). **Upstream:** HTTP/1.1 with a keep-alive pool. HTTP/2 → HTTP/1.1 translation works because the target is rebuilt from path + query, `:authority` becomes `X-Forwarded-Host`, and connection-specific headers (illegal in h2) are removed. Upstream h2 (h2c / TLS) and WebSockets are not supported |

### Retries
Only one kind of retry exists: if the **TCP connection to the upstream could not be established**
(nothing was sent), and the request is **idempotent and bodyless**, it is retried once after 50 ms.
Everything else is never retried:
- For **non-idempotent** requests (`POST`, `PATCH`), a timeout or reset after sending does *not* mean the upstream didn't act on it. Retrying `POST /payments` could pay twice. Only the client, with an idempotency key, can make that safe.
- Streamed bodies can't be replayed without buffering them, which would defeat streaming and the memory bounds.
- Proxy retries multiply load exactly when the upstream is struggling (retry storms). Clients already get `Retry-After` on 502/503/504.

---

## 8. Dynamic trust store rotation

```
Trust Store v1 ──► Running Proxy ──► file changes / SIGHUP ──► validate ──► atomic swap ──► Trust Store v2
                                                         └─ invalid ─► keep v1, report error
```

**Mechanism.** A reload loop checks every `RELOAD_INTERVAL_MS` (and on `SIGHUP`). It reads the
CA bundle, server cert and key, and hashes them. If nothing changed, that's the end of it. If they
changed, it builds a complete new `TrustSnapshot` (a rustls `ServerConfig` plus the client verifier)
off to the side. Only if every step succeeds is the snapshot published with a single
`ArcSwap::store`. Content hashing (rather than mtime) also works with Kubernetes ConfigMap/Secret
symlink swaps and with editors that write in place.

**Concurrency safety.** The hot path takes no lock: each new connection does one atomic pointer
load and uses that immutable snapshot for its whole handshake. A reload can't produce a torn or
half-applied state, and in-flight handshakes finish with the snapshot they started with. The old
snapshot is freed when its last user drops it.

**Existing TLS connections.** TLS authenticates once, at handshake, and HTTP keep-alive or HTTP/2
connections can live for hours. Each connection therefore records which trust generation it was
verified against. On the first request after a rotation, `identify` **re-runs the new verifier
on the connection's stored chain**. If the chain is no longer trusted, the request gets
`401 certificate_no_longer_trusted` with `Connection: close`. Removing a CA therefore takes effect
on the next request, not on the next reconnect. Connections whose chain is still trusted keep
going with no disruption. (Tested in `trust_store_rotation_without_restart`.)

**Validating a bad update.** Rejected, with the previous snapshot kept active: unreadable files,
invalid PEM, an empty bundle, a non-CA certificate, an expired CA, anything webpki refuses, and a
server key that doesn't match its certificate. The error is logged once (`reload REJECTED;
keeping last-known-good`) and shown in `GET /status` (`trust.status.last_error`), so it can be alerted on.

**Rollback.** Write the previous bundle back. Its hash matches what's running, so the error clears
with no swap. Writing a *different* good bundle rolls forward as a new generation. Recommended
CA migration with zero downtime: v1 → **v1+v2 overlap bundle** → reissue client certificates → v2.

**Distributing trust changes across a fleet.**
- Treat the bundle as versioned config: a Git-reviewed change → CI validates it (the same `parse_ca_bundle` checks) → published to a Kubernetes Secret/ConfigMap, Vault, or an object store. Each instance's reload loop picks it up within seconds, with no restarts.
- Roll out progressively (one canary instance or AZ, then all). Watch `/status` for `generation` and the bundle `sha256`, plus handshake-rejection rates, before widening the rollout.
- Always go through an overlap bundle, so instances temporarily on different versions agree on every certificate in use.
- At larger scale, push trust over a control plane, e.g. the SPIFFE Workload API or SDS (Envoy's secret discovery service) via SPIRE. The same `ArcSwap` swap point accepts bundles from a push API instead of a file.

---

## 9. Resilience

| Capability | Implemented | Behaviour |
|---|---|---|
| Upstream timeout | ✅ | no response headers within `UPSTREAM_TIMEOUT_MS` → 504 + `Retry-After` |
| Request body limit | ✅ | 413 (up front, or mid-stream for chunked bodies) |
| Concurrency limit | ✅ | `MAX_CONCURRENCY` in-flight requests, then 503 `proxy_overloaded` + `Retry-After` (fail fast, no queue) |
| Rate limiting | ✅ | per-identity token bucket (GCRA via `governor`), 429 + `Retry-After` |
| Safe retry policy | ✅ | connect failures only, idempotent and bodyless only (see §7) |
| Graceful shutdown | ✅ | SIGTERM: `/readyz` → 503, stop accepting, drain in-flight requests (bounded by `SHUTDOWN_GRACE_SECS`), flush the audit log, exit 0 |
| Health / readiness | ✅ | admin listener: `/healthz`, `/readyz`, `/status` |
| Circuit breaker | ❌ | not implemented; the timeout plus fail-fast concurrency limit bound the damage. Listed in §13 |
| Handshake timeout | ✅ (extra) | slow or idle TLS handshakes are cut off after `HANDSHAKE_TIMEOUT_MS` |

---

## 10. Audit events

Audit events go to **stdout** as JSON lines; operational logs go to **stderr**. Example (`POST /payments` allowed):

```json
{
  "timestamp": "2026-10-02T09:16:28.205897Z",
  "event": "http_request",
  "request_id": "17a8896d-b4d2-4ab5-89f3-f1e9de32fffa",
  "identity": "spiffe://acme/prod/payment",
  "cert": {
    "subject": "O=Arkion Test, CN=payment",
    "issuer": "O=Arkion Test, CN=Arkion Test Root v1",
    "serial": "4c:87:e3:75:1f:76:db:0a:06:7b:04:3f:8e:9d:7d:d8:87:58:91:45",
    "not_before": "2026-10-02T08:15:51Z", "not_after": "2027-10-02T09:15:51Z",
    "uri_sans": ["spiffe://acme/prod/payment"], "dns_sans": [],
    "chain_len": 1, "leaf_sha256": "e82a40ef…", "trust": "verified", "trust_generation": 1
  },
  "client_addr": "127.0.0.1:56723", "tls_version": "TLSv1_3", "http_version": "HTTP/2.0",
  "method": "POST", "path": "/payments", "host": "localhost:8443",
  "headers": { "accept": "*/*", "content-length": "12", "content-type": "application/x-www-form-urlencoded", "user": "curl/8.7.1" },
  "decision": "ALLOW", "reason": "rule: POST /payments",
  "status": 200, "upstream_status": 200,
  "latency_ms": 1, "latency_us": 1007, "upstream_latency_us": 872,
  "policy_generation": 1
}
```

- **Every request gets an event**, including denials by any layer (`decision: "DENY"` with `reason`: `no_matching_rule`, `ambiguous_path`, `rate_limited`, `malformed_identity`, …) and upstream failures (`ALLOW` with `status` 502/504 and a reason suffix such as `upstream_timeout`). On identity failures, the presented certificate is still recorded.
- **Rejected handshakes** produce `{"event":"tls_handshake_rejected","client_addr":…,"reason":"invalid peer certificate: UnknownIssuer",…}`.
- **Never logged:** `Authorization`, `Cookie`, `Proxy-Authorization`, any header not on the allowlist (`user`, `content-type`, `content-length`, `accept`, `traceparent`), query strings, bodies. The end-to-end test asserts that a bearer token, a cookie value and the query don't appear in the serialised event.
- `latency_ms` is the time until response headers are sent. Body streaming continues after that.
- **Writer:** events are serialised on the request thread and handed over a bounded channel to a dedicated writer thread. It batches writes and flushes when the queue drains. When the queue is full it applies backpressure (it never drops events). It is flushed on shutdown. See §11 for why.

---

## 11. Performance results

**Setup.** Apple M3 Pro (11 cores). The load generator, proxy and upstream all run on the same
machine, release builds. `loadgen` is closed-loop, keep-alive HTTP/1.1, `POST /payments` with
a 256-byte body. It runs 2 s of warm-up and 10 s of measurement per level. The same client
measures the upstream **directly** (plain HTTP) and **through the proxy** (mTLS, TLS 1.3, full
pipeline including audit logging). The upstream is `echo-upstream`, which does very little work.
That's deliberate, because it isolates the proxy's cost.

| target | concurrency | req/s | p50 (ms) | p95 (ms) | p99 (ms) | error rate |
|---|---:|---:|---:|---:|---:|---:|
| direct | 1 | 27,416 | 0.04 | 0.04 | 0.05 | 0.00% |
| direct | 10 | 109,634 | 0.09 | 0.14 | 0.18 | 0.00% |
| direct | 100 | 152,298 | 0.64 | 1.15 | 1.44 | 0.00% |
| direct | 500 | 152,982 | 2.78 | 7.56 | 10.41 | 0.00% |
| **proxy** | 1 | 11,184 | 0.09 | 0.10 | 0.11 | 0.00% |
| **proxy** | 10 | 45,904 | 0.21 | 0.31 | 0.37 | 0.00% |
| **proxy** | 100 | 57,727 | 1.64 | 2.75 | 3.83 | 0.00% |
| **proxy** | 500 | 63,419 | 7.38 | 14.29 | 18.32 | 0.00% |
| proxy, HTTP/2 inbound | 10 | 32,907 | 0.30 | 0.43 | 0.49 | 0.00% |
| proxy, HTTP/2 inbound | 100 | 39,473 | 2.52 | 3.39 | 3.87 | 0.00% |

**Incremental latency added by the proxy**

| concurrency | p50 | p95 | p99 |
|---:|---:|---:|---:|
| 1 | **+0.05 ms** | +0.06 ms | +0.06 ms |
| 10 | +0.12 ms | +0.17 ms | +0.19 ms |
| 100 | +1.00 ms | +1.60 ms | +2.39 ms |
| 500 | +4.60 ms | +6.73 ms | +7.91 ms |

Without contention, the full mTLS, identity, policy, audit and forwarding pipeline adds about
**50 µs**. Under load, the added latency is queueing: during the saturated runs the machine was
about 99% busy (proxy ≈ 6.2 cores, upstream ≈ 1.7, load generator ≈ 1.8, of 11). So the absolute
req/s figures are a lower bound for the proxy on its own hardware.

**Primary sources of proxy overhead**
1. **TLS record protection.** Every request and response is decrypted/encrypted with AES-GCM. This is the largest fixed cost per byte. Handshakes (ECDHE + certificate-chain verification, far more expensive than a request) happen once per connection and are amortised by keep-alive; clients that reconnect per request would pay far more.
2. **A second HTTP hop.** The proxy parses the request, builds an upstream request, checks out a pooled upstream connection, then parses and re-encodes the response. That roughly doubles the socket syscalls per request (read/write on two connections instead of one) and adds wake-ups between tasks.
3. **Allocation and copying.** The header map is rebuilt (hop-by-hop filtering and the added `Forwarded`/`XFCC`/`Via` headers), body frames are passed through, and the audit event is built and serialised to JSON.
4. **Per-request middleware.** Small: identity is parsed **once per connection** and cached, policy lookup is a hash-map hit plus a short rule scan, and rate-limit and concurrency checks are atomic operations.
5. **HTTP/2 inbound is slower in this test** because the client multiplexes all 100 streams over **one** connection: one TLS stream and one connection task, against 100 independent HTTP/1.1 connections spread over all cores. Real fleets with many clients don't have this single-connection bottleneck.

**Two bottlenecks found by profiling and fixed** (macOS `sample` under load):
- The first version wrote each audit event with a synchronous, globally locked `stdout` write from the request thread. About 95% of mutex-wait samples were `Stdout::lock`. Moving the writes to a dedicated batched writer thread raised throughput at 100 callers from 46.0k to 54.2k req/s and cut p99 from 4.68 to 3.24 ms.
- axum clones the middleware state for every layer on every request. With 8 `Arc` fields, that was roughly 64 contended atomic refcount operations per request, and `drop_glue<AppState>` was the top busy frame. Wrapping the state in a single `Arc` took 100 callers from 54.2k to 57.7k req/s.
- Together, the two fixes took 500 callers from 47.4k to 63.4k req/s (+34%).

Reproduce:
```bash
./target/release/echo-upstream 127.0.0.1:8080 &
UPSTREAM_URL=http://127.0.0.1:8080 ./target/release/arkion-identity-proxy > audit.log &
ulimit -n 10240
./target/release/loadgen --label direct --url http://127.0.0.1:8080/payments
./target/release/loadgen --label proxy  --url https://localhost:8443/payments \
  --ca pki/ca-v1.crt --cert pki/payment.crt --key pki/payment.key
```

---

## 12. Security considerations

- **Fail closed everywhere:** mandatory client certificates, default-deny policy, ambiguous paths rejected, invalid trust or policy updates rejected, and a startup failure if the initial files are bad.
- **No spoofable identity:** identity comes only from the verified certificate. All identity, forwarding and request-id headers from clients are stripped or validated.
- **Exactly one, strictly parsed SPIFFE ID.** CN is never used. There is an optional trust-domain allowlist, which matters when one CA bundle serves several trust domains.
- **Trust revocation takes effect for live connections** (re-validation after rotation), and expiry is enforced per request.
- **No secrets in logs** (see §10). The query string is excluded because tokens often appear there.
- **DoS bounds:** handshake timeout, body cap, concurrency cap, per-identity rate limit, upstream timeout, bounded audit queue.
- **TLS:** TLS 1.3 and 1.2 only, with rustls defaults (no legacy ciphers or renegotiation). ALPN is limited to h2/http1.1.
- **Container:** non-root (uid 10001), read-only root filesystem, all capabilities dropped, `no-new-privileges`, keys mounted read-only, and an admin port published only on 127.0.0.1.
- **Not covered:** certificate revocation (CRL/OCSP), see §13. The admin endpoint is unauthenticated plain HTTP and must stay on a private interface. The demo PKI's keys are for testing only.

---

## 13. Architectural decisions, assumptions, known limitations

**Decisions**
- **rustls + webpki** for all chain validation. Cryptographic path validation is never hand-written; the application layer adds only naming policy and time- or rotation-dependent re-checks.
- **hyper-util's `auto` server** with a custom accept loop (instead of `axum::serve`) to get per-connection access to the TLS session, so the verified chain becomes a request extension. **axum middleware** (`from_fn`) for a readable, testable Intercept → Identify → Authorize → Observe pipeline.
- **`ArcSwap` snapshots** for trust and policy: lock-free reads, atomic swaps, no torn state.
- **Reject, don't normalise** ambiguous paths, and match the raw forwarded path.
- **Minimal policy language** (allow-only, exact or segment-prefix): easy to reason about and to audit.
- **Upstream over HTTP/1.1 keep-alive** (the existing API is assumed to be HTTP/1.1, which is the common case).

**Assumptions**
- Clients connect directly to the proxy over TCP (no L4 load balancer rewriting source IPs, and no L7 proxy in front). If there is one, see §14.
- The upstream is trusted and reachable only via the proxy (network policy), so it can rely on `X-Client-Identity`.
- The SPIFFE ID or DNS SAN is the identity. One identity per certificate.

**Known limitations**
- No CRL/OCSP revocation checking (rustls supports CRLs via `with_crls`, which would slot into `build_snapshot`). Short-lived certificates (the SPIFFE norm) reduce the need.
- No circuit breaker, no upstream TLS, no upstream HTTP/2, no WebSocket/upgrade proxying (rejected with 501).
- The concurrency permit is held until response *headers*, not until the end of the response body. Slow body downloads aren't counted.
- The upstream timeout covers time to headers. There is no idle timeout on streaming bodies.
- Rate-limit state is per instance (a fleet-wide limit needs a shared store).
- No metrics endpoint yet (`/status` exposes state; Prometheus would be the next step).
- `/status` and the audit pipeline go to stdout and a local port. Shipping them off the host (with durability guarantees) is the job of the deployment platform.

---

## 14. Production considerations

- **Behind a load balancer:** use L4 pass-through (TCP/TLS) so mTLS terminates here, with PROXY protocol to keep client IPs. If an L7 hop is unavoidable, it must forward the client certificate (XFCC) and the proxy must be configured to trust only that hop's forwarding headers. That is a different trust model and needs explicit configuration.
- **Certificates:** short-lived SVIDs issued by SPIRE or a private CA, delivered via the SPIFFE Workload API or SDS instead of files. Rotate the server certificate the same way (it's already hot-reloaded).
- **Trust distribution:** a versioned, CI-validated bundle with canary rollout and overlap bundles (§8). Alert on `trust.status.last_error`, handshake-rejection spikes, and the bundle `sha256` drifting across the fleet.
- **Policy as code:** policy changes go through review and CI (`Policy::from_yaml` as a linter), and are rolled out like the trust bundle. The `policy_generation` in every audit event shows exactly which policy authorised a request.
- **Audit pipeline:** stdout → a log shipper (Vector/Fluent Bit) → durable, append-only storage with retention, plus alerts on denials and anomalies. If audit loss is unacceptable, use a sink with acknowledgements.
- **Observability:** add Prometheus metrics (decisions, latency histograms, handshake failures by reason, pool saturation) and OpenTelemetry spans (`traceparent` is already passed through and audited).
- **Capacity:** scale horizontally, since the proxy is stateless apart from per-instance rate limits. Keep client connections long-lived; handshakes dominate cost when clients reconnect per request.
- **Hardening:** run with a distroless image, pin base image digests, sign the image, generate an SBOM, and run `cargo audit` / `cargo deny` in CI.

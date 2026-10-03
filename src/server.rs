//! Listener, per-connection TLS handshake, admin endpoints, reload loop and graceful shutdown.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::Json;
use axum::routing::get;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{error, info, warn};

use crate::audit::{AuditSink, HandshakeRejected};
use crate::config::Config;
use crate::identity::IdentityOptions;
use crate::middleware::{AppInner, AppState, ConnInfo, RateLimiter, router};
use crate::policy::{PolicyStore, ReloadOutcome, now};
use crate::proxy::Upstream;
use crate::tls::{TlsPaths, TlsState};

pub struct ProxyHandle {
    pub addr: SocketAddr,
    pub admin_addr: SocketAddr,
    pub tls: Arc<TlsState>,
    pub policy: Arc<PolicyStore>,
    reload_tx: tokio::sync::mpsc::Sender<()>,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl ProxyHandle {
    /// Forces an immediate trust/policy reload check (same as SIGHUP).
    pub async fn trigger_reload(&self) {
        let _ = self.reload_tx.send(()).await;
    }

    /// Stops accepting, lets in-flight requests finish (bounded by the grace period), returns.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

/// Builds all state, binds both listeners and spawns the serving tasks.
pub async fn start(cfg: &Config, audit: Arc<dyn AuditSink>) -> anyhow::Result<ProxyHandle> {
    let tls = Arc::new(TlsState::load(TlsPaths {
        cert: cfg.tls_cert.clone(),
        key: cfg.tls_key.clone(),
        client_ca_bundle: cfg.client_ca_bundle.clone(),
    })?);
    let policy = Arc::new(PolicyStore::load(cfg.policy_file.clone())?);
    let instance_id =
        cfg.instance_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string()[..12].to_string());
    let upstream =
        Arc::new(Upstream::new(&cfg.upstream_url, cfg.upstream_timeout(), cfg.max_body_bytes, &instance_id)?);

    let listener = TcpListener::bind(cfg.listen_addr).await?;
    let addr = listener.local_addr()?;
    let admin_listener = TcpListener::bind(cfg.admin_addr).await?;
    let admin_addr = admin_listener.local_addr()?;
    check_not_self(&upstream, addr)?;

    let draining = Arc::new(AtomicBool::new(false));
    let limiter = RateLimiter::new(cfg.rate_limit_rps, cfg.rate_limit_burst).map(Arc::new);
    let state = AppState::new(AppInner {
        tls: tls.clone(),
        policy: policy.clone(),
        upstream: upstream.clone(),
        audit: audit.clone(),
        limiter: limiter.clone(),
        concurrency: Arc::new(Semaphore::new(cfg.max_concurrency)),
        identity_opts: Arc::new(IdentityOptions {
            require_spiffe_id: cfg.require_spiffe_id,
            trust_domains: cfg.trust_domains(),
        }),
        draining: draining.clone(),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(4);

    let accept = tokio::spawn(accept_loop(
        listener,
        state.clone(),
        audit,
        cfg.handshake_timeout(),
        cfg.shutdown_grace(),
        shutdown_rx.clone(),
    ));
    let admin = tokio::spawn(admin_server(admin_listener, state.clone(), instance_id.clone(), shutdown_rx.clone()));
    let reload = tokio::spawn(reload_loop(state, limiter, cfg.reload_interval(), reload_rx, shutdown_rx));

    info!(%addr, %admin_addr, upstream = %cfg.upstream_url, instance_id, "proxy listening");
    Ok(ProxyHandle { addr, admin_addr, tls, policy, reload_tx, shutdown_tx, tasks: vec![accept, admin, reload] })
}

/// Refuse to start if the upstream is this very listener (the simplest accidental loop).
fn check_not_self(upstream: &Upstream, listen: SocketAddr) -> anyhow::Result<()> {
    let a = upstream.authority();
    let port = a.port_u16().unwrap_or(80);
    let local_host = matches!(a.host(), "localhost" | "127.0.0.1" | "[::1]" | "0.0.0.0");
    anyhow::ensure!(
        !(local_host && port == listen.port()),
        "UPSTREAM_URL points at the proxy's own listener ({listen})"
    );
    Ok(())
}

async fn accept_loop(
    listener: TcpListener,
    state: AppState,
    audit: Arc<dyn AuditSink>,
    handshake_timeout: Duration,
    grace: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let app = router(state.clone());
    let graceful = GracefulShutdown::new();
    loop {
        let (tcp, peer) = tokio::select! {
            res = listener.accept() => match res {
                Ok(x) => x,
                Err(e) => {
                    // e.g. EMFILE: back off instead of spinning.
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };
        let _ = tcp.set_nodelay(true);

        // One snapshot per connection: the whole handshake sees one consistent trust store.
        let snapshot = state.tls.current();
        let app = app.clone();
        let audit = audit.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(snapshot.server_config.clone());
            let tls = match tokio::time::timeout(handshake_timeout, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return handshake_rejected(&*audit, peer, e.to_string(), snapshot.generation),
                Err(_) => return handshake_rejected(&*audit, peer, "handshake timed out".into(), snapshot.generation),
            };
            let (_, session) = tls.get_ref();
            let Some(chain) =
                session.peer_certificates().map(|c| c.iter().map(|c| c.clone().into_owned()).collect::<Vec<_>>())
            else {
                // Unreachable with a mandatory client verifier; fail closed anyway.
                return handshake_rejected(&*audit, peer, "no client certificate".into(), snapshot.generation);
            };
            let conn = Arc::new(ConnInfo {
                peer_addr: peer,
                chain,
                tls_version: session.protocol_version().map(|v| format!("{v:?}")).unwrap_or_default(),
                verified_generation: AtomicU64::new(snapshot.generation),
                identity: OnceLock::new(),
            });

            let svc = service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(conn.clone());
                app.clone().oneshot(req)
            });
            let builder = auto::Builder::new(TokioExecutor::new());
            let served = builder.serve_connection(TokioIo::new(tls), svc).into_owned();
            if let Err(e) = watcher.watch(served).await {
                tracing::debug!(%peer, error = %e, "connection ended with error");
            }
        });
    }
    drop(listener);
    state.draining.store(true, Ordering::Release);
    info!("draining connections");
    tokio::select! {
        _ = graceful.shutdown() => info!("all connections closed"),
        _ = tokio::time::sleep(grace) => warn!("grace period elapsed; dropping remaining connections"),
    }
}

fn handshake_rejected(audit: &dyn AuditSink, peer: SocketAddr, reason: String, generation: u64) {
    audit.handshake_rejected(&HandshakeRejected {
        timestamp: now(),
        event: "tls_handshake_rejected",
        client_addr: peer.to_string(),
        reason,
        trust_generation: generation,
    });
}

async fn admin_server(
    listener: TcpListener,
    state: AppState,
    instance_id: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let st = state.clone();
    let app = axum::Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get({
                let draining = state.draining.clone();
                move || async move {
                    if draining.load(Ordering::Acquire) {
                        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "draining")
                    } else {
                        (axum::http::StatusCode::OK, "ready")
                    }
                }
            }),
        )
        .route(
            "/status",
            get(move || {
                let st = st.clone();
                let instance_id = instance_id.clone();
                async move {
                    let snap = st.tls.current();
                    Json(json!({
                        "instance_id": instance_id,
                        "draining": st.draining.load(Ordering::Acquire),
                        "trust": { "status": st.tls.status(), "cas": snap.cas },
                        "policy": { "status": st.policy.status(), "identities": st.policy.current().identities() },
                        "in_flight_available_permits": st.concurrency.available_permits(),
                    }))
                }
            }),
        );
    let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = shutdown.changed().await;
    });
    if let Err(e) = serve.await {
        error!(error = %e, "admin server failed");
    }
}

async fn reload_loop(
    state: AppState,
    limiter: Option<Arc<RateLimiter>>,
    interval: Duration,
    mut reload_rx: tokio::sync::mpsc::Receiver<()>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    #[cfg(unix)]
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    loop {
        #[cfg(unix)]
        let hup_fut = async {
            match hup.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending().await,
            }
        };
        #[cfg(not(unix))]
        let hup_fut = std::future::pending::<()>();
        tokio::select! {
            _ = ticker.tick() => {}
            _ = reload_rx.recv() => {}
            _ = hup_fut => info!("SIGHUP: reloading"),
            _ = shutdown.changed() => return,
        }
        // Reading and validating files is blocking work; keep it off the reactor.
        let (tls, policy) = (state.tls.clone(), state.policy.clone());
        let Ok((t, p)) =
            tokio::task::spawn_blocking(move || (tls.reload_if_changed(), policy.reload_if_changed())).await
        else {
            continue;
        };
        log_outcome("trust store", t);
        log_outcome("policy", p);
        if let Some(l) = &limiter {
            l.housekeeping();
        }
    }
}

fn log_outcome(what: &str, outcome: ReloadOutcome) {
    match outcome {
        ReloadOutcome::Unchanged => {}
        ReloadOutcome::Reloaded(generation) => info!(what, generation, "reloaded"),
        ReloadOutcome::Rejected(e) => error!(what, error = %e, "reload REJECTED; keeping last-known-good"),
    }
}

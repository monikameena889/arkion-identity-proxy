use std::sync::Arc;

use arkion_identity_proxy::audit::{AuditSink, StdoutSink};
use arkion_identity_proxy::config::{Config, LogFormat};
use arkion_identity_proxy::server;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();
    // Operational logs go to stderr; audit events are JSON lines on stdout.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr);
    match cfg.log_format {
        LogFormat::Json => builder.json().flatten_event(true).init(),
        LogFormat::Text => builder.init(),
    }

    let audit = Arc::new(StdoutSink::new());
    let handle = server::start(&cfg, audit.clone()).await?;
    shutdown_signal().await;
    tracing::info!("shutdown signal received");
    handle.shutdown().await;
    audit.flush();
    tracing::info!("stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

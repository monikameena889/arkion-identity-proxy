//! A tiny upstream ("existing API") used by tests, the demo and the benchmark.
//!
//! - any path: returns JSON describing the request it received (method, path, query, headers,
//!   body length and SHA-256) — this is how tests check what the proxy forwarded.
//! - `/slow/<ms>`: sleeps before answering (upstream-timeout tests).
//! - `/status/<code>`: answers with that status.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use serde_json::json;
use sha2::{Digest, Sha256};

async fn echo(req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    if let Some(ms) = path.strip_prefix("/slow/").and_then(|s| s.parse::<u64>().ok()) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    let status = path
        .strip_prefix("/status/")
        .and_then(|s| s.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::OK);
    let body: Bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in &parts.headers {
        headers.entry(k.to_string()).or_default().push(String::from_utf8_lossy(v.as_bytes()).into_owned());
    }
    let out = json!({
        "method": parts.method.as_str(),
        "path": path,
        "query": parts.uri.query(),
        "version": format!("{:?}", parts.version),
        "headers": headers,
        "body_len": body.len(),
        "body_sha256": hex::encode(Sha256::digest(&body)),
    });
    (
        status,
        [("x-upstream", "echo"), ("connection", "keep-alive, x-upstream-hop"), ("x-upstream-hop", "secret")],
        Json(out),
    )
        .into_response()
}

pub fn router() -> axum::Router {
    axum::Router::new().fallback(echo).layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024))
}

/// Binds `addr` and serves the echo upstream in the background. Returns the bound address.
pub async fn spawn(addr: SocketAddr) -> anyhow::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router()).await;
    });
    Ok(bound)
}

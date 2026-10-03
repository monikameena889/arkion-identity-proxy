//! Closed-loop HTTP load generator used to compare upstream-direct vs through-proxy latency.
//!
//! Direct:  loadgen --url http://127.0.0.1:8080/payments
//! Proxy:   loadgen --url https://localhost:8443/payments --ca pki/ca-v1.crt \
//!                  --cert pki/payment.crt --key pki/payment.key

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    url: String,
    #[arg(long, default_value = "POST")]
    method: String,
    #[arg(long, default_value = "1,10,100,500", value_delimiter = ',')]
    concurrency: Vec<usize>,
    #[arg(long, default_value_t = 10)]
    duration_secs: u64,
    #[arg(long, default_value_t = 2)]
    warmup_secs: u64,
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    /// CA to trust for https URLs.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Client certificate chain + key for mTLS.
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    /// Use HTTP/2 instead of HTTP/1.1 (https only).
    #[arg(long, default_value_t = false)]
    http2: bool,
    #[arg(long, default_value = "")]
    label: String,
}

#[derive(Default)]
struct Stats {
    latencies_us: Vec<u64>,
    errors: BTreeMap<String, u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut b = reqwest::Client::builder().pool_max_idle_per_host(1024).timeout(Duration::from_secs(15));
    if let Some(ca) = &args.ca {
        b = b
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    if let (Some(cert), Some(key)) = (&args.cert, &args.key) {
        let mut pem = std::fs::read(cert)?;
        pem.extend(std::fs::read(key)?);
        b = b.identity(reqwest::Identity::from_pem(&pem)?);
    }
    if !args.http2 {
        b = b.http1_only();
    }
    let client = b.build()?;
    let method: reqwest::Method = args.method.parse()?;
    let body = Arc::new(vec![0x42u8; args.payload_bytes]);

    println!("| target | concurrency | requests | req/s | p50 (ms) | p95 (ms) | p99 (ms) | error rate | errors |");
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---|");
    for &c in &args.concurrency {
        if args.warmup_secs > 0 {
            run(&client, &method, &args.url, &body, c, Duration::from_secs(args.warmup_secs)).await;
        }
        let started = Instant::now();
        let stats = run(&client, &method, &args.url, &body, c, Duration::from_secs(args.duration_secs)).await;
        report(&args.label, c, started.elapsed(), stats);
    }
    Ok(())
}

async fn run(
    client: &reqwest::Client,
    method: &reqwest::Method,
    url: &str,
    body: &Arc<Vec<u8>>,
    concurrency: usize,
    d: Duration,
) -> Stats {
    let deadline = Instant::now() + d;
    let workers: Vec<_> = (0..concurrency)
        .map(|_| {
            let (client, method, url, body) = (client.clone(), method.clone(), url.to_string(), body.clone());
            tokio::spawn(async move {
                let mut s = Stats::default();
                while Instant::now() < deadline {
                    let t = Instant::now();
                    let res = client.request(method.clone(), &url).body(body.as_ref().clone()).send().await;
                    let err = match res {
                        Ok(r) if r.status().is_success() => {
                            let _ = r.bytes().await;
                            None
                        }
                        Ok(r) => Some(r.status().as_u16().to_string()),
                        Err(e) if e.is_timeout() => Some("timeout".into()),
                        Err(_) => Some("connect/tls".into()),
                    };
                    s.latencies_us.push(t.elapsed().as_micros() as u64);
                    if let Some(k) = err {
                        *s.errors.entry(k).or_default() += 1;
                    }
                }
                s
            })
        })
        .collect();
    let mut total = Stats::default();
    for w in workers {
        let s = w.await.expect("worker panicked");
        total.latencies_us.extend(s.latencies_us);
        for (k, v) in s.errors {
            *total.errors.entry(k).or_default() += v;
        }
    }
    total
}

fn report(label: &str, c: usize, elapsed: Duration, mut s: Stats) {
    s.latencies_us.sort_unstable();
    let n = s.latencies_us.len();
    let pct = |p: f64| {
        if n == 0 { 0.0 } else { s.latencies_us[((p / 100.0) * (n as f64 - 1.0)).round() as usize] as f64 / 1000.0 }
    };
    let errors: u64 = s.errors.values().sum();
    let detail = if s.errors.is_empty() {
        "-".into()
    } else {
        s.errors.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(", ")
    };
    println!(
        "| {label} | {c} | {n} | {:.0} | {:.2} | {:.2} | {:.2} | {:.2}% | {detail} |",
        (n as u64 - errors) as f64 / elapsed.as_secs_f64(),
        pct(50.0),
        pct(95.0),
        pct(99.0),
        if n == 0 { 0.0 } else { errors as f64 * 100.0 / n as f64 }
    );
}

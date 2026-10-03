//! The demo upstream ("existing API"): `echo-upstream [ADDR]` (default 0.0.0.0:8080).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:8080".into()).parse()?;
    let bound = arkion_identity_proxy::echo::spawn(addr).await?;
    eprintln!("echo upstream listening on {bound}");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

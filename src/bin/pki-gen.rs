//! Generates the demo/test PKI: `pki-gen [DIR]` (default ./pki). See `devpki` for the layout.

fn main() -> anyhow::Result<()> {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "pki".into());
    arkion_identity_proxy::devpki::write_demo_pki(std::path::Path::new(&dir))?;
    println!("wrote demo PKI to {dir}/");
    Ok(())
}

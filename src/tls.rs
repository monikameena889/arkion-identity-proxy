//! TLS-layer validation and dynamic trust-store rotation.
//!
//! **What the TLS layer (rustls + webpki) validates, during the handshake:**
//! - a client certificate is present (`WebPkiClientVerifier` without `allow_unauthenticated`);
//! - the chain builds to a CA in the *current* trust bundle (intermediates supplied by the client);
//! - every signature in the chain; validity period (expired / not-yet-valid) of every certificate;
//! - CA basic constraints and path length; the leaf's extended key usage allows clientAuth;
//! - proof of possession of the private key (CertificateVerify).
//!
//! A failure aborts the handshake: no HTTP request is ever parsed for that connection.
//!
//! **Rotation design.** The current trust material is an immutable [`TrustSnapshot`] (rustls
//! `ServerConfig` + the verifier + metadata) behind an [`ArcSwap`]. The accept loop loads the
//! snapshot *once per connection*, so a handshake always uses one consistent snapshot; a reload
//! builds and fully validates a new snapshot off to the side and swaps a pointer. No locks on the
//! hot path, no torn reads, and in-flight handshakes keep the snapshot they started with.
//!
//! Existing connections were authenticated against an older snapshot. The identity middleware
//! re-verifies such a connection's stored chain against the new verifier on its next request
//! (see [`TrustSnapshot::verifier`]), so a CA removed from the bundle stops working immediately,
//! not when the client happens to reconnect.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::identity::sha256_hex;
use crate::policy::{ReloadOutcome, StoreStatus, now};

#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub client_ca_bundle: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaInfo {
    pub subject: String,
    pub sha256: String,
    pub not_after: String,
}

/// One immutable, fully validated generation of TLS material.
pub struct TrustSnapshot {
    pub generation: u64,
    pub server_config: Arc<rustls::ServerConfig>,
    /// The client-certificate verifier inside `server_config`, kept so that existing connections
    /// can be re-validated against the current trust store.
    pub verifier: Arc<dyn ClientCertVerifier>,
    pub cas: Vec<CaInfo>,
}

pub struct TlsState {
    paths: TlsPaths,
    current: ArcSwap<TrustSnapshot>,
    generation: AtomicU64,
    status: Mutex<StoreStatus>,
    /// Fingerprint of the last rejected file set, so a bad update is reported once, not every tick.
    rejected: Mutex<Option<String>>,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn read(path: &PathBuf) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

/// Parses and validates a CA bundle. Rejects empty bundles, non-CA certificates and expired CAs,
/// so an accidental bad deploy (wrong file, leaf cert, truncated PEM) can never become active.
pub fn parse_ca_bundle(pem: &[u8]) -> Result<(RootCertStore, Vec<CaInfo>), String> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(pem).collect::<Result<_, _>>().map_err(|e| format!("CA bundle PEM: {e}"))?;
    if certs.is_empty() {
        return Err("CA bundle contains no certificates".into());
    }
    let mut roots = RootCertStore::empty();
    let mut infos = Vec::new();
    let now = ASN1Time::now();
    for der in &certs {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|e| format!("CA bundle: unparseable certificate: {e}"))?;
        let subject = cert.subject().to_string();
        if !cert.is_ca() {
            return Err(format!("CA bundle: '{subject}' is not a CA certificate"));
        }
        if !cert.validity().is_valid_at(now) {
            return Err(format!("CA bundle: '{subject}' is expired or not yet valid"));
        }
        roots.add(der.clone()).map_err(|e| format!("CA bundle: '{subject}' rejected by webpki: {e}"))?;
        infos.push(CaInfo {
            subject,
            sha256: sha256_hex(der),
            not_after: cert.validity().not_after.to_datetime().to_string(),
        });
    }
    Ok((roots, infos))
}

struct Material {
    ca: Vec<u8>,
    cert: Vec<u8>,
    key: Vec<u8>,
    fingerprint: String,
}

fn read_material(paths: &TlsPaths) -> Result<Material, String> {
    let ca = read(&paths.client_ca_bundle)?;
    let cert = read(&paths.cert)?;
    let key = read(&paths.key)?;
    let mut h = Sha256::new();
    for part in [&ca, &cert, &key] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    Ok(Material { ca, cert, key, fingerprint: hex::encode(h.finalize()) })
}

fn build_snapshot(m: &Material, generation: u64) -> Result<TrustSnapshot, String> {
    let (roots, cas) = parse_ca_bundle(&m.ca)?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .map_err(|e| format!("building client verifier: {e}"))?;

    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&m.cert)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("server certificate PEM: {e}"))?;
    if chain.is_empty() {
        return Err("server certificate file contains no certificates".into());
    }
    let key = PrivateKeyDer::from_pem_slice(&m.key).map_err(|e| format!("server key PEM: {e}"))?;

    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(chain, key)
        .map_err(|e| format!("server certificate/key: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TrustSnapshot { generation, server_config: Arc::new(config), verifier, cas })
}

impl TlsState {
    /// Initial load. Unlike reloads, a failure here is fatal: there is no last-known-good yet.
    pub fn load(paths: TlsPaths) -> anyhow::Result<Self> {
        let material = read_material(&paths).map_err(|e| anyhow::anyhow!(e))?;
        let snapshot = build_snapshot(&material, 1).map_err(|e| anyhow::anyhow!(e))?;
        Ok(Self {
            paths,
            current: ArcSwap::from_pointee(snapshot),
            generation: AtomicU64::new(1),
            status: Mutex::new(StoreStatus {
                generation: 1,
                sha256: material.fingerprint,
                loaded_at: now(),
                last_error: None,
            }),
            rejected: Mutex::new(None),
        })
    }

    pub fn current(&self) -> Arc<TrustSnapshot> {
        self.current.load_full()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn status(&self) -> StoreStatus {
        self.status.lock().unwrap().clone()
    }

    /// Rebuilds the snapshot if any of the cert/key/CA files changed. Invalid material is
    /// rejected and the current snapshot stays active (last-known-good). Unchanged files cost
    /// three reads and a hash, nothing more.
    pub fn reload_if_changed(&self) -> ReloadOutcome {
        let material = match read_material(&self.paths) {
            Ok(m) => m,
            Err(e) => return self.reject(None, e),
        };
        {
            let mut st = self.status.lock().unwrap();
            if material.fingerprint == st.sha256 {
                // Unchanged, or a bad update was rolled back to what is already running.
                st.last_error = None;
                *self.rejected.lock().unwrap() = None;
                return ReloadOutcome::Unchanged;
            }
        }
        if self.rejected.lock().unwrap().as_deref() == Some(material.fingerprint.as_str()) {
            return ReloadOutcome::Unchanged; // same bad files as last time, already reported
        }
        let next_gen = self.generation() + 1;
        match build_snapshot(&material, next_gen) {
            Ok(snapshot) => {
                self.current.store(Arc::new(snapshot));
                self.generation.store(next_gen, Ordering::Release);
                *self.rejected.lock().unwrap() = None;
                *self.status.lock().unwrap() = StoreStatus {
                    generation: next_gen,
                    sha256: material.fingerprint,
                    loaded_at: now(),
                    last_error: None,
                };
                ReloadOutcome::Reloaded(next_gen)
            }
            Err(e) => self.reject(Some(material.fingerprint), e),
        }
    }

    fn reject(&self, fingerprint: Option<String>, e: String) -> ReloadOutcome {
        let mut st = self.status.lock().unwrap();
        let repeat = st.last_error.as_deref() == Some(e.as_str());
        st.last_error = Some(e.clone());
        *self.rejected.lock().unwrap() = fingerprint;
        if repeat { ReloadOutcome::Unchanged } else { ReloadOutcome::Rejected(e) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devpki::{Ca, LeafSpec};

    #[test]
    fn rejects_bad_bundles() {
        assert!(parse_ca_bundle(b"").unwrap_err().contains("no certificates"));
        assert!(parse_ca_bundle(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n").is_err());
        let ca = Ca::new_root("root").unwrap();
        let leaf = ca.issue(&LeafSpec::client("leaf", &["spiffe://acme/x"])).unwrap();
        assert!(parse_ca_bundle(leaf.cert_pem.as_bytes()).unwrap_err().contains("not a CA"));
        let (_, infos) = parse_ca_bundle(ca.cert_pem.as_bytes()).unwrap();
        assert_eq!(infos.len(), 1);
    }

    #[test]
    fn rejects_server_key_that_does_not_match_certificate() {
        let dir = tempfile::tempdir().unwrap();
        crate::devpki::write_demo_pki(dir.path()).unwrap();
        let paths = TlsPaths {
            cert: dir.path().join("server.crt"),
            key: dir.path().join("payment.key"),
            client_ca_bundle: dir.path().join("trust-bundle.pem"),
        };
        let err = TlsState::load(paths).err().expect("mismatched key must be rejected");
        assert!(err.to_string().contains("server certificate/key"), "{err}");
    }
}

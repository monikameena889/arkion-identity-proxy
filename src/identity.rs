//! Application-layer identity extraction.
//!
//! By the time this runs, rustls/webpki has already verified the chain to a trusted root,
//! signatures, validity period, basic constraints and the clientAuth EKU (see [`crate::tls`]).
//! This module decides **who** the (already trusted) certificate identifies:
//!
//! 1. Exactly one SPIFFE URI SAN → that is the identity (strictly validated per the SPIFFE spec).
//!    More than one, or a malformed one → rejected (never "pick the first").
//! 2. No SPIFFE ID and `require_spiffe_id = false` → first DNS SAN, as `dns:<name>`.
//! 3. Otherwise → rejected. The subject CN is never used as an identity (it is unstructured and
//!    not covered by name constraints).

use ::time::format_description::well_known::Rfc3339;
use rustls::pki_types::CertificateDer;
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

const MAX_SPIFFE_ID_LEN: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpiffeId {
    pub trust_domain: String,
    pub path: String,
}

impl SpiffeId {
    pub fn as_uri(&self) -> String {
        format!("spiffe://{}{}", self.trust_domain, self.path)
    }
}

/// Everything we extract from the presented chain. All of it is public certificate data.
#[derive(Debug, Clone, Serialize)]
pub struct CertDetails {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    #[serde(skip)]
    pub not_after_unix: i64,
    #[serde(skip)]
    pub not_before_unix: i64,
    pub uri_sans: Vec<String>,
    pub dns_sans: Vec<String>,
    /// Certificates presented by the client (leaf + intermediates).
    pub chain_len: usize,
    /// SHA-256 fingerprints of the presented chain, leaf first.
    pub chain_sha256: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    Spiffe,
    Dns,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientIdentity {
    /// The authenticated identity used for authorization, e.g. `spiffe://acme/prod/payment`.
    pub id: String,
    pub kind: IdentityKind,
    pub cert: CertDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("client presented no certificate")]
    NoCertificate,
    #[error("client certificate could not be parsed: {0}")]
    Unparseable(String),
    #[error("certificate has {0} SPIFFE IDs; exactly one is allowed")]
    MultipleSpiffeIds(usize),
    #[error("malformed SPIFFE ID: {0}")]
    MalformedSpiffeId(String),
    #[error("SPIFFE trust domain '{0}' is not allowed")]
    TrustDomainNotAllowed(String),
    #[error("certificate carries no usable identity (no SPIFFE ID{0})")]
    NoIdentity(&'static str),
    #[error("malformed DNS SAN: {0}")]
    MalformedDns(String),
}

#[derive(Debug, Clone, Default)]
pub struct IdentityOptions {
    pub require_spiffe_id: bool,
    /// Empty = any trust domain.
    pub trust_domains: Vec<String>,
}

/// Strict SPIFFE ID parser (SPIFFE-ID spec §2): lowercase scheme, trust domain of
/// `[a-z0-9.-_]`, optional path of non-empty segments of `[A-Za-z0-9.-_]`, no `.`/`..`
/// segments, no query, fragment, port, userinfo or percent-encoding.
pub fn parse_spiffe_id(s: &str) -> Result<SpiffeId, String> {
    if s.len() > MAX_SPIFFE_ID_LEN {
        return Err("longer than 2048 bytes".into());
    }
    let rest = s.strip_prefix("spiffe://").ok_or("scheme must be exactly 'spiffe://'")?;
    let (td, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if td.is_empty() {
        return Err("empty trust domain".into());
    }
    if !td.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')) {
        return Err(format!("invalid character in trust domain '{td}'"));
    }
    if !path.is_empty() {
        for seg in path[1..].split('/') {
            if seg.is_empty() {
                return Err("empty path segment (or trailing slash)".into());
            }
            if seg == "." || seg == ".." {
                return Err("dot segment in path".into());
            }
            if !seg.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
                return Err(format!("invalid character in path segment '{seg}'"));
            }
        }
    }
    Ok(SpiffeId { trust_domain: td.to_string(), path: path.to_string() })
}

/// Validates a policy/identity string of the form `spiffe://...` or `dns:<name>`.
pub fn validate_identity_string(s: &str) -> Result<(), String> {
    if let Some(name) = s.strip_prefix("dns:") {
        return validate_dns_name(name);
    }
    parse_spiffe_id(s).map(|_| ())
}

fn validate_dns_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if ok { Ok(()) } else { Err(format!("invalid DNS name '{name}' (must be lowercase LDH)")) }
}

pub fn sha256_hex(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

fn fmt_time(t: ASN1Time) -> String {
    t.to_datetime().format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

/// Parses the leaf certificate (first in `chain`) into [`CertDetails`].
pub fn cert_details(chain: &[CertificateDer<'_>]) -> Result<CertDetails, IdentityError> {
    let leaf = chain.first().ok_or(IdentityError::NoCertificate)?;
    let (rest, cert) = X509Certificate::from_der(leaf).map_err(|e| IdentityError::Unparseable(e.to_string()))?;
    if !rest.is_empty() {
        return Err(IdentityError::Unparseable("trailing data after certificate".into()));
    }
    let mut uri_sans = Vec::new();
    let mut dns_sans = Vec::new();
    let san = cert.subject_alternative_name().map_err(|e| IdentityError::Unparseable(format!("SAN extension: {e}")))?;
    if let Some(san) = san {
        for name in &san.value.general_names {
            match name {
                GeneralName::URI(u) => uri_sans.push(u.to_string()),
                GeneralName::DNSName(d) => dns_sans.push(d.to_string()),
                _ => {}
            }
        }
    }
    let validity = cert.validity();
    Ok(CertDetails {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before: fmt_time(validity.not_before),
        not_after: fmt_time(validity.not_after),
        not_before_unix: validity.not_before.timestamp(),
        not_after_unix: validity.not_after.timestamp(),
        uri_sans,
        dns_sans,
        chain_len: chain.len(),
        chain_sha256: chain.iter().map(|c| sha256_hex(c)).collect(),
    })
}

/// Resolves the authenticated identity from a chain that the TLS layer has already verified.
pub fn extract_identity(chain: &[CertificateDer<'_>], opts: &IdentityOptions) -> Result<ClientIdentity, IdentityError> {
    let cert = cert_details(chain)?;

    // Anything that *looks* like a SPIFFE ID counts (case-insensitive scheme), so that e.g.
    // "SPIFFE://..." is rejected as malformed instead of being silently ignored.
    let spiffe_like: Vec<&String> =
        cert.uri_sans.iter().filter(|u| u.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("spiffe:"))).collect();

    match spiffe_like.as_slice() {
        [] => {}
        [one] => {
            let id = parse_spiffe_id(one).map_err(|e| IdentityError::MalformedSpiffeId(format!("{one}: {e}")))?;
            if !opts.trust_domains.is_empty() && !opts.trust_domains.contains(&id.trust_domain) {
                return Err(IdentityError::TrustDomainNotAllowed(id.trust_domain));
            }
            return Ok(ClientIdentity { id: id.as_uri(), kind: IdentityKind::Spiffe, cert });
        }
        many => return Err(IdentityError::MultipleSpiffeIds(many.len())),
    }

    if opts.require_spiffe_id {
        return Err(IdentityError::NoIdentity(", and REQUIRE_SPIFFE_ID is set"));
    }
    match cert.dns_sans.first() {
        Some(dns) => {
            validate_dns_name(dns).map_err(IdentityError::MalformedDns)?;
            Ok(ClientIdentity { id: format!("dns:{dns}"), kind: IdentityKind::Dns, cert })
        }
        None => Err(IdentityError::NoIdentity(" and no DNS SAN")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devpki::{Ca, LeafSpec};

    fn chain_of(pem: &str) -> Vec<CertificateDer<'static>> {
        use rustls::pki_types::pem::PemObject;
        CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<_, _>>().unwrap()
    }

    #[test]
    fn spiffe_parser_accepts_valid_ids() {
        let id = parse_spiffe_id("spiffe://acme/prod/payment").unwrap();
        assert_eq!(id.trust_domain, "acme");
        assert_eq!(id.path, "/prod/payment");
        assert!(parse_spiffe_id("spiffe://acme.example-1_x").is_ok());
    }

    #[test]
    fn spiffe_parser_rejects_malformed_ids() {
        for bad in [
            "SPIFFE://acme/x",
            "spiffe:/acme/x",
            "https://acme/x",
            "spiffe:///x",
            "spiffe://Acme/x",
            "spiffe://acme:443/x",
            "spiffe://user@acme/x",
            "spiffe://acme/x/../admin",
            "spiffe://acme/./x",
            "spiffe://acme//x",
            "spiffe://acme/x/",
            "spiffe://acme/x?q=1",
            "spiffe://acme/x#frag",
            "spiffe://acme/x%2Fy",
        ] {
            assert!(parse_spiffe_id(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn extracts_identity_and_details() {
        let ca = Ca::new_root("root").unwrap();
        let inter = ca.new_intermediate("issuing").unwrap();
        let leaf = inter.issue(&LeafSpec::client("pay", &["spiffe://acme/prod/payment"])).unwrap();
        let chain = chain_of(&leaf.chain_pem);
        let id = extract_identity(&chain, &IdentityOptions::default()).unwrap();
        assert_eq!(id.id, "spiffe://acme/prod/payment");
        assert_eq!(id.kind, IdentityKind::Spiffe);
        assert_eq!(id.cert.chain_len, 2);
        assert!(id.cert.subject.contains("CN=pay"));
        assert!(id.cert.issuer.contains("CN=issuing"));
        assert!(!id.cert.serial.is_empty());
    }

    #[test]
    fn rejects_multiple_and_malformed_spiffe_ids() {
        let ca = Ca::new_root("root").unwrap();
        let multi = ca.issue(&LeafSpec::client("m", &["spiffe://acme/a", "spiffe://acme/b"])).unwrap();
        assert_eq!(
            extract_identity(&chain_of(&multi.chain_pem), &IdentityOptions::default()).unwrap_err(),
            IdentityError::MultipleSpiffeIds(2)
        );
        let bad = ca.issue(&LeafSpec::client("b", &["spiffe://acme/../admin"])).unwrap();
        assert!(matches!(
            extract_identity(&chain_of(&bad.chain_pem), &IdentityOptions::default()),
            Err(IdentityError::MalformedSpiffeId(_))
        ));
    }

    #[test]
    fn trust_domain_allowlist_and_dns_fallback() {
        let ca = Ca::new_root("root").unwrap();
        let other = ca.issue(&LeafSpec::client("o", &["spiffe://evil/x"])).unwrap();
        let opts = IdentityOptions { require_spiffe_id: false, trust_domains: vec!["acme".into()] };
        assert_eq!(
            extract_identity(&chain_of(&other.chain_pem), &opts).unwrap_err(),
            IdentityError::TrustDomainNotAllowed("evil".into())
        );

        let mut spec = LeafSpec::client("d", &[]);
        spec.dns = vec!["batch.acme.internal".into()];
        let dns = ca.issue(&spec).unwrap();
        let id = extract_identity(&chain_of(&dns.chain_pem), &IdentityOptions::default()).unwrap();
        assert_eq!(id.id, "dns:batch.acme.internal");
        let strict = IdentityOptions { require_spiffe_id: true, trust_domains: vec![] };
        assert!(matches!(extract_identity(&chain_of(&dns.chain_pem), &strict), Err(IdentityError::NoIdentity(_))));

        let none = ca.issue(&LeafSpec::client("n", &[])).unwrap();
        assert!(matches!(
            extract_identity(&chain_of(&none.chain_pem), &IdentityOptions::default()),
            Err(IdentityError::NoIdentity(_))
        ));
    }
}

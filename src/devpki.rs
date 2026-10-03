//! Generates a throw-away PKI for tests, local runs and the container demo.
//!
//! Layout written by [`write_demo_pki`]:
//!
//! ```text
//! ca-v1.crt            root CA "Arkion Test Root v1"            (in trust-bundle.pem initially)
//! intermediate.crt     intermediate under ca-v1
//! ca-v2.crt            root CA "Arkion Test Root v2"            (for the rotation demo)
//! untrusted-ca.crt     a CA that is never trusted
//! trust-bundle.pem     = ca-v1.crt
//! trust-bundle-v2.pem  = ca-v2.crt
//! server.{crt,key}     localhost / proxy / 127.0.0.1 (signed by ca-v1, trusted by clients via ca-v1.crt)
//! payment        spiffe://acme/prod/payment   (ca-v1)
//! reporting      spiffe://acme/prod/reporting (intermediate -> chain of 2)
//! unknown        spiffe://acme/prod/unknown   (ca-v1, no policy)
//! dns            DNS SAN only: batch.acme.internal  (ca-v1)
//! expired              payment identity, expired
//! not-yet-valid        payment identity, valid from next year
//! untrusted            payment identity, signed by untrusted-ca
//! malformed-spiffe     spiffe://acme/prod/../admin
//! multi-spiffe         two SPIFFE URI SANs
//! payment-v2     spiffe://acme/prod/payment signed by ca-v2
//! ```
//! Each client has `<name>.crt` (leaf + intermediates) and `<name>.key`.

use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

pub struct Ca {
    pub name: String,
    pub cert_pem: String,
    /// PEMs of intermediates between this CA and the root (empty for roots).
    pub chain_pem: Vec<String>,
    issuer: Issuer<'static, KeyPair>,
}

pub struct Leaf {
    pub cert_pem: String,
    /// Leaf followed by any intermediates — what a client presents.
    pub chain_pem: String,
    pub key_pem: String,
}

#[derive(Clone)]
pub struct LeafSpec {
    pub common_name: String,
    pub uris: Vec<String>,
    pub dns: Vec<String>,
    pub ips: Vec<std::net::IpAddr>,
    pub server: bool,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl LeafSpec {
    pub fn client(cn: &str, uris: &[&str]) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            common_name: cn.into(),
            uris: uris.iter().map(|s| s.to_string()).collect(),
            dns: vec![],
            ips: vec![],
            server: false,
            not_before: now - Duration::hours(1),
            not_after: now + Duration::days(365),
        }
    }

    pub fn with_validity(mut self, not_before: OffsetDateTime, not_after: OffsetDateTime) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }
}

fn dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Arkion Test");
    dn.push(DnType::CommonName, cn);
    dn
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(3650);
    p
}

impl Ca {
    pub fn new_root(cn: &str) -> anyhow::Result<Self> {
        let key = KeyPair::generate()?;
        let params = ca_params(cn);
        let cert = params.self_signed(&key)?;
        Ok(Self { name: cn.into(), cert_pem: cert.pem(), chain_pem: vec![], issuer: Issuer::new(params, key) })
    }

    pub fn new_intermediate(&self, cn: &str) -> anyhow::Result<Self> {
        let key = KeyPair::generate()?;
        let params = ca_params(cn);
        let cert = params.signed_by(&key, &self.issuer)?;
        let mut chain_pem = vec![cert.pem()];
        chain_pem.extend(self.chain_pem.iter().cloned());
        Ok(Self { name: cn.into(), cert_pem: cert.pem(), chain_pem, issuer: Issuer::new(params, key) })
    }

    pub fn issue(&self, spec: &LeafSpec) -> anyhow::Result<Leaf> {
        let key = KeyPair::generate()?;
        let mut p = CertificateParams::default();
        p.distinguished_name = dn(&spec.common_name);
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages =
            vec![if spec.server { ExtendedKeyUsagePurpose::ServerAuth } else { ExtendedKeyUsagePurpose::ClientAuth }];
        for u in &spec.uris {
            p.subject_alt_names.push(SanType::URI(u.clone().try_into()?));
        }
        for d in &spec.dns {
            p.subject_alt_names.push(SanType::DnsName(d.clone().try_into()?));
        }
        for ip in &spec.ips {
            p.subject_alt_names.push(SanType::IpAddress(*ip));
        }
        p.not_before = spec.not_before;
        p.not_after = spec.not_after;
        let cert = p.signed_by(&key, &self.issuer)?;
        let mut chain_pem = cert.pem();
        // Intermediates only: the root is never sent by the client.
        for c in self.chain_pem.iter() {
            chain_pem.push_str(c);
        }
        Ok(Leaf { cert_pem: cert.pem(), chain_pem, key_pem: key.serialize_pem() })
    }
}

/// Writes the demo PKI described in the module docs into `dir`.
pub fn write_demo_pki(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let write = |name: &str, contents: &str| std::fs::write(dir.join(name), contents);

    let v1 = Ca::new_root("Arkion Test Root v1")?;
    let inter = v1.new_intermediate("Arkion Test Issuing CA")?;
    let v2 = Ca::new_root("Arkion Test Root v2")?;
    let untrusted = Ca::new_root("Untrusted Root")?;

    write("ca-v1.crt", &v1.cert_pem)?;
    write("intermediate.crt", &inter.cert_pem)?;
    write("ca-v2.crt", &v2.cert_pem)?;
    write("untrusted-ca.crt", &untrusted.cert_pem)?;
    write("trust-bundle.pem", &v1.cert_pem)?;
    write("trust-bundle-v2.pem", &v2.cert_pem)?;
    write("trust-bundle-v1-v2.pem", &format!("{}{}", v1.cert_pem, v2.cert_pem))?;

    let now = OffsetDateTime::now_utc();
    let mut server = LeafSpec::client("arkion-proxy", &[]);
    server.server = true;
    server.dns = vec!["localhost".into(), "proxy".into(), "arkion-proxy".into()];
    server.ips = vec!["127.0.0.1".parse()?, "::1".parse()?];
    let s = v1.issue(&server)?;
    write("server.crt", &s.chain_pem)?;
    write("server.key", &s.key_pem)?;

    let pay = "spiffe://acme/prod/payment";
    let mut dns = LeafSpec::client("batch", &[]);
    dns.dns = vec!["batch.acme.internal".into()];
    let clients: Vec<(&str, &Ca, LeafSpec)> = vec![
        ("payment", &v1, LeafSpec::client("payment", &[pay])),
        ("reporting", &inter, LeafSpec::client("reporting", &["spiffe://acme/prod/reporting"])),
        ("unknown", &v1, LeafSpec::client("unknown", &["spiffe://acme/prod/unknown"])),
        ("dns", &v1, dns),
        (
            "expired",
            &v1,
            LeafSpec::client("expired", &[pay]).with_validity(now - Duration::days(30), now - Duration::days(1)),
        ),
        (
            "not-yet-valid",
            &v1,
            LeafSpec::client("not-yet-valid", &[pay])
                .with_validity(now + Duration::days(365), now + Duration::days(730)),
        ),
        ("untrusted", &untrusted, LeafSpec::client("untrusted", &[pay])),
        ("malformed-spiffe", &v1, LeafSpec::client("malformed", &["spiffe://acme/prod/../admin"])),
        ("multi-spiffe", &v1, LeafSpec::client("multi", &[pay, "spiffe://acme/prod/reporting"])),
        ("payment-v2", &v2, LeafSpec::client("payment", &[pay])),
    ];
    for (name, ca, spec) in clients {
        let leaf = ca.issue(&spec)?;
        write(&format!("{name}.crt"), &leaf.chain_pem)?;
        write(&format!("{name}.key"), &leaf.key_pem)?;
    }

    #[cfg(unix)]
    for entry in std::fs::read_dir(dir)? {
        use std::os::unix::fs::PermissionsExt;
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "key") {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

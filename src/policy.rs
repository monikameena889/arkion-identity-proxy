//! File-based authorization policy and request-path safety checks.
//!
//! ```yaml
//! policies:
//!   - identity: "spiffe://acme/prod/payment"
//!     allow:
//!       - method: POST
//!         path: "/payments"
//!   - identity: "spiffe://acme/prod/reporting"
//!     allow:
//!       - method: GET
//!         path: "/reports/*"
//! ```
//!
//! Semantics (deliberately small, so they are easy to reason about):
//! - **Default deny.** Only `allow` rules exist; no deny rules, no rule ordering, no priorities.
//! - **Identity**: exact, case-sensitive string match. Each identity may appear once.
//! - **Method**: exact match against a fixed set of uppercase methods. `GET` does not imply `HEAD`.
//! - **Path**: either an exact path (`/payments` matches only `/payments`), or a prefix pattern whose
//!   *last segment is exactly `*`* (`/reports/*` matches `/reports/x` and `/reports/x/y`, never
//!   `/reports`, `/reports/` or `/reportsX`). `*` anywhere else is a load-time error.
//! - Query strings are not part of matching.
//!
//! Requests are matched on the **raw** path exactly as it will be forwarded upstream, after
//! [`check_request_path`] has rejected anything that the upstream could interpret differently
//! (encoded slashes/dots, dot segments, `//`, backslashes...). We reject rather than normalise so
//! that the string we authorise is byte-for-byte the string the upstream receives.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::identity::validate_identity_string;

const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    policies: Vec<PolicyEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEntry {
    identity: String,
    allow: Vec<RuleSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    method: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PathPattern {
    Exact(String),
    /// Stored with its trailing slash, e.g. "/reports/".
    Prefix(String),
}

impl PathPattern {
    fn parse(p: &str) -> Result<Self, String> {
        if !p.starts_with('/') {
            return Err(format!("path '{p}' must start with '/'"));
        }
        if p.bytes().any(|b| !(0x21..0x7f).contains(&b) || matches!(b, b'%' | b'?' | b'#' | b'\\' | b';')) {
            return Err(format!("path '{p}' contains a forbidden character (%, ?, #, \\, ;, space or control)"));
        }
        if p == "/" {
            return Ok(Self::Exact("/".into()));
        }
        let segments: Vec<&str> = p[1..].split('/').collect();
        for (i, seg) in segments.iter().enumerate() {
            let last = i == segments.len() - 1;
            if seg.is_empty() && !last {
                return Err(format!("path '{p}' contains an empty segment"));
            }
            if *seg == "." || *seg == ".." {
                return Err(format!("path '{p}' contains a dot segment"));
            }
            if seg.contains('*') && !(last && *seg == "*") {
                return Err(format!("path '{p}': '*' is only allowed as the entire last segment"));
            }
        }
        match p.strip_suffix('*') {
            Some(prefix) => Ok(Self::Prefix(prefix.to_string())),
            None => Ok(Self::Exact(p.to_string())),
        }
    }

    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(e) => path == e,
            Self::Prefix(prefix) => path.len() > prefix.len() && path.starts_with(prefix.as_str()),
        }
    }

    fn as_str(&self) -> String {
        match self {
            Self::Exact(e) => e.clone(),
            Self::Prefix(p) => format!("{p}*"),
        }
    }
}

#[derive(Debug, Clone)]
struct Rule {
    method: String,
    path: PathPattern,
}

#[derive(Debug, Default)]
pub struct Policy {
    rules: HashMap<String, Vec<Rule>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// `rule` is a human-readable description of the matching rule, e.g. "GET /reports/*".
    Allow {
        rule: String,
    },
    Deny(DenyReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The identity has no entry in the policy.
    UnknownIdentity,
    /// The identity exists but no rule matches method + path.
    NoMatchingRule,
}

impl DenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownIdentity => "no_policy_for_identity",
            Self::NoMatchingRule => "no_matching_rule",
        }
    }
}

impl Policy {
    pub fn from_yaml(text: &str) -> Result<Self, String> {
        let file: PolicyFile = serde_yaml_ng::from_str(text).map_err(|e| format!("invalid policy YAML: {e}"))?;
        let mut rules: HashMap<String, Vec<Rule>> = HashMap::new();
        for entry in file.policies {
            validate_identity_string(&entry.identity)
                .map_err(|e| format!("invalid identity '{}': {e}", entry.identity))?;
            if rules.contains_key(&entry.identity) {
                return Err(format!("identity '{}' appears more than once", entry.identity));
            }
            if entry.allow.is_empty() {
                return Err(format!("identity '{}' has an empty allow list", entry.identity));
            }
            let mut compiled = Vec::with_capacity(entry.allow.len());
            for r in entry.allow {
                if !METHODS.contains(&r.method.as_str()) {
                    return Err(format!("identity '{}': unsupported method '{}'", entry.identity, r.method));
                }
                let path = PathPattern::parse(&r.path).map_err(|e| format!("identity '{}': {e}", entry.identity))?;
                compiled.push(Rule { method: r.method, path });
            }
            rules.insert(entry.identity, compiled);
        }
        Ok(Self { rules })
    }

    pub fn identities(&self) -> usize {
        self.rules.len()
    }

    /// `path` must already have passed [`check_request_path`].
    pub fn evaluate(&self, identity: &str, method: &str, path: &str) -> Decision {
        let Some(rules) = self.rules.get(identity) else {
            return Decision::Deny(DenyReason::UnknownIdentity);
        };
        rules
            .iter()
            .find(|r| r.method == method && r.path.matches(path))
            .map(|r| Decision::Allow { rule: format!("{} {}", r.method, r.path.as_str()) })
            .unwrap_or(Decision::Deny(DenyReason::NoMatchingRule))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PathError(pub &'static str);

/// Rejects request paths that an upstream might interpret differently from the literal string
/// we authorise against. Called before policy evaluation; failures become `400 ambiguous_path`.
pub fn check_request_path(path: &str) -> Result<(), PathError> {
    if !path.starts_with('/') {
        return Err(PathError("path must be origin-form and start with '/'"));
    }
    if path.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'\\' || b == b'#') {
        return Err(PathError("path contains a control character, space, backslash or '#'"));
    }
    let lower = path.to_ascii_lowercase();
    // Encoded '/', '\', '.', NUL: classic traversal / prefix-confusion vectors.
    for enc in ["%2f", "%5c", "%2e", "%00"] {
        if lower.contains(enc) {
            return Err(PathError("path contains an encoded slash, backslash, dot or NUL"));
        }
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() && i != segments.len() - 1 {
            return Err(PathError("path contains an empty segment ('//')"));
        }
        // Treat ';' path parameters the way servlet containers do: "..;x" is still "..".
        let bare = seg.split(';').next().unwrap_or("");
        if bare == "." || bare == ".." {
            return Err(PathError("path contains a dot segment"));
        }
    }
    Ok(())
}

/// Hot-reloadable policy with last-known-good semantics.
pub struct PolicyStore {
    path: PathBuf,
    current: ArcSwap<Policy>,
    generation: AtomicU64,
    status: Mutex<StoreStatus>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StoreStatus {
    pub generation: u64,
    pub sha256: String,
    pub loaded_at: String,
    pub last_error: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReloadOutcome {
    Unchanged,
    Reloaded(u64),
    Rejected(String),
}

impl PolicyStore {
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        let bytes = std::fs::read(&path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let policy = Policy::from_yaml(std::str::from_utf8(&bytes)?).map_err(|e| anyhow::anyhow!(e))?;
        let status = StoreStatus {
            generation: 1,
            sha256: hex::encode(Sha256::digest(&bytes)),
            loaded_at: now(),
            last_error: None,
        };
        Ok(Self {
            path,
            current: ArcSwap::from_pointee(policy),
            generation: AtomicU64::new(1),
            status: Mutex::new(status),
        })
    }

    pub fn current(&self) -> Arc<Policy> {
        self.current.load_full()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn status(&self) -> StoreStatus {
        self.status.lock().unwrap().clone()
    }

    /// Re-reads the file; swaps the policy only if it changed *and* is valid. On a bad file the
    /// previous policy stays active (last-known-good) and the error is reported in status.
    pub fn reload_if_changed(&self) -> ReloadOutcome {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) => return self.reject(format!("reading {}: {e}", self.path.display())),
        };
        let hash = hex::encode(Sha256::digest(&bytes));
        if hash == self.status.lock().unwrap().sha256 {
            return ReloadOutcome::Unchanged;
        }
        let parsed = std::str::from_utf8(&bytes).map_err(|e| e.to_string()).and_then(Policy::from_yaml);
        match parsed {
            Ok(policy) => {
                self.current.store(Arc::new(policy));
                let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
                *self.status.lock().unwrap() =
                    StoreStatus { generation, sha256: hash, loaded_at: now(), last_error: None };
                ReloadOutcome::Reloaded(generation)
            }
            Err(e) => {
                // Remember the bad hash so we don't log the same error every interval.
                let mut st = self.status.lock().unwrap();
                st.sha256 = hash;
                st.last_error = Some(e.clone());
                ReloadOutcome::Rejected(e)
            }
        }
    }

    fn reject(&self, e: String) -> ReloadOutcome {
        self.status.lock().unwrap().last_error = Some(e.clone());
        ReloadOutcome::Rejected(e)
    }
}

pub(crate) fn now() -> String {
    time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
policies:
  - identity: "spiffe://acme/prod/payment"
    allow:
      - method: POST
        path: "/payments"
  - identity: "spiffe://acme/prod/reporting"
    allow:
      - method: GET
        path: "/reports/*"
"#;

    fn policy() -> Policy {
        Policy::from_yaml(POLICY).unwrap()
    }

    #[test]
    fn exact_match() {
        let p = policy();
        let pay = "spiffe://acme/prod/payment";
        assert!(matches!(p.evaluate(pay, "POST", "/payments"), Decision::Allow { .. }));
        for (m, path) in [
            ("GET", "/payments"),
            ("POST", "/payments/"),
            ("POST", "/payments/1"),
            ("POST", "/Payments"),
            ("post", "/payments"),
            ("POST", "/paymentsX"),
        ] {
            assert_eq!(p.evaluate(pay, m, path), Decision::Deny(DenyReason::NoMatchingRule), "{m} {path}");
        }
    }

    #[test]
    fn prefix_match() {
        let p = policy();
        let rep = "spiffe://acme/prod/reporting";
        assert_eq!(p.evaluate(rep, "GET", "/reports/q1"), Decision::Allow { rule: "GET /reports/*".into() });
        assert!(matches!(p.evaluate(rep, "GET", "/reports/2024/q1"), Decision::Allow { .. }));
        for path in ["/reports", "/reports/", "/reportsX", "/reportsX/y", "/other/reports/x"] {
            assert_eq!(p.evaluate(rep, "GET", path), Decision::Deny(DenyReason::NoMatchingRule), "{path}");
        }
        assert_eq!(p.evaluate(rep, "HEAD", "/reports/q1"), Decision::Deny(DenyReason::NoMatchingRule));
    }

    #[test]
    fn unknown_identity_denied() {
        assert_eq!(policy().evaluate("spiffe://acme/prod/x", "GET", "/"), Decision::Deny(DenyReason::UnknownIdentity));
    }

    #[test]
    fn rejects_ambiguous_policies() {
        let bad = [
            (
                "policies:\n  - identity: \"spiffe://acme/a\"\n    allow:\n      - method: GET\n        path: \"/a/*/b\"\n",
                "only allowed",
            ),
            (
                "policies:\n  - identity: \"spiffe://acme/a\"\n    allow:\n      - method: GET\n        path: \"/a*\"\n",
                "only allowed",
            ),
            (
                "policies:\n  - identity: \"spiffe://acme/a\"\n    allow:\n      - method: GET\n        path: \"/a/../b\"\n",
                "dot segment",
            ),
            (
                "policies:\n  - identity: \"spiffe://acme/a\"\n    allow:\n      - method: GET\n        path: \"/a%2fb\"\n",
                "forbidden",
            ),
            (
                "policies:\n  - identity: \"spiffe://acme/a\"\n    allow:\n      - method: get\n        path: \"/a\"\n",
                "unsupported method",
            ),
            (
                "policies:\n  - identity: \"spiffe://acme/a\"\n    allow:\n      - method: GET\n        path: \"a\"\n",
                "must start",
            ),
            (
                "policies:\n  - identity: \"spiffe://ACME/a\"\n    allow:\n      - method: GET\n        path: \"/a\"\n",
                "invalid identity",
            ),
            ("policies:\n  - identity: \"spiffe://acme/a\"\n    allow: []\n", "empty allow"),
            (
                "policies:\n  - identity: \"spiffe://acme/a\"\n    allow:\n      - method: GET\n        path: \"/a\"\n  - identity: \"spiffe://acme/a\"\n    allow:\n      - method: GET\n        path: \"/b\"\n",
                "more than once",
            ),
            (
                "policies:\n  - identity: \"spiffe://acme/a\"\n    alow:\n      - method: GET\n        path: \"/a\"\n",
                "invalid policy YAML",
            ),
        ];
        for (yaml, expected) in bad {
            let err = Policy::from_yaml(yaml).unwrap_err();
            assert!(err.contains(expected), "expected '{expected}' in '{err}'");
        }
    }

    #[test]
    fn request_path_checks() {
        for ok in ["/", "/payments", "/reports/q1", "/reports/q1/", "/a%20b", "/a;v=1"] {
            assert!(check_request_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "/reports/../payments",
            "/reports/./x",
            "/reports/%2e%2e/payments",
            "/reports/%2E%2E/payments",
            "/reports/..%2fpayments",
            "/reports%2fx",
            "/reports/..;/payments",
            "//payments",
            "/reports//x",
            "/reports\\..\\payments",
            "/a%00b",
            "reports",
        ] {
            assert!(check_request_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn store_keeps_last_known_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, POLICY).unwrap();
        let store = PolicyStore::load(path.clone()).unwrap();
        assert_eq!(store.reload_if_changed(), ReloadOutcome::Unchanged);

        std::fs::write(&path, "policies: [oops").unwrap();
        assert!(matches!(store.reload_if_changed(), ReloadOutcome::Rejected(_)));
        assert_eq!(store.generation(), 1);
        assert!(matches!(
            store.current().evaluate("spiffe://acme/prod/payment", "POST", "/payments"),
            Decision::Allow { .. }
        ));
        assert!(store.status().last_error.is_some());

        std::fs::write(&path, POLICY.replace("POST", "PUT")).unwrap();
        assert_eq!(store.reload_if_changed(), ReloadOutcome::Reloaded(2));
        assert!(store.status().last_error.is_none());
        assert!(matches!(
            store.current().evaluate("spiffe://acme/prod/payment", "PUT", "/payments"),
            Decision::Allow { .. }
        ));
    }
}

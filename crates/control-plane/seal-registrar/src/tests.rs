//! The registrar against the real dev log (real inclusion proofs) and a control plane that
//! checks a version 1 the way seal-control does: the registrar's signature and log inclusion.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use seal_crypto::sign::{verify_threshold, SigningKey};
use seal_proto::release::{LogEntry, TlogProof};
use seal_proto::state::{root_id, AdminKey, LoggedRoot, TENANT_ROOT_LABEL};
use seal_proto::{PublicKey, TenantId};
use seal_tlog::dev::DevLog;
use seal_tlog::LogVerifier;

use super::*;

struct Fakes {
    log: Mutex<DevLog>,
    trust: seal_tlog::TlogTrust,
    registrar_key: PublicKey,
    roots: Mutex<BTreeMap<TenantId, LoggedRoot>>,
    fail_log_once: Mutex<bool>,
}

struct Shared(Arc<Fakes>);

#[async_trait]
impl Upstreams for Shared {
    async fn log_append(&self, entry: &LogEntry) -> Result<u64, UpstreamError> {
        let mut fail = self.0.fail_log_once.lock().unwrap();
        if *fail {
            *fail = false;
            return Err(UpstreamError("log down".into()));
        }
        self.0.log.lock().unwrap().append(entry.clone()).map_err(|e| UpstreamError(e.to_string()))
    }
    async fn log_proof(&self, index: u64) -> Result<TlogProof, UpstreamError> {
        Ok(self.0.log.lock().unwrap().prove(index))
    }
    async fn put_root(&self, tenant: &TenantId, root: &LoggedRoot) -> Result<(), UpstreamError> {
        verify_threshold(&[self.0.registrar_key], 1, TENANT_ROOT_LABEL, &root.root)
            .map_err(|e| UpstreamError(format!("signature: {e}")))?;
        LogVerifier::new(self.0.trust.clone())
            .inclusion(&LogEntry::TenantRoot(root.root.body.clone()), &root.proof)
            .map_err(|e| UpstreamError(format!("inclusion: {e}")))?;
        let mut roots = self.0.roots.lock().unwrap();
        match roots.get(tenant) {
            Some(have) if have.root != root.root => Err(UpstreamError("409 version 1 is already in the chain".into())),
            _ => {
                roots.insert(tenant.clone(), root.clone());
                Ok(())
            }
        }
    }
}

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("seal-registrar-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A fresh ledger file of its own.
fn ledger() -> Ledger {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ledger::open(&dir(&format!("ledger-{n}")).join("ledger.jsonl")).unwrap()
}

fn setup(name: &str, ledger: Ledger) -> (Registrar, Arc<Fakes>) {
    let key = SigningKey::from_seed(&[5; 32]);
    let log = DevLog::open(&dir(name), [9; 32], 3, 2).unwrap();
    let fakes = Arc::new(Fakes {
        trust: log.trust(),
        log: Mutex::new(log),
        registrar_key: key.public_key(),
        roots: Mutex::new(BTreeMap::new()),
        fail_log_once: Mutex::new(false),
    });
    let policy = Policy { passkey_rp_id: "seal.zone".into() };
    (Registrar::new(key, policy, Box::new(Shared(fakes.clone())), ledger), fakes)
}

fn passkey(b: u8) -> AdminKey {
    let mut sec1 = vec![4u8];
    sec1.extend([b; 64]);
    AdminKey::WebAuthnEs256 { sec1, rp_id: "seal.zone".into() }
}

#[tokio::test]
async fn creates_a_logged_root_the_control_plane_accepts() {
    let (r, fakes) = setup("create", ledger());
    let got = r.create_root("acme", passkey(1)).await.unwrap();
    let stored = fakes.roots.lock().unwrap().get(&TenantId::new("acme").unwrap()).cloned().unwrap();
    assert_eq!(got.root_id, root_id(&stored.root.body).to_string());
    assert_eq!(got.key_id, seal_crypto::sign::admin_key_id(&passkey(1)).to_string());
    assert_eq!(got.log_index, stored.proof.leaf_index);
    let body = &stored.root.body;
    assert_eq!((body.version, body.threshold, body.cosign_releases), (1, 1, false));
    assert_eq!(body.admin_keys.iter().collect::<Vec<_>>(), vec![&passkey(1)]);
}

#[tokio::test]
async fn retries_are_idempotent_and_other_keys_are_refused() {
    let (r, fakes) = setup("retry", ledger());
    let first = r.create_root("acme", passkey(1)).await.unwrap();
    assert_eq!(r.create_root("acme", passkey(1)).await.unwrap(), first);
    assert_eq!(fakes.log.lock().unwrap().size(), 1, "a retry never logs again");
    assert!(matches!(r.create_root("acme", passkey(2)).await, Err(RegistrarError::Refused(_))));
    assert_eq!(fakes.log.lock().unwrap().size(), 1, "a refused root is never logged");
}

#[tokio::test]
async fn bad_input_is_refused_before_anything_is_logged() {
    let (r, fakes) = setup("bad", ledger());
    assert!(matches!(r.create_root("Not-An-Id", passkey(1)).await, Err(RegistrarError::Refused(_))));
    let other_rp = AdminKey::WebAuthnEs256 { sec1: vec![4; 65], rp_id: "evil.example".into() };
    assert!(matches!(r.create_root("acme", other_rp).await, Err(RegistrarError::Refused(_))));
    let short = AdminKey::WebAuthnEs256 { sec1: vec![4; 33], rp_id: "seal.zone".into() };
    assert!(matches!(r.create_root("acme", short).await, Err(RegistrarError::Refused(_))));
    assert_eq!(fakes.log.lock().unwrap().size(), 0);
}

#[tokio::test]
async fn a_failed_log_append_is_retried_with_the_same_root() {
    let (r, fakes) = setup("crash", ledger());
    *fakes.fail_log_once.lock().unwrap() = true;
    assert!(matches!(r.create_root("acme", passkey(1)).await, Err(RegistrarError::Unavailable(_))));
    // The id is already promised to this key: another key is refused even before the retry.
    assert!(matches!(r.create_root("acme", passkey(2)).await, Err(RegistrarError::Refused(_))));
    r.create_root("acme", passkey(1)).await.unwrap();
    assert_eq!(fakes.log.lock().unwrap().size(), 1);
}

#[tokio::test]
async fn the_ledger_survives_a_restart() {
    let path = dir("ledger").join("ledger.jsonl");
    let (r, _) = setup("ledger-a", Ledger::open(&path).unwrap());
    r.create_root("acme", passkey(1)).await.unwrap();
    drop(r);
    let reopened = Ledger::open(&path).unwrap();
    let rec = reopened.get(&TenantId::new("acme").unwrap()).unwrap();
    assert_eq!(rec.log_index, Some(0));
    // A fresh registrar (fresh log and control plane) still refuses the taken id.
    let (r2, _) = setup("ledger-b", reopened);
    assert!(matches!(r2.create_root("acme", passkey(2)).await, Err(RegistrarError::Refused(_))));
    // A torn last line is cut off, and the next record is a line of its own.
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"{\"tenant\":").unwrap();
    let (r3, _) = setup("ledger-c", Ledger::open(&path).unwrap());
    r3.create_root("other", passkey(3)).await.unwrap();
    let reopened = Ledger::open(&path).unwrap();
    assert!(reopened.get(&TenantId::new("acme").unwrap()).is_some());
    assert!(reopened.get(&TenantId::new("other").unwrap()).is_some());
}

#[test]
fn api_token_is_required() {
    let (r, _) = setup("auth", ledger());
    let app = server::App::new(r, "a-long-enough-api-token");
    let mut h = axum::http::HeaderMap::new();
    assert!(!app.authorized(&h));
    h.insert("authorization", "Bearer wrong".parse().unwrap());
    assert!(!app.authorized(&h));
    h.insert("authorization", "Bearer a-long-enough-api-token".parse().unwrap());
    assert!(app.authorized(&h));
}

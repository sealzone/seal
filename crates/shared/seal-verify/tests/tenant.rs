mod common;

use std::collections::BTreeMap;

use common::{key, Log, T};
use seal_crypto::sign::admin_key_id;
use seal_proto::codec::{digest, labeled_digest};
use seal_proto::identity::WorkloadIdentity;
use seal_proto::integrity::{IntegritySignal, Severity, SignalSource, SignedSignal, SIGNAL_LABEL};
use seal_proto::release::{LogEntry, ServiceKeyCertificate, SERVICE_KEY_CERTIFICATE_LABEL};
use seal_proto::session::{SessionEnd, SignedSessionEnd, SESSION_END_LABEL};
use seal_proto::signed::Signed;
use seal_proto::state::{
    root_id, AdminKey, LoggedRoot, LoggedState, SignedStateFreshness, SignedTenantState, StateFreshness, TenantBundle,
    TenantKeyVersions, TenantRoot, TenantState, STATE_FRESHNESS_LABEL, STATE_FRESHNESS_SECS, TENANT_ROOT_LABEL,
    TENANT_STATE_LABEL,
};
use seal_proto::{
    ErrorCode, KeyId, PlatformId, PublicKey, ServiceKeyVersion, TenantId, TenantKeyVersion, TrustedTime, UnixTime,
};
use seal_tlog::TlogError;
use seal_verify::{verify_service_certificate, TenantTrust, TenantVerifier, VerifiedTenant, VerifyError};

const REGISTRARS: [u8; 3] = [21, 22, 23];
const V1_ADMINS: [u8; 3] = [31, 32, 33];
const V2_ADMINS: [u8; 2] = [34, 35];
const TELEMETRY: u8 = 50;
const EDR: u8 = 51;
const TENANT_FRESHNESS: u8 = 52;
const SECS: u64 = STATE_FRESHNESS_SECS;
/// When the fixtures' documents were logged: past every pending window, so the latest state is
/// known to be in force without older ones.
const EARLY: UnixTime = T - 8 * 86_400;

fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}
fn other() -> TenantId {
    TenantId::new("other").unwrap()
}

fn root(version: u64, admins: &[u8], threshold: u8) -> TenantRoot {
    TenantRoot {
        tenant: acme(),
        version,
        admin_keys: admins.iter().map(|&n| AdminKey::Ed25519 { public_key: key(n).public_key() }).collect(),
        threshold,
        cosign_releases: false,
    }
}

fn signed<T: serde::Serialize>(label: &str, body: T, keys: &[u8]) -> Signed<T> {
    let mut s = Signed { body, signatures: vec![] };
    for &n in keys {
        key(n).cosign(label, &mut s);
    }
    s
}

fn state(version: u64, root_version: u64) -> TenantState {
    let mut integrity = seal_proto::integrity::IntegrityPolicy::default();
    integrity.sources.insert("edr".into(), key(EDR).public_key());
    TenantState {
        tenant: acme(),
        version,
        root_version,
        apps: Default::default(),
        tenant_key_versions: TenantKeyVersions { current: TenantKeyVersion(1), oldest_accepted: TenantKeyVersion(1) },
        platforms: [PlatformId::Sim].into(),
        integrity,
        deployments: Default::default(),
        freshness_keys: Default::default(),
        telemetry_readers: Default::default(),
        issued_at: T,
        pending_window_secs: 0,
        app_networks: Default::default(),
        freshness_secs: None,
    }
}

fn at(t: UnixTime) -> TrustedTime {
    TrustedTime::exact(t)
}

/// Root v1 (admins 31-33, threshold 2, registrar-signed), state 1 on it, root v2 (admins 34-35,
/// threshold 1, signed by 31 and 32) and state 3 on it, all logged.
struct Tenant {
    log: Log,
    v1: Signed<TenantRoot>,
    v2: Signed<TenantRoot>,
    indices: [u64; 2],
    s1: SignedTenantState,
    /// The log's statement for state 1 at `T - SECS`, before state 3 was logged.
    s1_freshness: SignedStateFreshness,
    s3: SignedTenantState,
    s3_index: u64,
}

impl Tenant {
    fn new() -> Self {
        Self::with(2, |_| {})
    }

    fn with(seed: u8, change: impl FnOnce(&mut TenantState)) -> Self {
        let mut log = Log::new(seed);
        let v1 = signed(TENANT_ROOT_LABEL, root(1, &V1_ADMINS, 2), &REGISTRARS[..2]);
        let i1 = log.log.append(LogEntry::TenantRoot(v1.body.clone())).unwrap();
        let s1 = signed(TENANT_STATE_LABEL, state(1, 1), &V1_ADMINS[..2]);
        log.log.append_state(&s1).unwrap();
        let s1_freshness = log.freshness_at(&acme(), T - SECS);
        let v2 = signed(TENANT_ROOT_LABEL, root(2, &V2_ADMINS, 1), &V1_ADMINS[..2]);
        let i2 = log.log.append(LogEntry::TenantRoot(v2.body.clone())).unwrap();
        let mut body = state(3, 2);
        change(&mut body);
        let s3 = signed(TENANT_STATE_LABEL, body, &V2_ADMINS[..1]);
        let s3_index = log.log.append_state(&s3).unwrap();
        Self { log, v1, v2, indices: [i1, i2], s1, s1_freshness, s3, s3_index }
    }

    fn trust(&self) -> TenantTrust {
        TenantTrust {
            tlog: self.log.log.trust(),
            registrar_keys: REGISTRARS.iter().map(|&n| key(n).public_key()).collect(),
            registrar_threshold: 2,
        }
    }

    fn verifier(&self) -> TenantVerifier {
        TenantVerifier::new(self.trust(), vec![key(TELEMETRY).public_key()])
    }

    fn chain(&mut self) -> Vec<LoggedRoot> {
        self.log.checkpoint_at(EARLY);
        vec![
            LoggedRoot { root: self.v1.clone(), proof: self.log.log.prove(self.indices[0]) },
            LoggedRoot { root: self.v2.clone(), proof: self.log.log.prove(self.indices[1]) },
        ]
    }

    /// The full chain, state 3 and the log's statement for it at `T`.
    fn bundle(&mut self) -> TenantBundle {
        let (s3, index) = (self.s3.clone(), self.s3_index);
        self.bundle_of(s3, index)
    }

    /// The full chain and `state` (logged at `index`) public since `EARLY`, the log's statement
    /// for it and a checkpoint at `T`.
    fn bundle_of(&mut self, state: SignedTenantState, index: u64) -> TenantBundle {
        let root_chain = self.chain();
        let logged = LoggedState { state: state.clone(), proof: self.log.log.prove(index) };
        TenantBundle {
            root_chain,
            state,
            signals: vec![],
            ended_sessions: vec![],
            freshness: vec![self.log.freshness_at(&acme(), T)],
            wrap_keys: vec![],
            states: vec![logged],
            checkpoint: Some(self.log.checkpoint_at(T)),
            anchors: Vec::new(),
        }
    }
}

#[test]
fn a_full_bundle_is_accepted() {
    let mut t = Tenant::new();
    let bundle = t.bundle();
    let v = t.verifier().verify(&acme(), &bundle, &at(T + 10)).unwrap();
    assert_eq!(v.root_id(), &root_id(&t.v1.body));
    assert_eq!(v.root(), &t.v2.body);
    assert_eq!(v.state(), &t.s3.body);
    assert_eq!(v.fresh_until(), T + SECS);
    assert!(v.signals().is_empty() && v.ended_sessions().is_empty());
}

#[test]
fn a_chain_of_one_root_is_accepted() {
    let mut log = Log::new(3);
    let v1 = signed(TENANT_ROOT_LABEL, root(1, &V1_ADMINS, 2), &REGISTRARS[1..]);
    let index = log.log.append(LogEntry::TenantRoot(v1.body.clone())).unwrap();
    let s1 = signed(TENANT_STATE_LABEL, state(1, 1), &V1_ADMINS[1..]);
    log.log.append_state(&s1).unwrap();
    let bundle = TenantBundle {
        root_chain: vec![LoggedRoot { root: v1.clone(), proof: log.proof_at(index, T) }],
        state: s1,
        signals: vec![],
        ended_sessions: vec![],
        freshness: vec![log.freshness_at(&acme(), T)],
        wrap_keys: vec![],
        states: Vec::new(),
        checkpoint: None,
        anchors: Vec::new(),
    };
    let trust = TenantTrust {
        tlog: log.log.trust(),
        registrar_keys: REGISTRARS.iter().map(|&n| key(n).public_key()).collect(),
        registrar_threshold: 2,
    };
    let v = TenantVerifier::new(trust, vec![]).verify(&acme(), &bundle, &at(T)).unwrap();
    assert_eq!(v.root(), &v1.body);
    assert_eq!(v.root_id(), &root_id(&v1.body));
}

fn chain_error(t: &Tenant, bundle: &TenantBundle) -> VerifyError {
    t.verifier().verify(&acme(), bundle, &at(T + 10)).unwrap_err()
}

fn is_chain_error(e: VerifyError) -> bool {
    matches!(e, VerifyError::RootChain(_))
}

#[test]
fn version_1_needs_the_registrar_threshold() {
    let mut t = Tenant::new();
    let good = t.bundle();
    let resign = |keys: &[u8]| {
        let mut b = good.clone();
        b.root_chain[0].root = signed(TENANT_ROOT_LABEL, t.v1.body.clone(), keys);
        b
    };
    assert!(is_chain_error(chain_error(&t, &resign(&[21]))), "short by one");
    assert!(is_chain_error(chain_error(&t, &resign(&[21, 77]))), "an unknown registrar");
    assert!(is_chain_error(chain_error(&t, &resign(&[31, 32]))), "admins are not registrars");
    let mut dup = resign(&[21]);
    let sig = dup.root_chain[0].root.signatures[0].clone();
    dup.root_chain[0].root.signatures.push(sig);
    assert!(is_chain_error(chain_error(&t, &dup)), "the same registrar twice");
    let mut forged = resign(&[21]);
    forged.root_chain[0].root.signatures.push(key(22).sign(TENANT_ROOT_LABEL, &root(1, &[22], 1)));
    assert!(is_chain_error(chain_error(&t, &forged)), "a signature over another root");
    t.verifier().verify(&acme(), &resign(&[22, 23]), &at(T + 10)).unwrap();
}

#[test]
fn later_links_need_the_previous_roots_threshold() {
    let mut t = Tenant::new();
    let good = t.bundle();
    let resign = |keys: &[u8]| {
        let mut b = good.clone();
        b.root_chain[1].root = signed(TENANT_ROOT_LABEL, t.v2.body.clone(), keys);
        b
    };
    assert!(is_chain_error(chain_error(&t, &resign(&[31]))), "one of two");
    assert!(is_chain_error(chain_error(&t, &resign(&[34, 35]))), "its own admins");
    assert!(is_chain_error(chain_error(&t, &resign(&[31, 77]))), "an unknown key");
    assert!(is_chain_error(chain_error(&t, &resign(&[21, 22]))), "registrars after version 1");
    let mut dup = resign(&[31]);
    let sig = dup.root_chain[1].root.signatures[0].clone();
    dup.root_chain[1].root.signatures.push(sig);
    assert!(is_chain_error(chain_error(&t, &dup)), "the same admin twice");
    t.verifier().verify(&acme(), &resign(&[33, 32]), &at(T + 10)).unwrap();
}

#[test]
fn reordered_gapped_or_rootless_chains_are_refused() {
    let mut t = Tenant::new();
    let good = t.bundle();
    let with_chain = |chain: Vec<LoggedRoot>| TenantBundle { root_chain: chain, ..good.clone() };
    let [l1, l2] = [good.root_chain[0].clone(), good.root_chain[1].clone()];
    assert!(is_chain_error(chain_error(&t, &with_chain(vec![]))), "empty");
    assert!(is_chain_error(chain_error(&t, &with_chain(vec![l2.clone()]))), "no version 1");
    assert!(is_chain_error(chain_error(&t, &with_chain(vec![l2.clone(), l1.clone()]))), "reordered");
    assert!(is_chain_error(chain_error(&t, &with_chain(vec![l1.clone(), l1.clone(), l2.clone()]))), "repeated");
    let mut v3 = l2.clone();
    v3.root.body.version = 3;
    assert!(is_chain_error(chain_error(&t, &with_chain(vec![l1, v3]))), "a gap");
}

#[test]
fn every_link_must_be_logged() {
    let mut t = Tenant::new();
    let good = t.bundle();
    let mut wrong_proof = good.clone();
    wrong_proof.root_chain[1].proof = good.root_chain[0].proof.clone();
    assert_eq!(chain_error(&t, &wrong_proof), VerifyError::Log(TlogError::BadInclusion));
    // A validly signed version 2 that was never logged.
    let mut unlogged = good.clone();
    unlogged.root_chain[1].root = signed(TENANT_ROOT_LABEL, root(2, &[36], 1), &V1_ADMINS[..2]);
    assert_eq!(chain_error(&t, &unlogged), VerifyError::Log(TlogError::BadInclusion));
    let mut unlogged_v1 = good;
    unlogged_v1.root_chain[0].root = signed(TENANT_ROOT_LABEL, root(1, &[36], 1), &REGISTRARS[..2]);
    assert_eq!(chain_error(&t, &unlogged_v1), VerifyError::Log(TlogError::BadInclusion));
}

#[test]
fn a_bundle_for_another_tenant_is_refused() {
    let mut t = Tenant::new();
    let bundle = t.bundle();
    assert_eq!(t.verifier().verify(&other(), &bundle, &at(T + 10)).unwrap_err(), VerifyError::WrongTenant);
    let mut other_state = bundle;
    other_state.state.body.tenant = other();
    assert_eq!(chain_error(&t, &other_state), VerifyError::WrongTenant);
}

#[test]
fn the_state_must_be_signed_by_the_latest_root_for_its_version() {
    let mut t = Tenant::new();
    let good = t.bundle();
    let with_state = |s: SignedTenantState| TenantBundle { state: s, ..good.clone() };
    let is_state_error = |e: VerifyError| matches!(e, VerifyError::State(_));
    // For root version 1, while the chain ends at 2.
    let old_root = signed(TENANT_STATE_LABEL, state(4, 1), &V1_ADMINS[..2]);
    assert!(is_state_error(chain_error(&t, &with_state(old_root))));
    // For root version 2 but signed by version 1's admins.
    let old_admins = signed(TENANT_STATE_LABEL, state(3, 2), &V1_ADMINS[..2]);
    assert!(is_state_error(chain_error(&t, &with_state(old_admins))));
    // Unsigned, or signed by an outsider.
    assert!(is_state_error(chain_error(&t, &with_state(signed(TENANT_STATE_LABEL, state(3, 2), &[])))));
    assert!(is_state_error(chain_error(&t, &with_state(signed(TENANT_STATE_LABEL, state(3, 2), &[77])))));
    // A truncated chain makes the latest state name a root the chain does not reach.
    let mut truncated = good.clone();
    truncated.root_chain.truncate(1);
    assert!(is_state_error(chain_error(&t, &truncated)));
}

#[test]
fn a_truncated_chain_with_an_old_state_is_not_fresh() {
    let mut t = Tenant::new();
    let mut bundle = t.bundle();
    bundle.root_chain.truncate(1);
    bundle.state = t.s1.clone();
    bundle.states.clear();
    // The log signs only for its latest state now; its old statement for state 1 has run out.
    assert_eq!(chain_error(&t, &bundle), VerifyError::StateNotFresh);
    bundle.freshness.push(t.s1_freshness.clone());
    assert_eq!(chain_error(&t, &bundle), VerifyError::StateNotFresh);
    // Within its window it still worked (the documented freshness limit).
    t.verifier().verify(&acme(), &bundle, &at(T - 1)).unwrap();
}

#[test]
fn the_log_freshness_statement_must_be_current_and_for_exactly_this_state() {
    let mut t = Tenant::new();
    let good = t.bundle();
    let v = t.verifier();
    let with = |freshness: Vec<SignedStateFreshness>| TenantBundle { freshness, ..good.clone() };
    let not_fresh = Err(VerifyError::StateNotFresh);

    assert_eq!(v.verify(&acme(), &with(vec![]), &at(T)).map(|_| ()), not_fresh);
    // Stale by one second, and by clock uncertainty.
    assert_eq!(v.verify(&acme(), &good, &at(T + SECS)).map(|_| ()), not_fresh);
    assert_eq!(v.verify(&acme(), &good, &TrustedTime { now: T + SECS - 1, radius: 1 }).map(|_| ()), not_fresh);
    assert_eq!(v.verify(&acme(), &good, &at(T + SECS - 1)).unwrap().fresh_until(), T + SECS);

    let statement = &good.freshness[0];
    let mut other_version = statement.body.clone();
    other_version.version = 1;
    let mut other_digest = statement.body.clone();
    other_digest.digest = labeled_digest(TENANT_STATE_LABEL, &t.s1.body);
    let mut other_tenant = statement.body.clone();
    other_tenant.tenant = other();
    let log_key =
        Signed { body: statement.body.clone(), signatures: vec![key(5).sign(STATE_FRESHNESS_LABEL, &statement.body)] };
    for (what, bad) in [
        ("signed by another key", log_key),
        ("another version", Signed { body: other_version, signatures: statement.signatures.clone() }),
        ("another digest", Signed { body: other_digest, signatures: statement.signatures.clone() }),
        ("another tenant", Signed { body: other_tenant, signatures: statement.signatures.clone() }),
    ] {
        assert_eq!(v.verify(&acme(), &with(vec![bad]), &at(T)).map(|_| ()), not_fresh, "{what}");
    }

    // The latest valid statement counts, wherever it sits.
    let later = t.log.freshness_at(&acme(), T + 50);
    let both = with(vec![later, statement.clone()]);
    assert_eq!(v.verify(&acme(), &both, &at(T + SECS + 10)).unwrap().fresh_until(), T + 50 + SECS);

    // A statement dated in the future (signed in advance) never counts, alone or next to a
    // current one.
    let ahead = t.log.freshness_at(&acme(), T + 1000);
    assert_eq!(v.verify(&acme(), &with(vec![ahead.clone()]), &at(T)).map(|_| ()), not_fresh);
    let mixed = with(vec![ahead, statement.clone()]);
    assert_eq!(v.verify(&acme(), &mixed, &at(T)).unwrap().fresh_until(), T + SECS);
}

fn tenant_statement(t: &Tenant, signer: u8, signed_at: UnixTime) -> SignedStateFreshness {
    let body = StateFreshness {
        tenant: acme(),
        version: t.s3.body.version,
        digest: labeled_digest(TENANT_STATE_LABEL, &t.s3.body),
        signed_at,
    };
    signed(STATE_FRESHNESS_LABEL, body, &[signer])
}

#[test]
fn a_state_with_freshness_keys_also_needs_a_tenant_statement() {
    let mut t = Tenant::with(4, |s| {
        s.freshness_keys.insert(key(TENANT_FRESHNESS).public_key());
    });
    let log_only = t.bundle();
    let v = t.verifier();
    let now = at(T + 10);
    assert_eq!(v.verify(&acme(), &log_only, &now).unwrap_err(), VerifyError::StateNotFresh);

    let with_tenant = |s: SignedStateFreshness| {
        let mut b = log_only.clone();
        b.freshness.push(s);
        b
    };
    let ok = v.verify(&acme(), &with_tenant(tenant_statement(&t, TENANT_FRESHNESS, T - 100)), &now).unwrap();
    assert_eq!(ok.fresh_until(), T - 100 + SECS, "the earlier expiry of the two");
    let ok = v.verify(&acme(), &with_tenant(tenant_statement(&t, TENANT_FRESHNESS, T + 5)), &now).unwrap();
    assert_eq!(ok.fresh_until(), T + SECS);
    assert_eq!(
        v.verify(&acme(), &with_tenant(tenant_statement(&t, TENANT_FRESHNESS, T + 10 - SECS)), &now).unwrap_err(),
        VerifyError::StateNotFresh,
        "a stale tenant statement"
    );
    assert_eq!(
        v.verify(&acme(), &with_tenant(tenant_statement(&t, 77, T)), &now).unwrap_err(),
        VerifyError::StateNotFresh,
        "a key the state does not name"
    );
    // The tenant's statement does not replace the log's.
    let mut tenant_only = with_tenant(tenant_statement(&t, TENANT_FRESHNESS, T));
    tenant_only.freshness.remove(0);
    assert_eq!(v.verify(&acme(), &tenant_only, &now).unwrap_err(), VerifyError::StateNotFresh);
    // One statement may carry both signatures.
    let mut cosigned = log_only.freshness[0].clone();
    key(TENANT_FRESHNESS).cosign(STATE_FRESHNESS_LABEL, &mut cosigned);
    let both = TenantBundle { freshness: vec![cosigned], ..log_only.clone() };
    assert_eq!(v.verify(&acme(), &both, &now).unwrap().fresh_until(), T + SECS);
}

#[test]
fn a_tenants_freshness_window_applies_to_the_log_and_tenant_statements() {
    const WINDOW: u64 = 600;
    let mut t = Tenant::with(5, |s| {
        s.freshness_secs = Some(WINDOW);
        s.freshness_keys.insert(key(TENANT_FRESHNESS).public_key());
    });
    let mut bundle = t.bundle();
    bundle.freshness.push(tenant_statement(&t, TENANT_FRESHNESS, T));
    let v = t.verifier();
    assert_eq!(v.verify(&acme(), &bundle, &at(T + WINDOW - 1)).unwrap().fresh_until(), T + WINDOW);
    // Statements older than the window, though well within 24 h, keep nothing alive.
    assert_eq!(v.verify(&acme(), &bundle, &at(T + WINDOW)).unwrap_err(), VerifyError::StateNotFresh);

    // A fresh log statement, as the log signs on demand, with a tenant one past the window.
    let log_now = t.log.freshness_at(&acme(), T + 3 * WINDOW);
    let stale_tenant = TenantBundle { freshness: vec![log_now.clone(), bundle.freshness[1].clone()], ..bundle.clone() };
    assert_eq!(v.verify(&acme(), &stale_tenant, &at(T + 3 * WINDOW)).unwrap_err(), VerifyError::StateNotFresh);
    let tenant_now = tenant_statement(&t, TENANT_FRESHNESS, T + 3 * WINDOW - 100);
    let fresh = TenantBundle { freshness: vec![log_now, tenant_now], ..bundle };
    let ok = v.verify(&acme(), &fresh, &at(T + 3 * WINDOW)).unwrap();
    assert_eq!(ok.fresh_until(), T + 4 * WINDOW - 100, "the earlier of the two, by the tenant's window");
}

fn signal(tenant: TenantId, source: SignalSource, code: &str, n: u8) -> IntegritySignal {
    IntegritySignal {
        tenant,
        identity: WorkloadIdentity::AppKey { key_id: KeyId([n; 32]) },
        source,
        code: code.into(),
        severity: Severity::High,
        observed_at: T,
        blob_id: None,
    }
}

fn enclave() -> SignalSource {
    SignalSource::Enclave { detector: "sqli".into() }
}
fn edr() -> SignalSource {
    SignalSource::External { source: "edr".into() }
}

#[test]
fn junk_signals_are_dropped_and_valid_ones_kept_once() {
    let mut t = Tenant::new();
    let mut bundle = t.bundle();
    let good_enclave = signal(acme(), enclave(), "sqli", 1);
    let good_sdk = signal(acme(), SignalSource::Sdk, "self-signal", 2);
    let good_edr = signal(acme(), edr(), "edr-high", 3);
    let s = |body: IntegritySignal, keys: &[u8]| -> SignedSignal { signed(SIGNAL_LABEL, body, keys) };
    bundle.signals = vec![
        s(good_enclave.clone(), &[TELEMETRY]),
        s(good_enclave.clone(), &[TELEMETRY]),
        s(signal(acme(), enclave(), "Bad Code", 4), &[TELEMETRY]),
        s(signal(acme(), enclave(), "", 4), &[TELEMETRY]),
        s(signal(other(), enclave(), "sqli", 4), &[TELEMETRY]),
        s(signal(acme(), enclave(), "sqli", 4), &[]),
        s(signal(acme(), enclave(), "sqli", 4), &[77]),
        s(signal(acme(), enclave(), "sqli", 4), &[EDR]),
        s(signal(acme(), SignalSource::Sdk, "self-signal", 4), &[EDR]),
        s(signal(acme(), edr(), "edr-high", 4), &[TELEMETRY]),
        s(signal(acme(), SignalSource::External { source: "unknown".into() }, "edr-high", 4), &[EDR]),
        Signed {
            body: signal(acme(), enclave(), "sqli", 4),
            signatures: vec![key(TELEMETRY).sign(SESSION_END_LABEL, &signal(acme(), enclave(), "sqli", 4))],
        },
        s(good_sdk.clone(), &[77, TELEMETRY]),
        s(good_edr.clone(), &[EDR]),
        s(good_edr.clone(), &[EDR, TELEMETRY]),
    ];
    let v = t.verifier().verify(&acme(), &bundle, &at(T + 10)).unwrap();
    assert_eq!(v.signals(), &[good_enclave, good_sdk, good_edr]);
}

fn end(tenant: TenantId, n: u8, ended_at: UnixTime) -> SessionEnd {
    SessionEnd { tenant, session_id: [n; 16], reason: ErrorCode::SessionEnded, ended_at }
}

#[test]
fn junk_session_ends_are_dropped_and_valid_ones_kept_once_per_session() {
    let mut t = Tenant::new();
    let mut bundle = t.bundle();
    let s = |body: SessionEnd, label: &str, keys: &[u8]| -> SignedSessionEnd { signed(label, body, keys) };
    bundle.ended_sessions = vec![
        s(end(acme(), 1, T), SESSION_END_LABEL, &[TELEMETRY]),
        s(end(acme(), 1, T + 5), SESSION_END_LABEL, &[TELEMETRY]),
        s(end(acme(), 2, T), SESSION_END_LABEL, &[]),
        s(end(acme(), 2, T), SESSION_END_LABEL, &[77]),
        s(end(acme(), 2, T), SIGNAL_LABEL, &[TELEMETRY]),
        s(end(acme(), 2, T), SESSION_END_LABEL, &[EDR]),
        s(end(other(), 2, T), SESSION_END_LABEL, &[TELEMETRY]),
        s(end(acme(), 3, T), SESSION_END_LABEL, &[77, TELEMETRY]),
    ];
    let v = t.verifier().verify(&acme(), &bundle, &at(T + 10)).unwrap();
    assert_eq!(v.ended_sessions(), &[end(acme(), 1, T), end(acme(), 3, T)]);
    assert_eq!(v.session_end(&[1; 16]), Some(&end(acme(), 1, T)));
    assert_eq!(v.session_end(&[2; 16]), None);
}

#[test]
fn admin_signatures_count_distinct_matched_keys() {
    let r = root(1, &V1_ADMINS, 2);
    let label = "seal/test/v1";
    let check = |keys: &[u8]| TenantVerifier::verify_admin_signed(&r, label, &signed(label, 7u32, keys));
    check(&[31, 32]).unwrap();
    check(&[33, 77, 31]).unwrap();
    assert!(matches!(check(&[31]), Err(VerifyError::State(_))));
    assert!(matches!(check(&[31, 77]), Err(VerifyError::State(_))));
    let mut dup = signed(label, 7u32, &[31]);
    dup.signatures.push(dup.signatures[0].clone());
    assert!(TenantVerifier::verify_admin_signed(&r, label, &dup).is_err());
    // A signature is found by `admin_key_id`, so naming the key any other way does not count.
    let admin = AdminKey::Ed25519 { public_key: key(32).public_key() };
    assert_eq!(admin_key_id(&admin), key(32).key_id());
    let mut renamed = signed(label, 7u32, &[31, 32]);
    renamed.signatures[1].signer = KeyId(digest(&admin));
    assert!(TenantVerifier::verify_admin_signed(&r, label, &renamed).is_err());
    // Another label.
    assert!(TenantVerifier::verify_admin_signed(&r, "seal/other/v1", &signed(label, 7u32, &[31, 32])).is_err());
    // A threshold of 0 accepts nothing.
    let zero = root(1, &V1_ADMINS, 0);
    assert!(TenantVerifier::verify_admin_signed(&zero, label, &signed(label, 7u32, &[31, 32])).is_err());
}

fn verified(t: &mut Tenant, bundle: &TenantBundle) -> VerifiedTenant {
    t.verifier().verify(&acme(), bundle, &at(T + 100)).unwrap()
}

#[test]
fn merge_keeps_the_newer_state_and_unions_signals_and_ends() {
    let mut t = Tenant::new();
    let mut b3 = t.bundle();
    let shared = signed(SIGNAL_LABEL, signal(acme(), enclave(), "sqli", 1), &[TELEMETRY]);
    b3.signals = vec![shared.clone(), signed(SIGNAL_LABEL, signal(acme(), enclave(), "sqli", 2), &[TELEMETRY])];
    b3.ended_sessions = vec![signed(SESSION_END_LABEL, end(acme(), 1, T), &[TELEMETRY])];
    let v3 = verified(&mut t, &b3);

    // The same state with a later statement: the later `fresh_until` wins either way.
    let mut later = b3.clone();
    later.freshness = vec![t.log.freshness_at(&acme(), T + 50)];
    later.signals = vec![];
    let v3_later = verified(&mut t, &later);
    let mut a = v3.clone();
    a.merge(v3_later.clone()).unwrap();
    assert_eq!(a.fresh_until(), T + 50 + SECS);
    assert_eq!(a.signals(), v3.signals(), "merging drops no signal");
    let mut b = v3_later.clone();
    b.merge(v3.clone()).unwrap();
    assert_eq!(b.fresh_until(), T + 50 + SECS);
    assert_eq!(b.signals().len(), 2);

    // A newer state, logged later, with an earlier statement than the cached one's.
    let s4 = signed(TENANT_STATE_LABEL, state(4, 2), &V2_ADMINS[1..]);
    let s4_index = t.log.log.append_state(&s4).unwrap();
    let mut b4 = t.bundle_of(s4.clone(), s4_index);
    b4.freshness = vec![t.log.freshness_at(&acme(), T + 20)];
    b4.signals = vec![shared, signed(SIGNAL_LABEL, signal(acme(), enclave(), "sqli", 3), &[TELEMETRY])];
    b4.ended_sessions = vec![
        signed(SESSION_END_LABEL, end(acme(), 1, T + 9), &[TELEMETRY]),
        signed(SESSION_END_LABEL, end(acme(), 2, T), &[TELEMETRY]),
    ];
    let v4 = verified(&mut t, &b4);
    let mut merged = v3_later.clone();
    merged.merge(v4.clone()).unwrap();
    assert_eq!(merged.state(), &s4.body);
    assert_eq!(merged.fresh_until(), T + 20 + SECS, "one state's freshness does not carry over");
    let codes: Vec<KeyId> = merged
        .signals()
        .iter()
        .map(|s| match &s.identity {
            WorkloadIdentity::AppKey { key_id } => *key_id,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(codes, vec![KeyId([1; 32]), KeyId([3; 32])]);
    let mut all = v3.clone();
    all.merge(v4.clone()).unwrap();
    assert_eq!(all.signals().len(), 3);
    assert_eq!(all.ended_sessions(), &[end(acme(), 1, T), end(acme(), 2, T)]);

    // Rollback: an older state into a newer cache.
    let mut cache = v4.clone();
    let before = format!("{cache:?}");
    assert!(matches!(cache.merge(v3.clone()), Err(VerifyError::State(_))));
    assert_eq!(format!("{cache:?}"), before, "unchanged on error");
}

#[test]
fn merge_refuses_another_root_id_and_equivocation() {
    let mut t = Tenant::new();
    let b = t.bundle();
    let v = verified(&mut t, &b);

    // A competing root v1 for the same name, from the same registrar.
    let mut competing = Log::new(2);
    let c1 = signed(TENANT_ROOT_LABEL, root(1, &[36], 1), &REGISTRARS[..2]);
    let index = competing.log.append(LogEntry::TenantRoot(c1.body.clone())).unwrap();
    let cs = signed(TENANT_STATE_LABEL, state(1, 1), &[36]);
    competing.log.append_state(&cs).unwrap();
    let bundle = TenantBundle {
        root_chain: vec![LoggedRoot { root: c1, proof: competing.proof_at(index, T) }],
        state: cs,
        signals: vec![],
        ended_sessions: vec![],
        freshness: vec![competing.freshness_at(&acme(), T)],
        wrap_keys: vec![],
        states: Vec::new(),
        checkpoint: None,
        anchors: Vec::new(),
    };
    let rival = t.verifier().verify(&acme(), &bundle, &at(T + 100)).unwrap();
    assert_ne!(rival.root_id(), v.root_id());
    let mut cache = v.clone();
    assert!(matches!(cache.merge(rival), Err(VerifyError::RootChain(_))));

    // Another state 3 on the same chain (the same keys running a second log).
    let mut twin = Tenant::with(2, |s| s.issued_at = T + 1);
    let tb = twin.bundle();
    let twin_v = verified(&mut twin, &tb);
    assert_eq!(twin_v.root_id(), v.root_id());
    let mut cache = v.clone();
    assert!(matches!(cache.merge(twin_v), Err(VerifyError::State(_))));

    // Same root id and state: fine.
    let mut cache = v.clone();
    cache.merge(v.clone()).unwrap();
}

#[test]
fn service_key_certificates_need_their_platforms_guardian() {
    let guardian = key(60);
    let guardians: BTreeMap<PlatformId, PublicKey> = [(PlatformId::Sim, guardian.public_key())].into();
    let body = ServiceKeyCertificate {
        platform: PlatformId::Sim,
        tenant: acme(),
        root_id: seal_proto::TenantRootId([1; 32]),
        service_key_version: ServiceKeyVersion(1),
        tls_spki_sha256: [2; 32],
        ingest_public_key: PublicKey([3; 32]),
        telemetry_public_keys: vec![(ServiceKeyVersion(1), PublicKey([4; 32]))],
    };
    let cert = guardian.sign_into(SERVICE_KEY_CERTIFICATE_LABEL, body.clone());
    assert_eq!(verify_service_certificate(&guardians, &cert).unwrap(), &body);

    let is_cert_error = |r: Result<&ServiceKeyCertificate, VerifyError>| matches!(r, Err(VerifyError::Certificate(_)));
    let wrong_key = key(61).sign_into(SERVICE_KEY_CERTIFICATE_LABEL, body.clone());
    assert!(is_cert_error(verify_service_certificate(&guardians, &wrong_key)));
    let wrong_label = guardian.sign_into(SIGNAL_LABEL, body.clone());
    assert!(is_cert_error(verify_service_certificate(&guardians, &wrong_label)));
    let mut other_platform = body.clone();
    other_platform.platform = PlatformId::AwsNitro;
    let other_platform = guardian.sign_into(SERVICE_KEY_CERTIFICATE_LABEL, other_platform);
    assert!(is_cert_error(verify_service_certificate(&guardians, &other_platform)));
    let mut tampered = cert;
    tampered.body.service_key_version = ServiceKeyVersion(2);
    assert!(is_cert_error(verify_service_certificate(&guardians, &tampered)));
}

/// Versions below the platform's `min_service_key_version` sign nothing that counts, for
/// readers too: their keys drop out, and a certificate of a retired version is a finding.
#[test]
fn telemetry_keys_of_retired_service_key_versions_count_for_nothing() {
    use seal_proto::release::ReleaseConstraints;
    use seal_verify::telemetry::{certified_keys, Finding};
    use seal_verify::{telemetry_floor, telemetry_keys_in_force};
    let guardian = key(60);
    let guardians: BTreeMap<PlatformId, PublicKey> = [(PlatformId::Sim, guardian.public_key())].into();
    let cert = |v: u32| ServiceKeyCertificate {
        platform: PlatformId::Sim,
        tenant: acme(),
        root_id: seal_proto::TenantRootId([1; 32]),
        service_key_version: ServiceKeyVersion(v),
        tls_spki_sha256: [2; 32],
        ingest_public_key: PublicKey([3; 32]),
        telemetry_public_keys: (1..=v).map(|i| (ServiceKeyVersion(i), PublicKey([i as u8; 32]))).collect(),
    };
    let floor = |min: u32| ReleaseConstraints {
        min_service_key_version: [(PlatformId::Sim, ServiceKeyVersion(min))].into(),
        ..Default::default()
    };
    let v3 = cert(3);
    assert_eq!(telemetry_keys_in_force(&v3, Some(&ReleaseConstraints::default())).len(), 3);
    assert_eq!(telemetry_keys_in_force(&v3, Some(&floor(2))), [PublicKey([2; 32]), PublicKey([3; 32])]);
    // Another platform's floor retires nothing here.
    let mut aws = floor(3);
    aws.min_service_key_version = [(PlatformId::AwsNitro, ServiceKeyVersion(3))].into();
    assert_eq!(telemetry_floor(&v3, Some(&aws)), ServiceKeyVersion(0));
    // With no policy known, only the certificate's own version.
    assert_eq!(telemetry_keys_in_force(&v3, None), [PublicKey([3; 32])]);

    let signed = |c: ServiceKeyCertificate| guardian.sign_into(SERVICE_KEY_CERTIFICATE_LABEL, c);
    let root_id = seal_proto::TenantRootId([1; 32]);
    let certificates = [signed(cert(1)), signed(cert(3))];
    let (keys, findings) = certified_keys(&guardians, &acme(), &root_id, &certificates, Some(&floor(2)));
    assert_eq!(keys, [PublicKey([2; 32]), PublicKey([3; 32])]);
    assert!(matches!(&findings[..], [Finding::CertificateIgnored { index: 0, reason }] if reason.contains("retired")));
    let (keys, findings) = certified_keys(&guardians, &acme(), &root_id, &certificates, None);
    assert_eq!((keys, findings), (vec![PublicKey([1; 32]), PublicKey([3; 32])], vec![]));
}

/// A passkey's WebAuthn assertion over `labeled_digest(label, body)`, origin `https://seal.zone`.
fn passkey_sign<T: serde::Serialize>(n: u8, label: &str, body: &T) -> (AdminKey, seal_proto::signed::Signature) {
    use p256::ecdsa::signature::Signer as _;
    use sha2::{Digest, Sha256};
    let signing = p256::ecdsa::SigningKey::from_slice(&[n; 32]).unwrap();
    let sec1 = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let admin = AdminKey::WebAuthnEs256 { sec1, rp_id: "seal.zone".into() };
    let mut authenticator_data = Sha256::digest(b"seal.zone").to_vec();
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&1u32.to_be_bytes());
    let challenge = seal_proto::codec::b64url(&labeled_digest(label, body));
    let client_data_json =
        format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://seal.zone"}}"#).into_bytes();
    let signed = [&authenticator_data[..], &Sha256::digest(&client_data_json)[..]].concat();
    let sig: p256::ecdsa::DerSignature = signing.sign(&signed);
    let signature = seal_proto::signed::Signature {
        signer: admin_key_id(&admin),
        alg: seal_proto::signed::SigAlg::WebAuthnEs256 {
            authenticator_data,
            client_data_json,
            sig: sig.as_bytes().to_vec(),
        },
    };
    (admin, signature)
}

#[test]
fn passkeys_count_when_named_by_their_admin_key_id() {
    let label = TENANT_STATE_LABEL;
    let body = state(3, 1);
    let (passkey, passkey_sig) = passkey_sign(0x42, label, &body);
    let mut r = root(1, &[31], 2);
    r.admin_keys.insert(passkey.clone());
    let mut s = signed(label, body.clone(), &[31]);
    s.signatures.push(passkey_sig.clone());
    TenantVerifier::verify_admin_signed(&r, label, &s).unwrap();

    // Named any other way, it does not count.
    let AdminKey::WebAuthnEs256 { sec1, .. } = &passkey else { unreachable!() };
    let mut renamed = s.clone();
    renamed.signatures[1].signer = KeyId(<[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(sec1)));
    assert!(TenantVerifier::verify_admin_signed(&r, label, &renamed).is_err());
    // Twice is once.
    let mut twice = signed(label, body.clone(), &[]);
    twice.signatures = vec![passkey_sig.clone(), passkey_sig];
    assert!(TenantVerifier::verify_admin_signed(&r, label, &twice).is_err());
    // A passkey the root does not list.
    let (_, stranger) = passkey_sign(0x43, label, &body);
    let mut unknown = signed(label, body, &[31]);
    unknown.signatures.push(stranger);
    assert!(TenantVerifier::verify_admin_signed(&r, label, &unknown).is_err());
}

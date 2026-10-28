//! The pending window: which state is in force, from real log proofs with pinned witness times.

mod common;

use common::{key, Log, T};
use seal_proto::identity::IdentityMatcher;
use seal_proto::release::LogEntry;
use seal_proto::signed::Signed;
use seal_proto::state::{
    AdminKey, LoggedRoot, LoggedState, SignedTenantState, TenantAnchor, TenantBundle, TenantKeyVersions, TenantRoot,
    TenantState, MAX_PENDING_WINDOW_SECS, TENANT_ANCHOR_LABEL, TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::{KeyId, PlatformId, PublicKey, TenantId, TenantKeyVersion, TrustedTime, UnixTime};
use seal_verify::{Change, TenantTrust, TenantVerifier, VerifiedTenant, VerifyError};

const REGISTRAR: u8 = 21;
const ADMINS: [u8; 2] = [31, 32];
const NEW_ADMIN: u8 = 33;
const HOUR: u64 = 3_600;

fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn signed<B: serde::Serialize>(label: &str, body: B, keys: &[u8]) -> Signed<B> {
    let mut s = Signed { body, signatures: vec![] };
    for &n in keys {
        key(n).cosign(label, &mut s);
    }
    s
}

fn producer(n: u8) -> IdentityMatcher {
    IdentityMatcher::AppKey { key_id: KeyId([n; 32]), public_key: PublicKey([n; 32]) }
}

fn admin(n: u8) -> AdminKey {
    AdminKey::Ed25519 { public_key: key(n).public_key() }
}

/// A tenant with a one-hour window whose documents are logged at chosen witness times.
struct Tenant {
    log: Log,
    roots: Vec<LoggedRoot>,
    states: Vec<LoggedState>,
    signers: Vec<u8>,
}

impl Tenant {
    /// Root v1 (admins 31 and 32, threshold 1) and state 1 (producer 1, a one-hour window),
    /// logged at `at`.
    fn new(at: UnixTime) -> Self {
        let mut t = Self { log: Log::new(7), roots: vec![], states: vec![], signers: ADMINS[..1].to_vec() };
        let root = TenantRoot {
            tenant: acme(),
            version: 1,
            admin_keys: ADMINS.iter().map(|&n| admin(n)).collect(),
            threshold: 1,
            cosign_releases: false,
        };
        t.log_root(signed(TENANT_ROOT_LABEL, root, &[REGISTRAR]), at);
        let first = TenantState {
            tenant: acme(),
            version: 1,
            root_version: 1,
            apps: Default::default(),
            producers: [producer(1)].into(),
            tenant_key_versions: TenantKeyVersions {
                current: TenantKeyVersion(1),
                oldest_accepted: TenantKeyVersion(1),
            },
            platforms: [PlatformId::Sim].into(),
            integrity: Default::default(),
            deployments: Default::default(),
            freshness_keys: Default::default(),
            telemetry_readers: Default::default(),
            issued_at: at,
            pending_window_secs: HOUR,
            app_networks: Default::default(),
        };
        t.log_state(first, at);
        t
    }

    fn log_root(&mut self, root: Signed<TenantRoot>, at: UnixTime) {
        let index = self.log.log.append(LogEntry::TenantRoot(root.body.clone())).unwrap();
        self.roots.push(LoggedRoot { root, proof: self.log.proof_at(index, at) });
    }

    /// Logs `state` with its proof at `at`.
    fn log_state(&mut self, state: TenantState, at: UnixTime) -> SignedTenantState {
        let signed = signed(TENANT_STATE_LABEL, state, &self.signers);
        let index = self.log.log.append_state(&signed).unwrap();
        let proof = self.log.proof_at(index, at);
        self.states.push(LoggedState { state: signed.clone(), proof });
        signed
    }

    fn latest(&self) -> TenantState {
        self.states.last().unwrap().state.body.clone()
    }

    /// The next state: the latest's (or `base`'s) contents, edited, logged at `at`.
    fn change(&mut self, at: UnixTime, base: Option<&TenantState>, edit: impl FnOnce(&mut TenantState)) {
        let latest = self.latest();
        let mut next = base.cloned().unwrap_or_else(|| latest.clone());
        next.version = latest.version + 1;
        next.root_version = self.roots.len() as u64;
        next.issued_at = at;
        edit(&mut next);
        self.log_state(next, at);
    }

    fn trust(&self) -> TenantTrust {
        TenantTrust {
            tlog: self.log.log.trust(),
            registrar_keys: vec![key(REGISTRAR).public_key()],
            registrar_threshold: 1,
        }
    }

    /// A bundle of every logged state from `from` (an index), fresh, with a checkpoint
    /// witnessed at `witnessed`.
    fn bundle_from(&mut self, from: usize, witnessed: UnixTime) -> TenantBundle {
        let latest = self.states.last().unwrap().state.clone();
        TenantBundle {
            root_chain: self.roots.clone(),
            state: latest,
            signals: vec![],
            ended_sessions: vec![],
            freshness: vec![self.log.freshness_at(&acme(), witnessed)],
            wrap_keys: vec![],
            states: self.states[from..].to_vec(),
            checkpoint: Some(self.log.checkpoint_at(witnessed)),
            anchors: vec![],
        }
    }

    fn verify_from(&mut self, from: usize, now: UnixTime) -> Result<VerifiedTenant, VerifyError> {
        let bundle = self.bundle_from(from, now);
        TenantVerifier::new(self.trust(), vec![]).verify(&acme(), &bundle, &TrustedTime::exact(now))
    }

    fn verify(&mut self, now: UnixTime) -> VerifiedTenant {
        self.verify_from(0, now).unwrap()
    }
}

fn in_force(v: &VerifiedTenant) -> u64 {
    v.state().version
}

#[test]
fn the_first_state_applies_at_once() {
    let mut t = Tenant::new(T);
    let v = t.verify(T);
    assert_eq!(in_force(&v), 1);
    assert!(v.pending().is_empty());
    // Even without log evidence, a first state is in force.
    let mut bundle = t.bundle_from(0, T);
    bundle.states.clear();
    let v = TenantVerifier::new(t.trust(), vec![]).verify(&acme(), &bundle, &TrustedTime::exact(T)).unwrap();
    assert_eq!(in_force(&v), 1);
}

#[test]
fn a_widening_change_waits_the_window_and_a_narrowing_one_applies_at_once() {
    let mut t = Tenant::new(T);
    t.change(T + 100, None, |s| {
        s.producers.insert(producer(2));
    });
    let v = t.verify(T + 101);
    assert_eq!(in_force(&v), 1, "the new producer waits");
    assert_eq!(v.latest_state().version, 2);
    let pending = v.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].change, Change::Widening);
    assert_eq!(pending[0].public_since, T + 100);
    assert_eq!(pending[0].effective_at, Some(T + 100 + HOUR));
    assert_eq!(in_force(&t.verify(T + 99 + HOUR)), 1, "one second short");
    let v = t.verify(T + 100 + HOUR);
    assert_eq!(in_force(&v), 2);
    assert_eq!(v.in_force_since(), T + 100 + HOUR);
    assert!(v.pending().is_empty());

    // Removing a producer applies as soon as it is public.
    t.change(T + 2 * HOUR, None, |s| {
        s.producers.remove(&producer(1));
    });
    let v = t.verify(T + 2 * HOUR);
    assert_eq!(in_force(&v), 3);
    assert_eq!(v.in_force_since(), T + 2 * HOUR);
}

#[test]
fn superseding_cancels_a_pending_change() {
    let mut t = Tenant::new(T);
    let first = t.latest();
    t.change(T + 100, None, |s| {
        s.producers.insert(producer(2));
    });
    // The cancel: state 1's contents again, as state 3. It narrows nothing, so it applies.
    t.change(T + 200, Some(&first), |_| {});
    let v = t.verify(T + 201);
    assert_eq!(in_force(&v), 3);
    assert!(v.pending().is_empty());
    // State 2 never takes effect, also once its window has passed.
    let v = t.verify(T + 100 + 2 * HOUR);
    assert_eq!(in_force(&v), 3);
    assert!(!v.state().producers.contains(&producer(2)));
}

#[test]
fn a_newer_widening_state_does_not_cancel() {
    let mut t = Tenant::new(T);
    t.change(T + 100, None, |s| {
        s.producers.insert(producer(2));
    });
    t.change(T + 200, None, |s| {
        s.producers.insert(producer(3));
    });
    let v = t.verify(T + 300);
    assert_eq!(in_force(&v), 1);
    assert_eq!(
        v.pending().iter().map(|p| p.effective_at).collect::<Vec<_>>(),
        vec![Some(T + 100 + HOUR), Some(T + 200 + HOUR)]
    );
    // State 2 takes effect at its time; state 3 widens state 2, so it waits for its own.
    assert_eq!(in_force(&t.verify(T + 150 + HOUR)), 2);
    assert_eq!(in_force(&t.verify(T + 200 + HOUR)), 3);
}

#[test]
fn shortening_the_window_waits_the_old_one() {
    let mut t = Tenant::new(T);
    t.change(T + 100, None, |s| s.pending_window_secs = 0);
    assert_eq!(in_force(&t.verify(T + 101)), 1);
    assert_eq!(in_force(&t.verify(T + 100 + HOUR)), 2);
    // With a window of 0, a widening change applies once public.
    t.change(T + 2 * HOUR, None, |s| {
        s.producers.insert(producer(2));
    });
    assert_eq!(in_force(&t.verify(T + 2 * HOUR)), 3);
    // Lengthening applies at once.
    t.change(T + 3 * HOUR, None, |s| s.pending_window_secs = 2 * HOUR);
    assert_eq!(in_force(&t.verify(T + 3 * HOUR)), 4);
}

#[test]
fn the_window_is_measured_by_the_logs_witnessed_time() {
    let mut t = Tenant::new(T);
    t.change(T + 100, None, |s| {
        s.producers.insert(producer(2));
    });
    // The verifier's clock says the window has passed; the log's witnesses do not.
    let bundle = t.bundle_from(0, T + 200);
    let late = TrustedTime::exact(T + 10 * HOUR);
    let v = TenantVerifier::new(t.trust(), vec![]).verify(&acme(), &bundle, &late).unwrap();
    assert_eq!(in_force(&v), 1);
    assert_eq!(v.checked_at(), T + 200);
    // And clock uncertainty counts against it.
    let bundle = t.bundle_from(0, T + 100 + HOUR);
    let unsure = TrustedTime { now: T + 100 + HOUR, radius: 5 };
    let v = TenantVerifier::new(t.trust(), vec![]).verify(&acme(), &bundle, &unsure).unwrap();
    assert_eq!(in_force(&v), 1);
}

#[test]
fn root_rotations_use_the_window_of_the_state_in_force() {
    let mut t = Tenant::new(T);
    // Root v2 adds an admin key: widening. The state is re-signed under it.
    let mut next = t.roots[0].root.body.clone();
    next.version = 2;
    next.admin_keys.insert(admin(NEW_ADMIN));
    t.log_root(signed(TENANT_ROOT_LABEL, next.clone(), &ADMINS[..1]), T + 100);
    t.change(T + 100, None, |_| {});
    let v = t.verify(T + 200);
    assert_eq!(in_force(&v), 1);
    assert_eq!(v.root().version, 1);
    assert_eq!(v.latest_root().version, 2);
    assert_eq!(v.pending()[0].change, Change::Widening, "the state is unchanged but its root widens");
    let v = t.verify(T + 100 + HOUR);
    assert_eq!((in_force(&v), v.root().version), (2, 2));

    // Root v3 raises the threshold, signed by v2's: narrowing, at once.
    let mut v3 = next;
    v3.version = 3;
    v3.threshold = 2;
    t.log_root(signed(TENANT_ROOT_LABEL, v3, &ADMINS[..1]), T + 2 * HOUR);
    t.signers = ADMINS.to_vec();
    t.change(T + 2 * HOUR, None, |_| {});
    let v = t.verify(T + 2 * HOUR);
    assert_eq!((in_force(&v), v.root().version), (3, 3));
}

#[test]
fn a_narrowing_root_signed_only_by_keys_not_in_force_waits() {
    let mut t = Tenant::new(T);
    // Root v2 replaces both admins with a new one (widening, pending) ...
    let mut v2 = t.roots[0].root.body.clone();
    v2.version = 2;
    v2.admin_keys = [admin(NEW_ADMIN)].into();
    t.log_root(signed(TENANT_ROOT_LABEL, v2.clone(), &ADMINS[..1]), T + 100);
    // ... whose key then signs v3, the same as v1 but with threshold 2: narrowing relative
    // to v1, but not signed by v1's keys.
    let mut v3 = t.roots[0].root.body.clone();
    v3.version = 3;
    v3.threshold = 2;
    t.log_root(signed(TENANT_ROOT_LABEL, v3, &[NEW_ADMIN]), T + 200);
    t.signers = ADMINS.to_vec();
    t.change(T + 200, None, |_| {});
    let v = t.verify(T + 300);
    assert_eq!((in_force(&v), v.root().version), (1, 1));
    assert_eq!(in_force(&t.verify(T + 200 + HOUR)), 2);
}

#[test]
fn a_stateless_verifier_needs_states_back_to_an_anchor() {
    let mut t = Tenant::new(T);
    t.change(T + 100, None, |s| {
        s.producers.remove(&producer(1));
    });
    // State 2 alone: what was in force before it is unknown.
    assert!(matches!(t.verify_from(1, T + 200), Err(VerifyError::State(_))));
    // Once it has been public for the longest window, it is in force whatever came before.
    let settled = T + 100 + MAX_PENDING_WINDOW_SECS;
    assert_eq!(in_force(&t.verify_from(1, settled).unwrap()), 2);

    // A state that stayed the latest that long anchors the ones after it.
    t.change(settled + 10, None, |s| {
        s.producers.insert(producer(2));
    });
    let v = t.verify_from(1, settled + 20).unwrap();
    assert_eq!(in_force(&v), 2);
    assert_eq!(v.pending().len(), 1);
}

const GUARDIAN: u8 = 60;

#[test]
fn a_guardian_anchor_bounds_the_states_a_bundle_needs() {
    let mut t = Tenant::new(T);
    // Changes every hour for three days: no state ever stays the latest for the cap.
    let mut at = T;
    for n in 0..72u8 {
        at += HOUR;
        t.change(at, None, |s| {
            if n % 2 == 0 {
                s.producers.insert(producer(n + 10));
            } else {
                s.producers.remove(&producer(n + 9));
            }
        });
    }
    let now = at + 60;
    let guardian = key(GUARDIAN);
    let verifier = |t: &Tenant| TenantVerifier::new(t.trust(), vec![]).with_anchor_keys(vec![guardian.public_key()]);
    // The guardian anchors on the whole history (a guardian sees what the control plane sends).
    let full = t.bundle_from(0, now);
    let truth = verifier(&t).verify(&acme(), &full, &TrustedTime::exact(now)).unwrap();
    let anchor = verifier(&t).anchor(PlatformId::Sim, &acme(), &full, &TrustedTime::exact(now)).unwrap();
    assert_eq!((anchor.version, anchor.at), (truth.state().version, now), "complete up to its freshness");
    let signed = guardian.sign_into(TENANT_ANCHOR_LABEL, anchor.clone());

    // From the anchored state on: every newer state became public within the cap before it.
    let from = t.states.iter().position(|s| s.state.body.version == anchor.version).unwrap();
    let mut short = t.bundle_from(from, now + 10);
    assert!(t.states[from + 1..].iter().all(|s| s.state.body.issued_at + MAX_PENDING_WINDOW_SECS > now));
    assert!(TenantVerifier::new(t.trust(), vec![]).verify(&acme(), &short, &TrustedTime::exact(now + 10)).is_err());
    short.anchors = vec![signed.clone()];
    let v = verifier(&t).verify(&acme(), &short, &TrustedTime::exact(now + 10)).unwrap();
    assert_eq!(v.state(), truth.state());
    assert_eq!(v.pending(), truth.pending());

    // Another key's anchor, another tenant's, or one dated after the log's time does not count.
    let mut forged = short.clone();
    forged.anchors = vec![key(61).sign_into(TENANT_ANCHOR_LABEL, anchor.clone())];
    assert!(verifier(&t).verify(&acme(), &forged, &TrustedTime::exact(now + 10)).is_err());
    let mut later = short.clone();
    later.anchors = vec![guardian.sign_into(TENANT_ANCHOR_LABEL, TenantAnchor { at: now + 1_000, ..anchor.clone() })];
    assert!(verifier(&t).verify(&acme(), &later, &TrustedTime::exact(now + 10)).is_err());
    // An anchor for a state with another digest does not match.
    let mut wrong = short;
    wrong.anchors = vec![guardian.sign_into(TENANT_ANCHOR_LABEL, TenantAnchor { digest: [9; 32], ..anchor })];
    assert!(verifier(&t).verify(&acme(), &wrong, &TrustedTime::exact(now + 10)).is_err());
}

#[test]
fn an_anchor_vouches_only_up_to_the_bundles_freshness() {
    let mut t = Tenant::new(T);
    t.change(T + 100, None, |s| {
        s.producers.insert(producer(2));
    });
    // Freshness from before state 2's window ends: the anchor stops there, although the
    // guardian's clock is later.
    let mut bundle = t.bundle_from(0, T + 200);
    bundle.checkpoint = Some(t.log.checkpoint_at(T + 3 * HOUR));
    let anchor = TenantVerifier::new(t.trust(), vec![])
        .anchor(PlatformId::Sim, &acme(), &bundle, &TrustedTime::exact(T + 3 * HOUR))
        .unwrap();
    assert_eq!((anchor.version, anchor.at), (1, T + 200));
}

#[test]
fn a_late_proof_only_makes_a_document_look_later() {
    let mut t = Tenant::new(T);
    t.change(T + 100, None, |s| {
        s.producers.insert(producer(2));
    });
    // The widening state shown with a proof from an hour later waits an hour longer.
    let mut bundle = t.bundle_from(0, T + 100 + HOUR);
    let index = bundle.states[1].proof.leaf_index;
    bundle.states[1].proof = t.log.proof_at(index, T + 100 + HOUR);
    let v =
        TenantVerifier::new(t.trust(), vec![]).verify(&acme(), &bundle, &TrustedTime::exact(T + 100 + HOUR)).unwrap();
    assert_eq!(in_force(&v), 1);
    assert_eq!(v.pending()[0].effective_at, Some(T + 100 + 2 * HOUR));
}

#[test]
fn bundles_with_gaps_reordered_or_mismatched_states_are_refused() {
    let mut t = Tenant::new(T);
    t.change(T + 100, None, |s| {
        s.producers.insert(producer(2));
    });
    t.change(T + 200, None, |s| {
        s.producers.insert(producer(3));
    });
    let good = t.bundle_from(0, T + 300);
    let refused = |b: &TenantBundle| {
        matches!(
            TenantVerifier::new(t.trust(), vec![]).verify(&acme(), b, &TrustedTime::exact(T + 300)),
            Err(VerifyError::State(_))
        )
    };
    let mut gap = good.clone();
    gap.states.remove(1);
    assert!(refused(&gap), "a missing version");
    let mut reordered = good.clone();
    reordered.states.swap(0, 1);
    assert!(refused(&reordered));
    let mut not_latest = good.clone();
    not_latest.states.pop();
    assert!(refused(&not_latest), "the last is not the bundle's state");
    let mut unsigned = good.clone();
    unsigned.states[1].state.signatures.clear();
    assert!(refused(&unsigned));
    let mut unlogged = good.clone();
    unlogged.states[1].proof = unlogged.states[2].proof.clone();
    assert!(TenantVerifier::new(t.trust(), vec![]).verify(&acme(), &unlogged, &TrustedTime::exact(T + 300)).is_err());
}

#[test]
fn a_cache_never_goes_back_and_moves_on_by_itself() {
    let mut t = Tenant::new(T);
    t.change(T + 100, None, |s| {
        s.producers.insert(producer(2));
    });
    let mut cache = t.verify(T + 100 + HOUR);
    assert_eq!(in_force(&cache), 2);
    t.change(T + 2 * HOUR, None, |s| {
        s.producers.insert(producer(3));
    });
    // A verifier without memory, shown only states 2 and 3 well after, cannot anchor on 2 ...
    assert!(t.verify_from(1, T + 2 * HOUR + 10).is_err());
    // ... and one shown everything agrees with the cache: 3 is pending.
    let fresh = t.verify(T + 2 * HOUR + 10);
    assert_eq!(in_force(&fresh), 2);
    cache.merge(fresh).unwrap();
    assert_eq!(in_force(&cache), 2);
    assert_eq!(cache.pending().len(), 1);

    // An older stateless result (a bundle anchored before state 2 at an earlier witnessed
    // time) does not move the cache back; it moves on from its own state at that bundle's time.
    let mut early = t.verify(T + 2 * HOUR + 10);
    let later = t.verify(T + 3 * HOUR);
    assert_eq!(in_force(&later), 3);
    early.merge(later).unwrap();
    assert_eq!(in_force(&early), 3);
}

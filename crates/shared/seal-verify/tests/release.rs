mod common;

use common::{key, Log, T};
use seal_crypto::sign::{key_id, SigningKey};
use seal_proto::release::{
    Component, LogEntry, ReleaseConstraints, ReleaseEvidence, ReleaseManifest, Tcb, AUDITOR_LABEL,
    FRESH_CHECKPOINT_SECS, RELEASE_LABEL,
};
use seal_proto::signed::Signed;
use seal_proto::{Measurement, PlatformId, ServiceKeyVersion, TrustedTime};
use seal_tlog::TlogError;
use seal_verify::{ReleaseTrust, ReleaseVerifier, VerifyError};

const LOCK: u64 = 14 * 86_400;

fn release_key(n: u8) -> SigningKey {
    key(n)
}
fn auditor() -> SigningKey {
    key(9)
}

fn manifest(n: u8) -> ReleaseManifest {
    ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::Sim,
        measurement: Measurement([n; 48]),
        service_key_version: ServiceKeyVersion(2),
        version: "0.1.0".into(),
        source_commit: "abc".into(),
        serves: None,
    }
}

fn signed_by(body: ReleaseManifest, keys: &[u8]) -> Signed<ReleaseManifest> {
    let mut s = Signed { body, signatures: vec![] };
    for &n in keys {
        release_key(n).cosign(RELEASE_LABEL, &mut s);
    }
    s
}

struct Fixture {
    log: Log,
    manifest: Signed<ReleaseManifest>,
    index: u64,
}

impl Fixture {
    /// A manifest signed by release keys 1 and 2 (of 1, 2, 3), logged as entry 1.
    fn new() -> Self {
        let mut log = Log::new(1);
        log.log.append(LogEntry::Release(manifest(0))).unwrap();
        let manifest = signed_by(manifest(1), &[1, 2]);
        let index = log.log.append(LogEntry::Release(manifest.body.clone())).unwrap();
        Self { log, manifest, index }
    }

    fn trust(&self) -> ReleaseTrust {
        ReleaseTrust {
            tlog: self.log.log.trust(),
            release_keys: vec![release_key(1).public_key(), release_key(2).public_key(), release_key(3).public_key()],
            release_threshold: 2,
            required_auditor: Some(auditor().public_key()),
            time_lock_secs: LOCK,
        }
    }

    fn verifier(&self) -> ReleaseVerifier {
        ReleaseVerifier::new(self.trust())
    }

    /// Included at `included_at`, fresh checkpoint at `fresh_at` (with the log's policy then).
    fn evidence(&mut self, included_at: u64, fresh_at: u64) -> ReleaseEvidence {
        let included = self.log.proof_at(self.index, included_at);
        let fresh = self.log.checkpoint_at(fresh_at);
        ReleaseEvidence {
            manifest: self.manifest.clone(),
            included,
            fresh,
            auditor: Some(auditor().sign(AUDITOR_LABEL, &self.manifest.body)),
        }
    }

    fn set_policy(&mut self, change: impl FnOnce(&mut ReleaseConstraints)) {
        let mut policy = self.log.log.checkpoint().checkpoint.policy;
        change(&mut policy);
        self.log.log.set_policy(policy).unwrap();
    }
}

fn at(t: u64) -> TrustedTime {
    TrustedTime::exact(t)
}

#[test]
fn a_release_past_its_time_lock_is_accepted() {
    let mut f = Fixture::new();
    let evidence = f.evidence(T, T + LOCK);
    let v = f.verifier().verify(&evidence, &at(T + LOCK)).unwrap();
    assert_eq!(v.manifest(), &f.manifest.body);
    assert_eq!(v.public_since(), T);
    assert_eq!(v.constraints(), &evidence.fresh.checkpoint.policy);
    // Later local time, still within the fresh checkpoint's window.
    f.verifier().verify(&evidence, &at(T + LOCK + FRESH_CHECKPOINT_SECS - 1)).unwrap();
}

#[test]
fn release_signatures_need_m_distinct_trusted_keys() {
    let mut f = Fixture::new();
    let good = f.evidence(T, T + LOCK);
    let v = f.verifier();
    let refused = |e: &ReleaseEvidence| matches!(v.verify(e, &at(T + LOCK)), Err(VerifyError::ReleaseSignatures(_)));

    let mut short = good.clone();
    short.manifest.signatures.truncate(1);
    assert!(refused(&short), "one of two");

    let mut duplicate = short.clone();
    duplicate.manifest.signatures.push(duplicate.manifest.signatures[0].clone());
    assert!(refused(&duplicate), "the same key twice");

    let mut unknown = short.clone();
    key(77).cosign(RELEASE_LABEL, &mut unknown.manifest);
    assert!(refused(&unknown), "an untrusted key");

    let mut forged = short.clone();
    forged.manifest.signatures.push(release_key(3).sign(RELEASE_LABEL, &manifest(2)));
    assert!(refused(&forged), "a signature over another manifest");

    let mut wrong_label = short;
    wrong_label.manifest.signatures.push(release_key(3).sign(AUDITOR_LABEL, &good.manifest.body));
    assert!(refused(&wrong_label), "a signature under another label");

    let mut all = good;
    release_key(3).cosign(RELEASE_LABEL, &mut all.manifest);
    v.verify(&all, &at(T + LOCK)).unwrap();
}

#[test]
fn revoked_release_keys_do_not_count() {
    let mut f = Fixture::new();
    let revoked = release_key(2).key_id();
    f.set_policy(|p| {
        p.revoked_keys.insert(revoked);
    });
    let evidence = f.evidence(T, T + LOCK);
    assert!(matches!(f.verifier().verify(&evidence, &at(T + LOCK)), Err(VerifyError::ReleaseSignatures(_))));
    let mut with_third = evidence;
    release_key(3).cosign(RELEASE_LABEL, &mut with_third.manifest);
    f.verifier().verify(&with_third, &at(T + LOCK)).unwrap();
}

#[test]
fn a_required_auditor_must_sign_and_not_be_revoked() {
    let mut f = Fixture::new();
    let good = f.evidence(T, T + LOCK);
    let v = f.verifier();
    let now = at(T + LOCK);

    let mut missing = good.clone();
    missing.auditor = None;
    assert_eq!(v.verify(&missing, &now), Err(VerifyError::Auditor));
    let mut wrong_key = good.clone();
    wrong_key.auditor = Some(release_key(3).sign(AUDITOR_LABEL, &good.manifest.body));
    assert_eq!(v.verify(&wrong_key, &now), Err(VerifyError::Auditor));
    let mut wrong_label = good.clone();
    wrong_label.auditor = Some(auditor().sign(RELEASE_LABEL, &good.manifest.body));
    assert_eq!(v.verify(&wrong_label, &now), Err(VerifyError::Auditor));

    // Not required: none needed.
    let mut trust = f.trust();
    trust.required_auditor = None;
    ReleaseVerifier::new(trust).verify(&missing, &now).unwrap();

    // Revoked by the fresh policy.
    let revoked = auditor().key_id();
    f.set_policy(|p| {
        p.revoked_keys.insert(revoked);
    });
    let evidence = f.evidence(T, T + LOCK);
    assert_eq!(f.verifier().verify(&evidence, &now), Err(VerifyError::Auditor));
}

#[test]
fn the_manifest_must_be_included() {
    let mut f = Fixture::new();
    let good = f.evidence(T, T + LOCK);
    let v = f.verifier();
    let now = at(T + LOCK);

    let mut other_entry = good.clone();
    other_entry.included = f.log.proof_at(0, T);
    assert_eq!(v.verify(&other_entry, &now), Err(VerifyError::Log(TlogError::BadInclusion)));

    let mut bad_path = good.clone();
    bad_path.included.audit_path[0][0] ^= 1;
    assert_eq!(v.verify(&bad_path, &now), Err(VerifyError::Log(TlogError::BadInclusion)));

    let mut short = good.clone();
    short.included.checkpoint.cosignatures.truncate(1);
    assert_eq!(v.verify(&short, &now), Err(VerifyError::Log(TlogError::NoQuorum { have: 1, need: 2 })));

    // A manifest that was never logged, with valid signatures.
    let mut unlogged = good;
    unlogged.manifest = signed_by(manifest(5), &[1, 2]);
    unlogged.auditor = Some(auditor().sign(AUDITOR_LABEL, &unlogged.manifest.body));
    assert_eq!(v.verify(&unlogged, &now), Err(VerifyError::Log(TlogError::BadInclusion)));
}

#[test]
fn the_fresh_checkpoint_needs_a_quorum_and_the_right_origin() {
    let mut f = Fixture::new();
    let good = f.evidence(T, T + LOCK);
    let now = at(T + LOCK);
    let mut short = good.clone();
    short.fresh.cosignatures.truncate(1);
    assert_eq!(f.verifier().verify(&short, &now), Err(VerifyError::Log(TlogError::NoQuorum { have: 1, need: 2 })));
    let mut forged = good.clone();
    forged.fresh.log_signature = key(5).sign(seal_proto::release::CHECKPOINT_LABEL, &forged.fresh.checkpoint);
    assert_eq!(f.verifier().verify(&forged, &now), Err(VerifyError::Log(TlogError::BadLogSignature)));
    let mut trust = f.trust();
    trust.tlog.origin = "another.log/v1".into();
    assert_eq!(ReleaseVerifier::new(trust).verify(&good, &now), Err(VerifyError::Log(TlogError::WrongOrigin)));
}

#[test]
fn witnesses_the_fresh_policy_revokes_do_not_count_for_inclusion() {
    let mut f = Fixture::new();
    let mut evidence = f.evidence(T, T + LOCK);
    // The inclusion checkpoint keeps cosignatures from witnesses 0 and 1 only.
    let witness_keys = f.log.log.trust().witness_keys;
    let ids: Vec<_> = witness_keys.iter().map(key_id).collect();
    evidence.included.checkpoint.cosignatures.retain(|c| c.signature.signer != ids[2]);
    f.verifier().verify(&evidence, &at(T + LOCK)).unwrap();

    f.set_policy(|p| {
        p.revoked_keys.insert(ids[0]);
    });
    evidence.fresh = f.log.checkpoint_at(T + LOCK);
    assert_eq!(
        f.verifier().verify(&evidence, &at(T + LOCK)),
        Err(VerifyError::Log(TlogError::NoQuorum { have: 1, need: 2 }))
    );
}

#[test]
fn a_stale_fresh_checkpoint_is_refused() {
    let mut f = Fixture::new();
    let evidence = f.evidence(T, T + LOCK);
    let v = f.verifier();
    let limit = T + LOCK + FRESH_CHECKPOINT_SECS;
    v.verify(&evidence, &at(limit - 1)).unwrap();
    assert_eq!(v.verify(&evidence, &at(limit)), Err(VerifyError::StaleCheckpoint));
    // Clock uncertainty counts against freshness.
    assert_eq!(v.verify(&evidence, &TrustedTime { now: limit - 1, radius: 1 }), Err(VerifyError::StaleCheckpoint));
}

#[test]
fn the_fresh_checkpoint_may_not_be_smaller_than_the_inclusion_checkpoint() {
    let mut f = Fixture::new();
    let small = f.log.checkpoint_at(T + LOCK);
    f.log.log.append(LogEntry::Release(manifest(7))).unwrap();
    let mut evidence = f.evidence(T, T + LOCK);
    assert_eq!(evidence.included.checkpoint.checkpoint.size, 3);
    f.verifier().verify(&evidence, &at(T + LOCK)).unwrap();
    evidence.fresh = small;
    assert_eq!(f.verifier().verify(&evidence, &at(T + LOCK)), Err(VerifyError::StaleCheckpoint));
}

#[test]
fn a_forked_or_loosened_fresh_checkpoint_is_refused() {
    let mut f = Fixture::new();
    f.set_policy(|p| {
        p.min_service_key_version.insert(PlatformId::Sim, ServiceKeyVersion(1));
    });
    let evidence = f.evidence(T, T + LOCK);

    // The same keys running a second log: a tree of the same size with another root.
    let mut fork = Log::new(1);
    fork.log.append(LogEntry::Release(manifest(8))).unwrap();
    fork.log.append(LogEntry::Release(manifest(9))).unwrap();
    fork.log.set_policy(evidence.fresh.checkpoint.policy.clone()).unwrap();
    let mut forked = evidence.clone();
    forked.fresh = fork.checkpoint_at(T + LOCK);
    assert_eq!(f.verifier().verify(&forked, &at(T + LOCK)), Err(VerifyError::Log(TlogError::BadConsistency)));

    // A larger tree whose policy drops the inclusion checkpoint's minimum.
    let mut loose = Log::new(1);
    for n in [8, 9, 10] {
        loose.log.append(LogEntry::Release(manifest(n))).unwrap();
    }
    let mut loosened = evidence;
    loosened.fresh = loose.checkpoint_at(T + LOCK);
    assert_eq!(f.verifier().verify(&loosened, &at(T + LOCK)), Err(VerifyError::Log(TlogError::BadConsistency)));
}

#[test]
fn the_time_lock_holds_by_local_time() {
    let mut f = Fixture::new();
    let evidence = f.evidence(T, T + LOCK);
    assert_eq!(
        f.verifier().verify(&evidence, &at(T + LOCK - 1)),
        Err(VerifyError::TimeLock { public_since: T, needed_secs: LOCK, now: T + LOCK - 1 })
    );
    // Clock uncertainty counts against the lock.
    assert_eq!(
        f.verifier().verify(&evidence, &TrustedTime { now: T + LOCK, radius: 1 }),
        Err(VerifyError::TimeLock { public_since: T, needed_secs: LOCK, now: T + LOCK - 1 })
    );
}

#[test]
fn the_time_lock_holds_by_witness_time() {
    let mut f = Fixture::new();
    let evidence = f.evidence(T, T + LOCK - 1);
    assert_eq!(
        f.verifier().verify(&evidence, &at(T + LOCK + 3600)),
        Err(VerifyError::TimeLock { public_since: T, needed_secs: LOCK, now: T + LOCK - 1 })
    );
    let evidence = f.evidence(T, T + LOCK);
    f.verifier().verify(&evidence, &at(T + LOCK + 3600)).unwrap();
}

#[test]
fn a_revoked_measurement_is_refused() {
    let mut f = Fixture::new();
    let measurement = f.manifest.body.measurement;
    f.set_policy(|p| {
        p.revoked_measurements.entry(PlatformId::AwsNitro).or_default().insert(measurement);
    });
    let evidence = f.evidence(T, T + LOCK);
    f.verifier().verify(&evidence, &at(T + LOCK)).unwrap();
    f.set_policy(|p| {
        p.revoked_measurements.entry(PlatformId::Sim).or_default().insert(measurement);
    });
    let evidence = f.evidence(T, T + LOCK);
    assert_eq!(f.verifier().verify(&evidence, &at(T + LOCK)), Err(VerifyError::Revoked));
}

#[test]
fn a_service_key_version_below_the_minimum_is_refused() {
    let mut f = Fixture::new();
    f.set_policy(|p| {
        p.min_service_key_version.insert(PlatformId::Sim, ServiceKeyVersion(2));
        p.min_service_key_version.insert(PlatformId::AwsNitro, ServiceKeyVersion(9));
    });
    let evidence = f.evidence(T, T + LOCK);
    f.verifier().verify(&evidence, &at(T + LOCK)).unwrap();
    f.set_policy(|p| {
        p.min_service_key_version.insert(PlatformId::Sim, ServiceKeyVersion(3));
    });
    let evidence = f.evidence(T, T + LOCK);
    assert_eq!(f.verifier().verify(&evidence, &at(T + LOCK)), Err(VerifyError::RetiredServiceKeyVersion));
}

#[test]
fn tcb_is_checked_against_the_platform_minimum() {
    let tcb = |parts: &[(&str, u64)]| Tcb(parts.iter().map(|(k, v)| (k.to_string(), *v)).collect());
    let mut policy = ReleaseConstraints::default();
    let platform = PlatformId::AzureSnpAci;
    let have = tcb(&[("snp", 22), ("microcode", 213)]);
    ReleaseVerifier::check_tcb(&policy, platform, &have).unwrap();
    policy.min_tcb.insert(platform, tcb(&[("snp", 22), ("microcode", 213)]));
    ReleaseVerifier::check_tcb(&policy, platform, &have).unwrap();
    ReleaseVerifier::check_tcb(&policy, PlatformId::AwsNitro, &Tcb::default()).unwrap();
    assert_eq!(
        ReleaseVerifier::check_tcb(&policy, platform, &tcb(&[("snp", 22), ("microcode", 212)])),
        Err(VerifyError::TcbTooLow)
    );
    assert_eq!(ReleaseVerifier::check_tcb(&policy, platform, &tcb(&[("snp", 99)])), Err(VerifyError::TcbTooLow));
}

#[test]
fn tcb_floors_are_per_family() {
    let tcb = |parts: &[(&str, u64)]| Tcb(parts.iter().map(|(k, v)| (k.to_string(), *v)).collect());
    let platform = PlatformId::AzureSnpAci;
    let mut policy = ReleaseConstraints::default();
    policy.min_tcb.insert(
        platform,
        tcb(&[("milan.snp", 24), ("genoa.snp", 23), ("turin.fmc", 1), ("turin.snp", 4), ("uvm_svn", 100)]),
    );
    let check = |have: &[(&str, u64)]| ReleaseVerifier::check_tcb(&policy, platform, &tcb(have));
    check(&[("milan.snp", 24), ("milan.microcode", 219), ("uvm_svn", 100)]).unwrap();
    check(&[("genoa.snp", 23), ("genoa.microcode", 84), ("uvm_svn", 104)]).unwrap();
    check(&[("turin.fmc", 1), ("turin.snp", 4), ("uvm_svn", 100)]).unwrap();
    // Genoa's floor of 23 never admits a Milan at 23.
    assert_eq!(check(&[("milan.snp", 23), ("uvm_svn", 100)]), Err(VerifyError::TcbTooLow));
    // A family without a floor is refused once the platform has any family floor.
    assert_eq!(check(&[("venice.snp", 99), ("uvm_svn", 100)]), Err(VerifyError::TcbTooLow));
}

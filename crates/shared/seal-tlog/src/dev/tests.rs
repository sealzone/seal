use std::sync::atomic::{AtomicU32, Ordering};

use seal_proto::release::{Component, ReleaseManifest};
use seal_proto::signed::Signed;
use seal_proto::state::{AdminKey, TenantKeyVersions, TenantState, TENANT_ROOT_LABEL};
use seal_proto::{Measurement, PlatformId, PublicKey, ServiceKeyVersion, TenantKeyVersion};

use super::*;
use crate::{LogVerifier, TlogError};

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("seal-tlog-dev-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn manifest(n: u8) -> LogEntry {
    LogEntry::Release(ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::Sim,
        measurement: Measurement([n; 48]),
        service_key_version: ServiceKeyVersion(1),
        version: "0.1.0".into(),
        source_commit: "abc".into(),
        serves: None,
    })
}

fn admin(n: u8) -> SigningKey {
    SigningKey::from_seed(&[100 + n; 32])
}

fn tenant() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn root(version: u64, admins: &[u8], threshold: u8) -> TenantRoot {
    TenantRoot {
        tenant: tenant(),
        version,
        admin_keys: admins.iter().map(|&n| AdminKey::Ed25519 { public_key: admin(n).public_key() }).collect(),
        threshold,
        cosign_releases: false,
    }
}

fn state(version: u64, root_version: u64) -> TenantState {
    TenantState {
        tenant: tenant(),
        version,
        root_version,
        apps: Default::default(),
        producers: Default::default(),
        tenant_key_versions: TenantKeyVersions { current: TenantKeyVersion(1), oldest_accepted: TenantKeyVersion(1) },
        platforms: [PlatformId::Sim].into(),
        integrity: Default::default(),
        deployments: Default::default(),
        freshness_keys: Default::default(),
        telemetry_readers: Default::default(),
        issued_at: 1,
        pending_window_secs: 0,
        app_networks: Default::default(),
    }
}

fn signed_by(body: TenantState, admins: &[u8]) -> SignedTenantState {
    let mut s = Signed { body, signatures: vec![] };
    for &n in admins {
        admin(n).cosign(TENANT_STATE_LABEL, &mut s);
    }
    s
}

fn wall_now() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn proofs_verify_against_the_trust() {
    let dir = TempDir::new();
    let mut log = DevLog::open(&dir.0, [7; 32], 3, 2).unwrap();
    let verifier = LogVerifier::new(log.trust());
    for n in 0..10u8 {
        assert_eq!(log.append(manifest(n)).unwrap(), u64::from(n));
    }
    let before = wall_now();
    for n in 0..10u8 {
        let proof = log.prove(u64::from(n));
        let v = verifier.inclusion(&manifest(n), &proof).unwrap();
        assert_eq!(v.checkpoint().size, 10);
        assert!(v.public_since() >= before && v.public_since() <= wall_now());
        assert_eq!(verifier.inclusion(&manifest(n + 1), &proof), Err(TlogError::BadInclusion));
    }
    // Proving an entry the latest checkpoint already covers reuses it.
    assert_eq!(log.prove(3).checkpoint, log.prove(9).checkpoint);
    // A new entry makes `prove` cosign a new checkpoint.
    log.append(manifest(10)).unwrap();
    let proof = log.prove(10);
    assert_eq!(proof.checkpoint.checkpoint.size, 11);
    verifier.inclusion(&manifest(10), &proof).unwrap();
}

#[test]
fn keys_are_deterministic_and_the_log_reopens() {
    let dir = TempDir::new();
    let trust = {
        let mut log = DevLog::open(&dir.0, [7; 32], 3, 2).unwrap();
        log.append(manifest(1)).unwrap();
        log.append(manifest(2)).unwrap();
        log.checkpoint();
        log.trust()
    };
    let other = TempDir::new();
    let fresh = DevLog::open(&other.0, [7; 32], 3, 2).unwrap().trust();
    assert_eq!((fresh.log_key, fresh.witness_keys.clone()), (trust.log_key, trust.witness_keys.clone()));
    let another_seed = DevLog::open(&TempDir::new().0, [8; 32], 3, 2).unwrap().trust();
    assert_ne!(another_seed.log_key, trust.log_key);

    let mut log = DevLog::open(&dir.0, [7; 32], 3, 2).unwrap();
    assert_eq!(log.size(), 2);
    assert_eq!((log.entry(0), log.entry(1), log.entry(2)), (Some(&manifest(1)), Some(&manifest(2)), None));
    log.append(manifest(3)).unwrap();
    assert_eq!(log.entry(2), Some(&manifest(3)));
    assert_eq!(log.entry(u64::MAX), None);
    let proof = log.prove(0);
    LogVerifier::new(trust).inclusion(&manifest(1), &proof).unwrap();
    // The witnesses remembered what they saw, so the new checkpoint extends it.
    assert_eq!(proof.checkpoint.cosignatures.len(), 3);

    assert!(DevLog::open(&dir.0, [8; 32], 3, 2).is_err());
    assert!(DevLog::open(&dir.0, [7; 32], 2, 2).is_err());
    assert!(DevLog::open(&TempDir::new().0, [7; 32], 2, 3).is_err());
    assert!(DevLog::open(&TempDir::new().0, [7; 32], 2, 0).is_err());
}

#[test]
fn another_origin_is_named_by_checkpoints_and_kept_on_reopen() {
    let dir = TempDir::new();
    let trust = {
        let mut log = DevLog::open_with_origin(&dir.0, [7; 32], 3, 2, "log.example/v1").unwrap();
        log.append(manifest(1)).unwrap();
        assert_eq!(log.checkpoint().checkpoint.origin, "log.example/v1");
        log.trust()
    };
    assert_eq!(trust.origin, "log.example/v1");
    let mut log = DevLog::open_with_origin(&dir.0, [7; 32], 3, 2, "log.example/v1").unwrap();
    LogVerifier::new(trust).inclusion(&manifest(1), &log.prove(0)).unwrap();
    assert!(DevLog::open(&dir.0, [7; 32], 3, 2).is_err(), "reopened with the default origin");
    assert!(DevLog::open_with_origin(&TempDir::new().0, [7; 32], 3, 2, "").is_err());
}

#[test]
fn a_truncated_log_does_not_reopen() {
    let dir = TempDir::new();
    {
        let mut log = DevLog::open(&dir.0, [7; 32], 2, 2).unwrap();
        log.append(manifest(1)).unwrap();
        log.append(manifest(2)).unwrap();
        log.checkpoint();
    }
    let entries = dir.0.join("entries");
    let bytes = fs::read(&entries).unwrap();
    let first = 4 + u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    fs::write(&entries, &bytes[..first]).unwrap();
    assert!(DevLog::open(&dir.0, [7; 32], 2, 2).is_err());
    fs::write(&entries, &bytes[..first + 3]).unwrap();
    assert!(DevLog::open(&dir.0, [7; 32], 2, 2).is_err());
}

#[test]
fn witnesses_refuse_forks_loosening_and_forgeries() {
    let dir = TempDir::new();
    let mut log = DevLog::open(&dir.0, [7; 32], 1, 1).unwrap();
    log.append(manifest(1)).unwrap();
    log.append(manifest(2)).unwrap();
    log.checkpoint();
    let trust = log.trust();
    let mut witness = Witness { key: SigningKey::from_seed(&[1; 32]), seen: None };
    let sign = |c: Checkpoint| SignedCheckpoint {
        log_signature: log.log_key.sign(CHECKPOINT_LABEL, &c),
        checkpoint: c,
        cosignatures: vec![],
    };
    let tree = |n: u8| -> Vec<[u8; 32]> { (0..n).map(|i| leaf_hash(&manifest(i))).collect() };
    let cp = |leaves: &[[u8; 32]], policy: ReleaseConstraints| Checkpoint {
        origin: ORIGIN.into(),
        size: leaves.len() as u64,
        root_hash: merkle::root(leaves),
        policy,
    };
    let mut strict = ReleaseConstraints::default();
    strict.revoked_keys.insert(KeyId([1; 32]));

    let first = sign(cp(&tree(2), strict.clone()));
    witness.cosign(&trust, &first, &[], 5).unwrap();

    // Another tree of three that does not extend the first two leaves.
    let mut forked = tree(3);
    forked[0] = [0; 32];
    let fork = sign(cp(&forked, strict.clone()));
    let proof = merkle::consistency_proof(2, &forked);
    assert!(witness.cosign(&trust, &fork, &proof, 6).is_err());
    // A smaller tree.
    let smaller = sign(cp(&tree(1), strict.clone()));
    assert!(witness.cosign(&trust, &smaller, &[], 6).is_err());
    // A loosened policy over a consistent tree.
    let grown = tree(4);
    let proof = merkle::consistency_proof(2, &grown);
    assert!(witness.cosign(&trust, &sign(cp(&grown, Default::default())), &proof, 6).is_err());
    // Not signed by the log key.
    let mut forged = sign(cp(&grown, strict.clone()));
    forged.log_signature = witness.key.sign(CHECKPOINT_LABEL, &forged.checkpoint);
    assert!(witness.cosign(&trust, &forged, &proof, 6).is_err());
    // Wrong origin.
    let mut elsewhere = cp(&grown, strict.clone());
    elsewhere.origin = "other/v1".into();
    assert!(witness.cosign(&trust, &sign(elsewhere), &proof, 6).is_err());

    // The honest extension is cosigned, over its timestamp.
    let next = sign(cp(&grown, strict));
    let cosig = witness.cosign(&trust, &next, &proof, 6).unwrap();
    assert_eq!(cosig.timestamp, 6);
    verify(&witness.key.public_key(), COSIGNATURE_LABEL, &(&next.checkpoint, 6u64), &cosig.signature).unwrap();
}

#[test]
fn policy_only_tightens_and_rides_in_later_checkpoints() {
    let dir = TempDir::new();
    let mut log = DevLog::open(&dir.0, [7; 32], 2, 2).unwrap();
    let mut strict = ReleaseConstraints::default();
    strict.min_service_key_version.insert(PlatformId::Sim, ServiceKeyVersion(2));
    log.set_policy(strict.clone()).unwrap();
    assert!(log.set_policy(ReleaseConstraints::default()).is_err());
    let cp = log.checkpoint();
    assert_eq!(cp.checkpoint.policy, strict);
    LogVerifier::new(log.trust()).checkpoint(&cp).unwrap();
    // The policy survives a reopen.
    drop(log);
    let mut log = DevLog::open(&dir.0, [7; 32], 2, 2).unwrap();
    assert_eq!(log.checkpoint().checkpoint.policy, strict);
}

#[test]
fn clock_offset_moves_witness_and_freshness_time() {
    let dir = TempDir::new();
    let mut log = DevLog::open(&dir.0, [7; 32], 2, 2).unwrap();
    let verifier = LogVerifier::new(log.trust());
    let before = wall_now();
    log.set_clock_offset(1_000_000);
    let v = verifier.checkpoint(&log.checkpoint()).unwrap();
    assert!(v.fresh_at() >= before + 1_000_000 && v.fresh_at() <= wall_now() + 1_000_000);
    log.set_clock_offset(-1_000);
    let v = verifier.checkpoint(&log.checkpoint()).unwrap();
    assert!(v.fresh_at() <= wall_now() - 1_000);
}

#[test]
fn entries_refuse_tenant_states() {
    let dir = TempDir::new();
    let mut log = DevLog::open(&dir.0, [7; 32], 1, 1).unwrap();
    let leaf =
        TenantStateLeaf { tenant: tenant(), root_id: seal_proto::TenantRootId([0; 32]), version: 1, digest: [0; 32] };
    let err = log.append(LogEntry::TenantState(leaf)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(log.size(), 0);
}

#[test]
fn states_need_the_latest_roots_threshold_and_a_higher_version() {
    let dir = TempDir::new();
    let mut log = DevLog::open(&dir.0, [7; 32], 2, 2).unwrap();
    assert!(log.append_state(&signed_by(state(1, 1), &[1, 2])).is_err(), "no root logged yet");
    assert_eq!(log.freshness(&tenant()), None);

    let v1 = root(1, &[1, 2, 3], 2);
    log.append(LogEntry::TenantRoot(v1.clone())).unwrap();
    // One admin, the same admin twice, a non-admin.
    assert!(log.append_state(&signed_by(state(1, 1), &[1])).is_err());
    let mut twice = signed_by(state(1, 1), &[1]);
    twice.signatures.push(twice.signatures[0].clone());
    assert!(log.append_state(&twice).is_err());
    assert!(log.append_state(&signed_by(state(1, 1), &[1, 9])).is_err());
    // A signature over another body.
    let mut forged = signed_by(state(1, 1), &[1]);
    forged.signatures.push(admin(2).sign(TENANT_STATE_LABEL, &state(2, 1)));
    assert!(log.append_state(&forged).is_err());

    let index = log.append_state(&signed_by(state(1, 1), &[1, 2])).unwrap();
    let LogEntry::TenantState(leaf) = &log.entries[index as usize] else { panic!() };
    assert_eq!(leaf.root_id, root_id(&v1));
    assert_eq!(leaf.digest, labeled_digest(TENANT_STATE_LABEL, &state(1, 1)));

    // Not above every logged version.
    assert!(log.append_state(&signed_by(state(1, 1), &[2, 3])).is_err());
    log.append_state(&signed_by(state(5, 1), &[2, 3])).unwrap();
    assert!(log.append_state(&signed_by(state(4, 1), &[2, 3])).is_err());

    // After root v2 only its admins count.
    let mut v2 = Signed { body: root(2, &[4, 5], 1), signatures: vec![] };
    admin(1).cosign(TENANT_ROOT_LABEL, &mut v2);
    log.append(LogEntry::TenantRoot(v2.body)).unwrap();
    assert!(log.append_state(&signed_by(state(6, 2), &[1, 2])).is_err());
    log.append_state(&signed_by(state(6, 2), &[5])).unwrap();

    // Another tenant's states are separate.
    let other = TenantId::new("other").unwrap();
    assert_eq!(log.freshness(&other), None);
}

#[test]
fn freshness_is_for_the_latest_state_signed_by_the_log_key_now() {
    let dir = TempDir::new();
    let mut log = DevLog::open(&dir.0, [7; 32], 2, 2).unwrap();
    log.append(LogEntry::TenantRoot(root(1, &[1], 1))).unwrap();
    log.append_state(&signed_by(state(1, 1), &[1])).unwrap();
    log.append_state(&signed_by(state(3, 1), &[1])).unwrap();
    log.set_clock_offset(500);
    let before = wall_now();
    let f = log.freshness(&tenant()).unwrap();
    assert_eq!(f.body.version, 3);
    assert_eq!(f.body.digest, labeled_digest(TENANT_STATE_LABEL, &state(3, 1)));
    assert!(f.body.signed_at >= before + 500 && f.body.signed_at <= wall_now() + 500);
    let log_key: PublicKey = log.trust().log_key;
    verify(&log_key, STATE_FRESHNESS_LABEL, &f.body, &f.signatures[0]).unwrap();
}

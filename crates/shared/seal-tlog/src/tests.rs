use proptest::prelude::*;

use seal_crypto::sign::SigningKey;
use seal_proto::release::{Cosignature, ReleaseConstraints, Tcb};
use seal_proto::{KeyId, Measurement, PlatformId, ServiceKeyVersion};

use super::*;
use crate::merkle::{consistency_proof, empty_root, inclusion_path, root};

fn h(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

// --- RFC 6962 / RFC 9162 reference vectors -------------------------------------------------
//
// The test data of the RFC 6962 reference implementation (certificate-transparency
// `merkle_tree_test.cc`, also `transparency-dev/merkle` `testonly`): eight leaf inputs, the
// root of every prefix, and inclusion and consistency proofs (1-based leaf numbers there,
// 0-based indices here).

const LEAF_INPUTS: [&str; 8] =
    ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];

const ROOTS: [&str; 8] = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

/// (leaf index, tree size, audit path)
fn inclusion_vectors() -> Vec<(u64, u64, Vec<[u8; 32]>)> {
    vec![
        (0, 1, vec![]),
        (
            0,
            8,
            vec![
                h("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
                h("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
                h("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"),
            ],
        ),
        (
            5,
            8,
            vec![
                h("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
                h("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
                h("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
            ],
        ),
        (2, 3, vec![h("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125")]),
        (
            1,
            5,
            vec![
                h("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
                h("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
                h("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
            ],
        ),
    ]
}

/// (old size, new size, proof)
fn consistency_vectors() -> Vec<(u64, u64, Vec<[u8; 32]>)> {
    vec![
        (1, 1, vec![]),
        (
            1,
            8,
            vec![
                h("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
                h("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
                h("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"),
            ],
        ),
        (
            6,
            8,
            vec![
                h("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a"),
                h("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
                h("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
            ],
        ),
        (
            2,
            5,
            vec![
                h("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
                h("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
            ],
        ),
    ]
}

fn reference_leaves() -> Vec<[u8; 32]> {
    LEAF_INPUTS.iter().map(|s| leaf_hash_bytes(&hex::decode(s).unwrap())).collect()
}

#[test]
fn rfc6962_roots() {
    assert_eq!(empty_root(), h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    let leaves = reference_leaves();
    for (n, expected) in ROOTS.iter().enumerate() {
        assert_eq!(root(&leaves[..n + 1]), h(expected), "size {}", n + 1);
    }
}

#[test]
fn rfc6962_inclusion_proofs() {
    let leaves = reference_leaves();
    for (index, size, path) in inclusion_vectors() {
        let tree = &leaves[..size as usize];
        assert_eq!(inclusion_path(index as usize, tree), path, "generated {index}/{size}");
        let got = root_from_inclusion(leaves[index as usize], index, size, &path).unwrap();
        assert_eq!(got, h(ROOTS[size as usize - 1]), "verified {index}/{size}");
    }
}

#[test]
fn rfc6962_consistency_proofs() {
    let leaves = reference_leaves();
    for (m, n, proof) in consistency_vectors() {
        assert_eq!(consistency_proof(m as usize, &leaves[..n as usize]), proof, "generated {m}/{n}");
        let (old, new) = (h(ROOTS[m as usize - 1]), h(ROOTS[n as usize - 1]));
        verify_consistency(m, &old, n, &new, &proof).unwrap();
        // The proof is for these roots only.
        assert_eq!(verify_consistency(m, &new, n, &old, &proof).is_ok(), m == n);
    }
}

fn leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n).map(|i| leaf_hash_bytes(&(i as u32).to_be_bytes())).collect()
}

/// Every inclusion proof in every tree of 1..=64 leaves verifies, and only for its own leaf,
/// index and exact path.
#[test]
fn every_inclusion_proof_up_to_64() {
    let all = leaves(65);
    for n in 1..=64usize {
        let tree = &all[..n];
        let r = root(tree);
        for m in 0..n {
            let path = inclusion_path(m, tree);
            let (mu, nu) = (m as u64, n as u64);
            assert_eq!(root_from_inclusion(tree[m], mu, nu, &path), Ok(r), "{m}/{n}");
            // Another leaf at this index, or this leaf at another index.
            assert_ne!(root_from_inclusion(all[64], mu, nu, &path).ok(), Some(r));
            if m + 1 < n {
                assert_ne!(root_from_inclusion(tree[m], mu + 1, nu, &path).ok(), Some(r));
            }
            // Out of range.
            assert_eq!(root_from_inclusion(tree[m], nu, nu, &path), Err(TlogError::BadInclusion));
            // One element short or long.
            if !path.is_empty() {
                assert_ne!(root_from_inclusion(tree[m], mu, nu, &path[..path.len() - 1]).ok(), Some(r));
            }
            let mut longer = path.clone();
            longer.push([7; 32]);
            assert_eq!(root_from_inclusion(tree[m], mu, nu, &longer), Err(TlogError::BadInclusion));
            // (A path can fit trees of several sizes; the size comes from the signed checkpoint.)
        }
    }
}

/// Every consistency proof between trees of 1..=64 leaves verifies, and only for its sizes and
/// roots.
#[test]
fn every_consistency_proof_up_to_64() {
    let all = leaves(64);
    for n in 1..=64usize {
        let new = root(&all[..n]);
        for m in 1..=n {
            let old = root(&all[..m]);
            let proof = consistency_proof(m, &all[..n]);
            let (mu, nu) = (m as u64, n as u64);
            assert_eq!(verify_consistency(mu, &old, nu, &new, &proof), Ok(()), "{m}/{n}");
            assert!(verify_consistency(mu, &[9; 32], nu, &new, &proof).is_err());
            assert!(verify_consistency(mu, &old, nu, &[9; 32], &proof).is_err());
            if m < n {
                // Shrinking is never consistent.
                assert!(verify_consistency(nu, &new, mu, &old, &proof).is_err());
                let mut longer = proof.clone();
                longer.push(old);
                assert!(verify_consistency(mu, &old, nu, &new, &longer).is_err());
                assert!(verify_consistency(mu, &old, nu, &new, &proof[..proof.len() - 1]).is_err());
                assert!(verify_consistency(mu, &old, nu, &new, &[]).is_err());
            }
        }
    }
}

#[test]
fn consistency_edge_cases() {
    let all = leaves(3);
    let r = root(&all);
    verify_consistency(0, &empty_root(), 3, &r, &[]).unwrap();
    assert!(verify_consistency(0, &[1; 32], 3, &r, &[]).is_err());
    assert!(verify_consistency(0, &empty_root(), 3, &r, &[r]).is_err());
    verify_consistency(3, &r, 3, &r, &[]).unwrap();
    assert!(verify_consistency(3, &r, 3, &r, &[r]).is_err());
    assert!(verify_consistency(3, &r, 3, &[0; 32], &[]).is_err());
    verify_consistency(0, &empty_root(), 0, &empty_root(), &[]).unwrap();
}

#[test]
fn leaf_and_node_hashes_are_domain_separated() {
    let entry = LogEntry::TenantState(seal_proto::release::TenantStateLeaf {
        tenant: seal_proto::TenantId::new("acme").unwrap(),
        root_id: seal_proto::TenantRootId([1; 32]),
        version: 1,
        digest: [2; 32],
    });
    let mut pre = vec![0u8];
    pre.extend(codec::canonical(&entry));
    assert_eq!(leaf_hash(&entry), <[u8; 32]>::from(Sha256::digest(&pre)));
    let (a, b) = ([1u8; 32], [2u8; 32]);
    let node: [u8; 32] = Sha256::digest([&[1u8][..], &a, &b].concat()).into();
    assert_eq!(node_hash(&a, &b), node);
    assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
}

proptest! {
    #[test]
    fn inclusion_proofs_verify_and_tampering_fails(n in 1usize..300, m in any::<prop::sample::Index>(), at in any::<prop::sample::Index>(), bit in 0u8..8) {
        let tree = leaves(n);
        let m = m.index(n);
        let path = inclusion_path(m, &tree);
        let r = root(&tree);
        prop_assert_eq!(root_from_inclusion(tree[m], m as u64, n as u64, &path), Ok(r));
        if !path.is_empty() {
            let mut bad = path.clone();
            let i = at.index(bad.len());
            bad[i][i % 32] ^= 1 << bit;
            prop_assert_ne!(root_from_inclusion(tree[m], m as u64, n as u64, &bad), Ok(r));
        }
    }

    #[test]
    fn consistency_proofs_verify_and_tampering_fails(n in 2usize..300, m in any::<prop::sample::Index>(), at in any::<prop::sample::Index>(), bit in 0u8..8) {
        let tree = leaves(n);
        let m = 1 + m.index(n - 1);
        let proof = consistency_proof(m, &tree);
        let (old, new) = (root(&tree[..m]), root(&tree));
        prop_assert!(verify_consistency(m as u64, &old, n as u64, &new, &proof).is_ok());
        let mut bad = proof.clone();
        let i = at.index(bad.len());
        bad[i][i % 32] ^= 1 << bit;
        prop_assert!(verify_consistency(m as u64, &old, n as u64, &new, &bad).is_err());
    }

    #[test]
    fn verifiers_never_panic(index in any::<u64>(), size in any::<u64>(), old in any::<u64>(), path in prop::collection::vec(any::<[u8; 32]>(), 0..70)) {
        let _ = root_from_inclusion([0; 32], index, size, &path);
        let _ = verify_consistency(old, &[0; 32], size, &[1; 32], &path);
    }
}

// --- Checkpoints ---------------------------------------------------------------------------

const ORIGIN: &str = "log.test/v1";

fn log_key() -> SigningKey {
    SigningKey::from_seed(&[1; 32])
}
fn witness(i: u8) -> SigningKey {
    SigningKey::from_seed(&[10 + i; 32])
}

fn trust(witnesses: u8, quorum: usize) -> TlogTrust {
    TlogTrust {
        origin: ORIGIN.into(),
        log_key: log_key().public_key(),
        witness_keys: (0..witnesses).map(|i| witness(i).public_key()).collect(),
        witness_quorum: quorum,
    }
}

fn checkpoint(size: u64, root_hash: [u8; 32], policy: ReleaseConstraints) -> Checkpoint {
    Checkpoint { origin: ORIGIN.into(), size, root_hash, policy }
}

fn cosign(key: &SigningKey, cp: &Checkpoint, timestamp: UnixTime) -> Cosignature {
    Cosignature { timestamp, signature: key.sign(COSIGNATURE_LABEL, &(cp, timestamp)) }
}

/// Signed by the log key and cosigned by `witness(i)` at `t` for each `(i, t)`.
fn signed(cp: Checkpoint, cosigners: &[(u8, UnixTime)]) -> SignedCheckpoint {
    let cosignatures = cosigners.iter().map(|&(i, t)| cosign(&witness(i), &cp, t)).collect();
    SignedCheckpoint { log_signature: log_key().sign(CHECKPOINT_LABEL, &cp), checkpoint: cp, cosignatures }
}

#[test]
fn checkpoint_with_quorum_is_accepted_and_times_are_sorted() {
    let cp = signed(checkpoint(1, [3; 32], Default::default()), &[(2, 300), (0, 100), (1, 200)]);
    let v = LogVerifier::new(trust(3, 2)).checkpoint(&cp).unwrap();
    assert_eq!(v.checkpoint(), &cp.checkpoint);
    assert_eq!(v.times, vec![100, 200, 300]);
    // Two of three had seen it by 200; two of three still vouched for it at 200.
    assert_eq!(v.public_since(), 200);
    assert_eq!(v.fresh_at(), 200);

    let cp = signed(checkpoint(1, [3; 32], Default::default()), &[(3, 400), (0, 100), (2, 300), (1, 200)]);
    let v = LogVerifier::new(trust(4, 2)).checkpoint(&cp).unwrap();
    assert_eq!((v.public_since(), v.fresh_at()), (200, 300));
    let v = LogVerifier::new(trust(4, 1)).checkpoint(&cp).unwrap();
    assert_eq!((v.public_since(), v.fresh_at()), (100, 400));
    let v = LogVerifier::new(trust(4, 4)).checkpoint(&cp).unwrap();
    assert_eq!((v.public_since(), v.fresh_at()), (400, 100));
}

#[test]
fn wrong_origin_is_refused() {
    let mut c = checkpoint(1, [3; 32], Default::default());
    c.origin = "other.log/v1".into();
    let cp = signed(c, &[(0, 1), (1, 1)]);
    assert_eq!(LogVerifier::new(trust(2, 2)).checkpoint(&cp), Err(TlogError::WrongOrigin));
}

#[test]
fn log_signature_must_be_the_log_keys_over_this_checkpoint() {
    let v = LogVerifier::new(trust(2, 2));
    let good = signed(checkpoint(1, [3; 32], Default::default()), &[(0, 1), (1, 1)]);
    v.checkpoint(&good).unwrap();

    let mut forged = good.clone();
    forged.log_signature = witness(0).sign(CHECKPOINT_LABEL, &forged.checkpoint);
    assert_eq!(v.checkpoint(&forged), Err(TlogError::BadLogSignature));

    let mut renamed = good.clone();
    renamed.log_signature = witness(0).sign(CHECKPOINT_LABEL, &renamed.checkpoint);
    renamed.log_signature.signer = log_key().key_id();
    assert_eq!(v.checkpoint(&renamed), Err(TlogError::BadLogSignature));

    // Another tree under the old signatures.
    let mut grown = good.clone();
    grown.checkpoint.size = 2;
    assert_eq!(v.checkpoint(&grown), Err(TlogError::BadLogSignature));

    let mut wrong_label = good;
    wrong_label.log_signature = log_key().sign(COSIGNATURE_LABEL, &wrong_label.checkpoint);
    assert_eq!(v.checkpoint(&wrong_label), Err(TlogError::BadLogSignature));
}

#[test]
fn quorum_short_by_one_is_refused() {
    let v = LogVerifier::new(trust(3, 3));
    let cp = signed(checkpoint(1, [3; 32], Default::default()), &[(0, 1), (1, 1)]);
    assert_eq!(v.checkpoint(&cp), Err(TlogError::NoQuorum { have: 2, need: 3 }));
    let none = signed(checkpoint(1, [3; 32], Default::default()), &[]);
    assert_eq!(v.checkpoint(&none), Err(TlogError::NoQuorum { have: 0, need: 3 }));
}

#[test]
fn duplicate_unknown_and_forged_cosignatures_do_not_count() {
    let v = LogVerifier::new(trust(2, 2));
    let base = signed(checkpoint(1, [3; 32], Default::default()), &[(0, 10)]);
    let short = Err(TlogError::NoQuorum { have: 1, need: 2 });

    // The same witness twice, at another time too.
    let mut dup = base.clone();
    dup.cosignatures.push(cosign(&witness(0), &dup.checkpoint, 10));
    dup.cosignatures.push(cosign(&witness(0), &dup.checkpoint, 20));
    assert_eq!(v.checkpoint(&dup), short);

    // A witness not in the trust.
    let mut unknown = base.clone();
    unknown.cosignatures.push(cosign(&witness(7), &unknown.checkpoint, 10));
    assert_eq!(v.checkpoint(&unknown), short);

    // A trusted witness's cosignature with its timestamp changed.
    let mut moved = base.clone();
    let mut c = cosign(&witness(1), &moved.checkpoint, 10);
    c.timestamp = 5;
    moved.cosignatures.push(c);
    assert_eq!(v.checkpoint(&moved), short);

    // Over another checkpoint.
    let mut other = base.clone();
    other.cosignatures.push(cosign(&witness(1), &checkpoint(2, [3; 32], Default::default()), 10));
    assert_eq!(v.checkpoint(&other), short);

    // The log key is not a witness.
    let mut by_log = base.clone();
    by_log.cosignatures.push(cosign(&log_key(), &by_log.checkpoint, 10));
    assert_eq!(v.checkpoint(&by_log), short);

    // A trusted key listed twice is one witness.
    let mut doubled = trust(1, 2);
    doubled.witness_keys.push(witness(0).public_key());
    assert_eq!(LogVerifier::new(doubled).checkpoint(&dup), short);

    let mut ok = base;
    ok.cosignatures.push(cosign(&witness(1), &ok.checkpoint, 10));
    v.checkpoint(&ok).unwrap();
}

#[test]
fn cosignatures_from_witnesses_the_checkpoint_revokes_do_not_count() {
    let v = LogVerifier::new(trust(3, 2));
    let mut policy = ReleaseConstraints::default();
    policy.revoked_keys.insert(witness(1).key_id());
    let cp = signed(checkpoint(1, [3; 32], policy.clone()), &[(0, 1), (1, 1)]);
    assert_eq!(v.checkpoint(&cp), Err(TlogError::NoQuorum { have: 1, need: 2 }));
    let cp = signed(checkpoint(1, [3; 32], policy), &[(0, 1), (1, 1), (2, 1)]);
    v.checkpoint(&cp).unwrap();
}

#[test]
fn quorum_zero_is_refused() {
    let cp = signed(checkpoint(1, [3; 32], Default::default()), &[(0, 1)]);
    assert_eq!(LogVerifier::new(trust(1, 0)).checkpoint(&cp), Err(TlogError::NoQuorum { have: 1, need: 0 }));
}

fn manifest_entry(n: u8) -> LogEntry {
    LogEntry::Release(seal_proto::release::ReleaseManifest {
        component: seal_proto::release::Component::Enclave,
        platform: PlatformId::Sim,
        measurement: Measurement([n; 48]),
        service_key_version: ServiceKeyVersion(1),
        version: "0.1.0".into(),
        source_commit: "abc".into(),
        serves: None,
    })
}

#[test]
fn inclusion_checks_the_checkpoint_and_the_path() {
    let entries: Vec<LogEntry> = (0..5).map(manifest_entry).collect();
    let tree: Vec<[u8; 32]> = entries.iter().map(leaf_hash).collect();
    let cp = signed(checkpoint(5, root(&tree), Default::default()), &[(0, 1), (1, 2)]);
    let v = LogVerifier::new(trust(2, 2));
    for (i, entry) in entries.iter().enumerate() {
        let proof = TlogProof { checkpoint: cp.clone(), leaf_index: i as u64, audit_path: inclusion_path(i, &tree) };
        assert_eq!(v.inclusion(entry, &proof).unwrap().public_since(), 2);
        // Another entry under this proof.
        assert_eq!(v.inclusion(&manifest_entry(9), &proof), Err(TlogError::BadInclusion));
    }
    let proof = TlogProof { checkpoint: cp.clone(), leaf_index: 1, audit_path: inclusion_path(1, &tree) };
    let mut wrong_index = proof.clone();
    wrong_index.leaf_index = 2;
    assert_eq!(v.inclusion(&entries[1], &wrong_index), Err(TlogError::BadInclusion));
    let mut past_end = proof.clone();
    past_end.leaf_index = 5;
    assert_eq!(v.inclusion(&entries[1], &past_end), Err(TlogError::BadInclusion));
    // The checkpoint is checked first.
    let mut short = proof.clone();
    short.checkpoint.cosignatures.pop();
    assert_eq!(v.inclusion(&entries[1], &short), Err(TlogError::NoQuorum { have: 1, need: 2 }));
    let mut other_root = proof;
    other_root.checkpoint = signed(checkpoint(5, [0; 32], Default::default()), &[(0, 1), (1, 2)]);
    assert_eq!(v.inclusion(&entries[1], &other_root), Err(TlogError::BadInclusion));
}

// --- policy_not_loosened -------------------------------------------------------------------

fn tcb(parts: &[(&str, u64)]) -> Tcb {
    Tcb(parts.iter().map(|(k, v)| (k.to_string(), *v)).collect())
}

fn base_policy() -> ReleaseConstraints {
    let mut p = ReleaseConstraints::default();
    p.min_service_key_version.insert(PlatformId::AzureSnpAci, ServiceKeyVersion(2));
    p.min_tcb.insert(PlatformId::AzureSnpAci, tcb(&[("snp", 22), ("microcode", 213)]));
    p.revoked_keys.insert(KeyId([1; 32]));
    p.revoked_measurements.insert(PlatformId::AzureSnpAci, [Measurement([1; 48])].into());
    p
}

#[test]
fn policy_may_stay_or_tighten() {
    let old = base_policy();
    assert!(policy_not_loosened(&old, &old));
    assert!(policy_not_loosened(&ReleaseConstraints::default(), &old));
    let mut tighter = old.clone();
    tighter.min_service_key_version.insert(PlatformId::AzureSnpAci, ServiceKeyVersion(3));
    tighter.min_service_key_version.insert(PlatformId::AwsNitro, ServiceKeyVersion(1));
    tighter.min_tcb.insert(PlatformId::AzureSnpAci, tcb(&[("snp", 23), ("microcode", 213), ("uvm_svn", 100)]));
    tighter.revoked_keys.insert(KeyId([2; 32]));
    tighter.revoked_measurements.get_mut(&PlatformId::AzureSnpAci).unwrap().insert(Measurement([2; 48]));
    tighter.revoked_measurements.insert(PlatformId::Sim, [Measurement([3; 48])].into());
    assert!(policy_not_loosened(&old, &tighter));
    assert!(!policy_not_loosened(&tighter, &old));
}

#[test]
fn policy_may_not_loosen_anything() {
    let old = base_policy();
    type Change = Box<dyn Fn(&mut ReleaseConstraints)>;
    let loosened: Vec<(&str, Change)> = vec![
        (
            "lower service key version",
            Box::new(|p| {
                p.min_service_key_version.insert(PlatformId::AzureSnpAci, ServiceKeyVersion(1));
            }),
        ),
        (
            "service key platform removed",
            Box::new(|p| {
                p.min_service_key_version.clear();
            }),
        ),
        (
            "lower TCB component",
            Box::new(|p| {
                p.min_tcb.insert(PlatformId::AzureSnpAci, tcb(&[("snp", 21), ("microcode", 999)]));
            }),
        ),
        (
            "TCB component removed",
            Box::new(|p| {
                p.min_tcb.insert(PlatformId::AzureSnpAci, tcb(&[("snp", 22)]));
            }),
        ),
        (
            "TCB platform removed",
            Box::new(|p| {
                p.min_tcb.clear();
            }),
        ),
        (
            "key unrevoked",
            Box::new(|p| {
                p.revoked_keys.clear();
            }),
        ),
        (
            "measurement unrevoked",
            Box::new(|p| {
                p.revoked_measurements.get_mut(&PlatformId::AzureSnpAci).unwrap().clear();
            }),
        ),
        (
            "revoked measurement platform removed",
            Box::new(|p| {
                p.revoked_measurements.clear();
            }),
        ),
    ];
    for (what, change) in loosened {
        let mut new = old.clone();
        change(&mut new);
        assert!(!policy_not_loosened(&old, &new), "{what}");
    }
}

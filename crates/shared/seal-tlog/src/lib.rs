//! Transparency-log primitives. Pure and sync; `seal-verify` builds release
//! and tenant-root verification on top.
//!
//! Trust model: the log operator signs checkpoints; independent witnesses
//! cosign a checkpoint only if it consistently extends, and does not loosen the
//! `ReleaseConstraints` of, every checkpoint they saw before, and stamp the time
//! they saw it. Witnesses must be run by parties other than Seal: their timestamps are what
//! the release time lock measures. Cosignatures from a witness key the checkpoint's own
//! policy revokes do not count toward the quorum.
//!
//! The log also holds every tenant's states (`LogEntry::TenantState`) and signs
//! `StateFreshness` for each tenant's latest with its log key.
//!
//! Merkle hashing and proof verification follow RFC 9162 §2.1 exactly, including its
//! iterative verification algorithms (§2.1.3.2 and §2.1.4.2).

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use seal_crypto::sign::{key_id, verify};
use seal_proto::release::{Checkpoint, LogEntry, SignedCheckpoint, TlogProof, CHECKPOINT_LABEL, COSIGNATURE_LABEL};
use seal_proto::{codec, PublicKey, UnixTime};

#[cfg(feature = "dev")]
pub mod dev;
#[cfg(any(test, feature = "dev"))]
mod merkle;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TlogError {
    #[error("checkpoint not signed by the log key")]
    BadLogSignature,
    #[error("wrong log origin")]
    WrongOrigin,
    #[error("witness quorum not met: {have}/{need}")]
    NoQuorum { have: usize, need: usize },
    #[error("inclusion proof does not match the checkpoint root")]
    BadInclusion,
    #[error("consistency proof invalid")]
    BadConsistency,
}

impl TlogError {
    /// The public code: a log proof that does not check out.
    pub fn code(&self) -> seal_proto::ErrorCode {
        seal_proto::ErrorCode::VerificationFailed
    }
}

/// Who the verifier trusts. Compiled into the guardian and enclave images; shipped in the SDK.
/// Its JSON (keys as hex) is part of `seal_verify::Trust::from_json`'s.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlogTrust {
    pub origin: String,
    pub log_key: PublicKey,
    pub witness_keys: Vec<PublicKey>,
    pub witness_quorum: usize,
}

/// A checkpoint with a verified log signature and witness quorum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    checkpoint: Checkpoint,
    /// Timestamps of valid cosignatures from DISTINCT trusted witnesses, ascending.
    /// `len() >= quorum`.
    times: Vec<UnixTime>,
    quorum: usize,
}

impl VerifiedCheckpoint {
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
    /// Earliest time by which a quorum had seen this checkpoint (`times[quorum-1]`):
    /// "public since" for anything included in it.
    pub fn public_since(&self) -> UnixTime {
        self.times[self.quorum - 1]
    }
    /// Latest time a quorum vouched for (`times[len-quorum]`): freshness.
    pub fn fresh_at(&self) -> UnixTime {
        self.times[self.times.len() - self.quorum]
    }
}

/// RFC 9162 leaf hash: `SHA-256(0x00 || canonical(entry))`.
pub fn leaf_hash(entry: &LogEntry) -> [u8; 32] {
    leaf_hash_bytes(&codec::canonical(entry))
}

fn leaf_hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// RFC 9162 interior node hash: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Right-shifts `fn_` and `sn` together until `fn_` is odd or zero (RFC 9162 §2.1.3.2 4.b.ii).
fn shift_while_even(fn_: &mut u64, sn: &mut u64) {
    while *fn_ & 1 == 0 && *fn_ != 0 {
        *fn_ >>= 1;
        *sn >>= 1;
    }
}

/// Recomputes the root from a leaf and its audit path (RFC 9162 §2.1.3.2). Fails
/// (`BadInclusion`) if `index >= size` or the path has the wrong length for `(index, size)`;
/// the caller compares the result with the checkpoint's root.
pub fn root_from_inclusion(leaf: [u8; 32], index: u64, size: u64, path: &[[u8; 32]]) -> Result<[u8; 32], TlogError> {
    if index >= size {
        return Err(TlogError::BadInclusion);
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = leaf;
    for p in path {
        if sn == 0 {
            return Err(TlogError::BadInclusion);
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            shift_while_even(&mut fn_, &mut sn);
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        return Err(TlogError::BadInclusion);
    }
    Ok(r)
}

/// RFC 9162 §2.1.4.2: `new` is an append-only extension of `old`. Equal sizes need an empty
/// proof and equal roots; an empty `old` tree (root `SHA-256("")`) needs an empty proof.
pub fn verify_consistency(
    old_size: u64,
    old_root: &[u8; 32],
    new_size: u64,
    new_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> Result<(), TlogError> {
    let bad = Err(TlogError::BadConsistency);
    if old_size > new_size {
        return bad;
    }
    if old_size == new_size {
        return if proof.is_empty() && old_root == new_root { Ok(()) } else { bad };
    }
    if old_size == 0 {
        let empty: [u8; 32] = Sha256::digest([]).into();
        return if proof.is_empty() && *old_root == empty { Ok(()) } else { bad };
    }
    if proof.is_empty() {
        return bad;
    }
    let mut path = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let (mut fn_, mut sn) = (old_size - 1, new_size - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (path[0], path[0]);
    for c in &path[1..] {
        if sn == 0 {
            return bad;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            shift_while_even(&mut fn_, &mut sn);
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    if sn == 0 && fr == *old_root && sr == *new_root {
        Ok(())
    } else {
        bad
    }
}

/// Origin, log signature and witness quorum.
pub struct LogVerifier {
    trust: TlogTrust,
}
impl LogVerifier {
    pub fn new(trust: TlogTrust) -> Self {
        Self { trust }
    }
    /// Origin, then the log signature (`CHECKPOINT_LABEL`), then the quorum: valid
    /// cosignatures (`COSIGNATURE_LABEL` over `(checkpoint, timestamp)`) from distinct trusted
    /// witness keys not in the checkpoint's own `policy.revoked_keys`. Unknown, revoked,
    /// duplicate and invalid cosignatures are ignored. A quorum of 0 is refused.
    pub fn checkpoint(&self, cp: &SignedCheckpoint) -> Result<VerifiedCheckpoint, TlogError> {
        let checkpoint = &cp.checkpoint;
        if checkpoint.origin != self.trust.origin {
            return Err(TlogError::WrongOrigin);
        }
        verify(&self.trust.log_key, CHECKPOINT_LABEL, checkpoint, &cp.log_signature)
            .map_err(|_| TlogError::BadLogSignature)?;
        let mut counted = BTreeSet::new();
        let mut times = Vec::new();
        for cosig in &cp.cosignatures {
            let signer = cosig.signature.signer;
            if counted.contains(&signer) || checkpoint.policy.revoked_keys.contains(&signer) {
                continue;
            }
            let Some(key) = self.trust.witness_keys.iter().find(|k| key_id(k) == signer) else {
                continue;
            };
            if verify(key, COSIGNATURE_LABEL, &(checkpoint, cosig.timestamp), &cosig.signature).is_ok() {
                counted.insert(signer);
                times.push(cosig.timestamp);
            }
        }
        let need = self.trust.witness_quorum;
        if need == 0 || times.len() < need {
            return Err(TlogError::NoQuorum { have: times.len(), need });
        }
        times.sort_unstable();
        Ok(VerifiedCheckpoint { checkpoint: checkpoint.clone(), times, quorum: need })
    }

    /// The proof's checkpoint (as `checkpoint`), and `entry`'s leaf at `leaf_index` under its root.
    pub fn inclusion(&self, entry: &LogEntry, proof: &TlogProof) -> Result<VerifiedCheckpoint, TlogError> {
        let verified = self.checkpoint(&proof.checkpoint)?;
        let cp = verified.checkpoint();
        let root = root_from_inclusion(leaf_hash(entry), proof.leaf_index, cp.size, &proof.audit_path)?;
        if root != cp.root_hash {
            return Err(TlogError::BadInclusion);
        }
        Ok(verified)
    }
}

/// Witness rule: `new` must not loosen `old`: every `min_service_key_version` ≥, every
/// `min_tcb` meets the old one (`Tcb::meets`), no platform or TCB component removed, and
/// `revoked_keys` and `revoked_measurements` keep everything `old` revoked.
pub fn policy_not_loosened(
    old: &seal_proto::release::ReleaseConstraints,
    new: &seal_proto::release::ReleaseConstraints,
) -> bool {
    let versions = old
        .min_service_key_version
        .iter()
        .all(|(platform, min)| new.min_service_key_version.get(platform).is_some_and(|v| v >= min));
    let tcbs = old.min_tcb.iter().all(|(platform, min)| new.min_tcb.get(platform).is_some_and(|tcb| tcb.meets(min)));
    let keys = old.revoked_keys.is_subset(&new.revoked_keys);
    let measurements = old
        .revoked_measurements
        .iter()
        .all(|(platform, old_set)| new.revoked_measurements.get(platform).is_some_and(|s| old_set.is_subset(s)));
    versions && tcbs && keys && measurements
}

#[cfg(test)]
mod tests;

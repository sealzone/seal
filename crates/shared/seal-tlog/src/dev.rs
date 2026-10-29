//! Dev/test log (feature `dev`): a file-backed append-only log with one
//! operator key and N in-process witnesses that enforce consistency and
//! `policy_not_loosened`, producing real proofs. The `seal-tlog-dev` binary
//! serves it over HTTP:
//!
//! | Method | Path                  | Body / Response                                |
//! |--------|-----------------------|------------------------------------------------|
//! | POST   | /v1/entries           | `LogEntry` → `{"index": n}`                     |
//! | GET    | /v1/entries/{index}   | → `LogEntry` (404 past the end)                 |
//! | GET    | /v1/proof/{index}     | → `TlogProof` against the latest checkpoint     |
//! | GET    | /v1/checkpoint        | → latest `SignedCheckpoint`                     |
//! | PUT    | /v1/policy            | `ReleaseConstraints` (must not loosen)            |
//! | POST   | /v1/tenants/{tenant}/states    | `SignedTenantState` → `{"index": n}`     |
//! | GET    | /v1/tenants/{tenant}/freshness | → `SignedStateFreshness` for the latest state |
//!
//! `POST /v1/entries` refuses `LogEntry::TenantState`: states go through `/states`, which
//! appends a leaf only for a state signed by `threshold` admin keys of the tenant's latest
//! logged root, with a version above every one logged for the tenant. The log keeps no other
//! tenant data. `/freshness` signs for the latest logged state only, at the time of the call.
//! `GET /v1/checkpoint` serves the latest checkpoint while it covers the whole tree and is
//! younger than `CHECKPOINT_REUSE_SECS`, and otherwise signs and cosigns a new one, so callers
//! (browsers on the transparency page among them) cannot make the log sign on every request.
//! Entries are at most `MAX_ENTRY_BYTES`.
//!
//! Tests shift witness timestamps with `DevLog::set_clock_offset` to cross time locks.
//!
//! On disk, `dir` holds `entries` (each leaf as a big-endian `u32` length and the
//! `canonical(LogEntry)` bytes) and `state` (`canonical` of the policy, every witness's last
//! cosigned checkpoint and the latest signed checkpoint). Reopening checks the entries against
//! what the witnesses saw, so a truncated or rewritten log is refused.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write as _};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use seal_crypto::sign::{admin_key_id, verify, verify_admin, SigningKey};
use seal_proto::codec::{self, labeled_digest};
use seal_proto::release::{
    Checkpoint, Cosignature, LogEntry, ReleaseConstraints, SignedCheckpoint, TenantStateLeaf, TlogProof,
    CHECKPOINT_LABEL, COSIGNATURE_LABEL,
};
use seal_proto::state::{
    root_id, LoggedState, SignedStateFreshness, SignedTenantState, StateFreshness, TenantRoot, STATE_FRESHNESS_LABEL,
    TENANT_STATE_LABEL,
};
use seal_proto::{KeyId, TenantId, UnixTime};

use crate::{leaf_hash, merkle, policy_not_loosened, verify_consistency, TlogTrust};

/// How long `GET /v1/checkpoint` serves one checkpoint for an unchanged tree
/// (`DevLog::recent_checkpoint`); witnessed time lags by at most this much more.
pub const CHECKPOINT_REUSE_SECS: u64 = 5;
/// The dev log's origin unless `open_with_origin` names another.
pub const ORIGIN: &str = "dev.log.seal.zone/v1";
/// The largest entry (`canonical(LogEntry)`) the log appends; anyone can append, so this bounds
/// what one request adds to the log's disk and memory.
pub const MAX_ENTRY_BYTES: usize = 64 * 1024;

pub struct DevLog {
    dir: PathBuf,
    origin: String,
    log_key: SigningKey,
    witnesses: Vec<Witness>,
    quorum: usize,
    entries: Vec<LogEntry>,
    leaves: Vec<[u8; 32]>,
    policy: ReleaseConstraints,
    latest: Option<SignedCheckpoint>,
    clock_offset: i64,
}

/// An in-process witness: cosigns a checkpoint only if the log signed it, it consistently
/// extends the last one this witness cosigned, and it does not loosen that one's policy.
struct Witness {
    key: SigningKey,
    seen: Option<Checkpoint>,
}

impl Witness {
    fn cosign(
        &mut self,
        trust: &TlogTrust,
        cp: &SignedCheckpoint,
        proof: &[[u8; 32]],
        now: UnixTime,
    ) -> Result<Cosignature, String> {
        let c = &cp.checkpoint;
        if c.origin != trust.origin {
            return Err("wrong origin".into());
        }
        verify(&trust.log_key, CHECKPOINT_LABEL, c, &cp.log_signature).map_err(|_| "bad log signature")?;
        if let Some(seen) = &self.seen {
            verify_consistency(seen.size, &seen.root_hash, c.size, &c.root_hash, proof)
                .map_err(|_| "not consistent with the last checkpoint")?;
            if !policy_not_loosened(&seen.policy, &c.policy) {
                return Err("loosens the policy".into());
            }
        }
        let signature = self.key.sign(COSIGNATURE_LABEL, &(c, now));
        self.seen = Some(c.clone());
        Ok(Cosignature { timestamp: now, signature })
    }
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    log_key_id: KeyId,
    policy: ReleaseConstraints,
    witnesses: Vec<Option<Checkpoint>>,
    latest: Option<SignedCheckpoint>,
}

fn derive_seed(label: &str, index: u32, seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.update(index.to_be_bytes());
    h.update(seed);
    h.finalize().into()
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// `threshold` distinct admin keys of `root` signed `state`. Each signer's first signature is
/// the only one tried, so repeating a signer cannot hold the log's lock for longer.
fn admins_signed(root: &TenantRoot, state: &SignedTenantState) -> bool {
    let need = usize::from(root.threshold);
    let mut counted = BTreeSet::new();
    let mut tried = BTreeSet::new();
    for sig in &state.signatures {
        if !tried.insert(sig.signer) {
            continue;
        }
        let Some(key) = root.admin_keys.iter().find(|k| admin_key_id(k) == sig.signer) else {
            continue;
        };
        if verify_admin(key, TENANT_STATE_LABEL, &state.body, sig).is_ok() {
            counted.insert(sig.signer);
        }
    }
    need > 0 && counted.len() >= need
}

impl DevLog {
    /// Opens or creates a log at `dir` with deterministic keys from `seed` and `witnesses` witnesses.
    pub fn open(dir: &std::path::Path, seed: [u8; 32], witnesses: usize, quorum: usize) -> std::io::Result<Self> {
        Self::open_with_origin(dir, seed, witnesses, quorum, ORIGIN)
    }

    /// `open` with the origin its checkpoints name; a log is reopened with the origin it was
    /// created with.
    pub fn open_with_origin(
        dir: &std::path::Path,
        seed: [u8; 32],
        witnesses: usize,
        quorum: usize,
        origin: &str,
    ) -> std::io::Result<Self> {
        if origin.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty origin"));
        }
        if quorum == 0 || quorum > witnesses {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "need 1 <= quorum <= witnesses"));
        }
        fs::create_dir_all(dir)?;
        let log_key = SigningKey::from_seed(&derive_seed("seal-tlog-dev/log", 0, &seed));
        let mut log = Self {
            dir: dir.to_path_buf(),
            origin: origin.into(),
            witnesses: (0..witnesses)
                .map(|i| Witness {
                    key: SigningKey::from_seed(&derive_seed("seal-tlog-dev/witness", i as u32, &seed)),
                    seen: None,
                })
                .collect(),
            log_key,
            quorum,
            entries: Vec::new(),
            leaves: Vec::new(),
            policy: ReleaseConstraints::default(),
            latest: None,
            clock_offset: 0,
        };
        log.load()?;
        Ok(log)
    }

    fn entries_path(&self) -> PathBuf {
        self.dir.join("entries")
    }
    fn state_path(&self) -> PathBuf {
        self.dir.join("state")
    }

    fn load(&mut self) -> io::Result<()> {
        match fs::read(self.entries_path()) {
            Ok(bytes) => {
                let mut rest = &bytes[..];
                while !rest.is_empty() {
                    let (len, tail) = rest.split_at_checked(4).ok_or_else(|| invalid("truncated entry"))?;
                    let len = u32::from_be_bytes(len.try_into().expect("4 bytes")) as usize;
                    let (body, tail) = tail.split_at_checked(len).ok_or_else(|| invalid("truncated entry"))?;
                    let entry: LogEntry = codec::from_canonical(body).map_err(|e| invalid(e.to_string()))?;
                    self.leaves.push(leaf_hash(&entry));
                    self.entries.push(entry);
                    rest = tail;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let state = match fs::read(self.state_path()) {
            Ok(bytes) => codec::from_canonical::<Persisted>(&bytes).map_err(|e| invalid(e.to_string()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !self.entries.is_empty() {
                    return Err(invalid("entries without state"));
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        if state.log_key_id != self.log_key.key_id() {
            return Err(invalid("the log was created with another seed"));
        }
        if state.latest.as_ref().is_some_and(|cp| cp.checkpoint.origin != self.origin) {
            return Err(invalid("the log was created with another origin"));
        }
        if state.witnesses.len() != self.witnesses.len() {
            return Err(invalid("the log was created with another number of witnesses"));
        }
        for (witness, seen) in self.witnesses.iter_mut().zip(state.witnesses) {
            if let Some(seen) = &seen {
                let size = usize::try_from(seen.size).map_err(|_| invalid("size"))?;
                if size > self.leaves.len() || merkle::root(&self.leaves[..size]) != seen.root_hash {
                    return Err(invalid("entries do not match what the witnesses saw"));
                }
            }
            witness.seen = seen;
        }
        self.policy = state.policy;
        self.latest = state.latest;
        Ok(())
    }

    fn persist(&self) -> io::Result<()> {
        let state = Persisted {
            log_key_id: self.log_key.key_id(),
            policy: self.policy.clone(),
            witnesses: self.witnesses.iter().map(|w| w.seen.clone()).collect(),
            latest: self.latest.clone(),
        };
        let tmp = self.dir.join("state.tmp");
        fs::write(&tmp, codec::canonical(&state))?;
        fs::rename(tmp, self.state_path())
    }

    /// The log's clock: the wall clock plus `set_clock_offset`'s offset.
    pub fn now(&self) -> UnixTime {
        let wall = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let wall = i64::try_from(wall).unwrap_or(i64::MAX);
        u64::try_from(wall.saturating_add(self.clock_offset)).unwrap_or(0)
    }

    pub fn trust(&self) -> TlogTrust {
        TlogTrust {
            origin: self.origin.clone(),
            log_key: self.log_key.public_key(),
            witness_keys: self.witnesses.iter().map(|w| w.key.public_key()).collect(),
            witness_quorum: self.quorum,
        }
    }

    /// The number of entries.
    pub fn size(&self) -> u64 {
        self.entries.len() as u64
    }

    /// The entry at `index`, if the log has one.
    pub fn entry(&self, index: u64) -> Option<&LogEntry> {
        self.entries.get(usize::try_from(index).ok()?)
    }

    /// Appends any entry but `LogEntry::TenantState` (`InvalidInput`), which goes through
    /// `append_state`.
    pub fn append(&mut self, entry: LogEntry) -> std::io::Result<u64> {
        if matches!(entry, LogEntry::TenantState(_)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "tenant states go through append_state"));
        }
        self.push(entry)
    }

    fn push(&mut self, entry: LogEntry) -> io::Result<u64> {
        let body = codec::canonical(&entry);
        if body.len() > MAX_ENTRY_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "entry too large"));
        }
        let len =
            u32::try_from(body.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "entry too large"))?;
        let mut file = fs::OpenOptions::new().create(true).append(true).open(self.entries_path())?;
        file.write_all(&[&len.to_be_bytes()[..], &body].concat())?;
        file.sync_data()?;
        self.leaves.push(leaf_hash(&entry));
        self.entries.push(entry);
        Ok(self.entries.len() as u64 - 1)
    }

    /// Signs and cosigns a checkpoint over the current tree (witnesses stamp now + offset).
    pub fn checkpoint(&mut self) -> SignedCheckpoint {
        let size = self.leaves.len();
        let checkpoint = Checkpoint {
            origin: self.origin.clone(),
            size: size as u64,
            root_hash: merkle::root(&self.leaves),
            policy: self.policy.clone(),
        };
        let mut cp = SignedCheckpoint {
            log_signature: self.log_key.sign(CHECKPOINT_LABEL, &checkpoint),
            checkpoint,
            cosignatures: Vec::new(),
        };
        let (trust, now) = (self.trust(), self.now());
        for witness in &mut self.witnesses {
            let proof = match &witness.seen {
                Some(seen) if seen.size <= size as u64 => merkle::consistency_proof(seen.size as usize, &self.leaves),
                _ => Vec::new(),
            };
            if let Ok(cosig) = witness.cosign(&trust, &cp, &proof, now) {
                cp.cosignatures.push(cosig);
            }
        }
        self.latest = Some(cp.clone());
        self.persist().expect("dev log: cannot write its state");
        cp
    }

    /// The latest checkpoint while it covers every entry under the current policy and its
    /// witnesses stamped it at most `max_age` seconds ago, else a new one (`checkpoint`).
    pub fn recent_checkpoint(&mut self, max_age: u64) -> SignedCheckpoint {
        let now = self.now();
        let recent = self.latest.as_ref().filter(|cp| {
            let stamped = cp.cosignatures.iter().map(|c| c.timestamp).min();
            cp.checkpoint.size == self.size()
                && cp.checkpoint.policy == self.policy
                && cp.cosignatures.len() >= self.quorum
                && stamped.is_some_and(|at| at <= now && now < at.saturating_add(max_age))
        });
        match recent {
            Some(cp) => cp.clone(),
            None => self.checkpoint(),
        }
    }

    /// Inclusion proof against the latest checkpoint (cosigning a new one if needed).
    /// Panics if `index` is not in the log.
    pub fn prove(&mut self, index: u64) -> TlogProof {
        assert!(index < self.size(), "entry {index} is not in the log");
        let checkpoint = match &self.latest {
            Some(cp) if cp.checkpoint.size > index => cp.clone(),
            _ => self.checkpoint(),
        };
        let size = checkpoint.checkpoint.size as usize;
        TlogProof {
            audit_path: merkle::inclusion_path(index as usize, &self.leaves[..size]),
            leaf_index: index,
            checkpoint,
        }
    }

    /// Replaces the policy of later checkpoints, unless it loosens the current one.
    pub fn set_policy(&mut self, policy: ReleaseConstraints) -> Result<(), String> {
        if !policy_not_loosened(&self.policy, &policy) {
            return Err("the policy loosens the current one".into());
        }
        let old = std::mem::replace(&mut self.policy, policy);
        if let Err(e) = self.persist() {
            self.policy = old;
            return Err(format!("cannot write the log state: {e}"));
        }
        Ok(())
    }

    /// The highest-version root logged for `tenant` (the later one on a tie), and the root id
    /// of the tenant's first logged version 1.
    fn latest_root(&self, tenant: &TenantId) -> Option<(&TenantRoot, seal_proto::TenantRootId)> {
        let roots = || {
            self.entries.iter().filter_map(|e| match e {
                LogEntry::TenantRoot(r) if &r.tenant == tenant => Some(r),
                _ => None,
            })
        };
        let latest = roots().fold(None::<&TenantRoot>, |best, r| match best {
            Some(b) if b.version > r.version => Some(b),
            _ => Some(r),
        })?;
        let v1 = roots().find(|r| r.version == 1)?;
        Some((latest, root_id(v1)))
    }

    fn latest_state(&self, tenant: &TenantId) -> Option<&TenantStateLeaf> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                LogEntry::TenantState(leaf) if &leaf.tenant == tenant => Some(leaf),
                _ => None,
            })
            .max_by_key(|leaf| leaf.version)
    }

    /// Appends `LogEntry::TenantState` for `state` after the checks above.
    pub fn append_state(&mut self, state: &SignedTenantState) -> Result<u64, String> {
        let tenant = &state.body.tenant;
        let (root, root_id) = self.latest_root(tenant).ok_or("the tenant has no logged root version 1")?;
        if !admins_signed(root, state) {
            return Err("not signed by the threshold of the tenant's latest root".into());
        }
        if self.latest_state(tenant).is_some_and(|leaf| leaf.version >= state.body.version) {
            return Err("the version is not above every logged state of the tenant".into());
        }
        let leaf = TenantStateLeaf {
            tenant: tenant.clone(),
            root_id,
            version: state.body.version,
            digest: labeled_digest(TENANT_STATE_LABEL, &state.body),
        };
        self.push(LogEntry::TenantState(leaf)).map_err(|e| format!("cannot append: {e}"))
    }

    /// `append_state` and the inclusion proof right after, as `TenantBundle::states` carries it.
    pub fn append_logged_state(&mut self, state: &SignedTenantState) -> Result<LoggedState, String> {
        let index = self.append_state(state)?;
        Ok(LoggedState { state: state.clone(), proof: self.prove(index) })
    }

    /// `StateFreshness` for the tenant's latest logged state, signed with the log key, at now + offset.
    pub fn freshness(&mut self, tenant: &TenantId) -> Option<SignedStateFreshness> {
        let leaf = self.latest_state(tenant)?;
        let statement = StateFreshness {
            tenant: leaf.tenant.clone(),
            version: leaf.version,
            digest: leaf.digest,
            signed_at: self.now(),
        };
        Some(self.log_key.sign_into(STATE_FRESHNESS_LABEL, statement))
    }

    pub fn set_clock_offset(&mut self, secs: i64) {
        self.clock_offset = secs;
    }
}

#[cfg(test)]
mod tests;

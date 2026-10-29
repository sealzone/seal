//! Pure verification of everything signed and logged. No IO, no clock (time is an argument).

#![forbid(unsafe_code)]

pub mod attestation;
pub mod change;
pub mod telemetry;
mod window;

use std::collections::{BTreeMap, BTreeSet};

use seal_crypto::sign::{admin_key_id, key_id, verify, verify_admin, verify_threshold};
use seal_proto::codec::{digest, labeled_digest};
use seal_proto::integrity::{validate_code, IntegritySignal, SignalSource, SignedSignal, SIGNAL_LABEL};
use seal_proto::release::{
    LogEntry, ReleaseConstraints, ReleaseEvidence, ReleaseManifest, ServiceKeyCertificate, SignedCheckpoint,
    SignedServiceKeyCertificate, TenantStateLeaf, AUDITOR_LABEL, FRESH_CHECKPOINT_SECS, RELEASE_LABEL,
    SERVICE_KEY_CERTIFICATE_LABEL,
};
use seal_proto::session::{SessionEnd, SignedSessionEnd, SESSION_END_LABEL};
use seal_proto::signed::Signed;
use seal_proto::state::{
    LoggedRoot, LoggedState, SignedStateFreshness, SignedTenantAnchor, TenantAnchor, TenantBundle, TenantRoot,
    TenantState, STATE_FRESHNESS_LABEL, TENANT_ANCHOR_LABEL, TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::{PlatformId, PublicKey, TenantId, TenantRootId, TrustedTime, UnixTime};
use seal_tlog::{policy_not_loosened, LogVerifier, TlogError};

pub use change::Change;
pub use window::Public;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("release signatures: {0}")]
    ReleaseSignatures(String),
    #[error("auditor signature missing or invalid")]
    Auditor,
    #[error("log: {0}")]
    Log(#[from] seal_tlog::TlogError),
    #[error("time lock: public since {public_since}, needs {needed_secs}s, now {now}")]
    TimeLock { public_since: UnixTime, needed_secs: u64, now: UnixTime },
    #[error("fresh checkpoint too old or older than the inclusion checkpoint")]
    StaleCheckpoint,
    #[error("release service key version below the log's minimum")]
    RetiredServiceKeyVersion,
    #[error("platform TCB below the log's minimum")]
    TcbTooLow,
    #[error("tenant root chain: {0}")]
    RootChain(String),
    #[error("tenant state: {0}")]
    State(String),
    #[error("bundle is for another tenant")]
    WrongTenant,
    #[error("no current freshness statement for this tenant state")]
    StateNotFresh,
    #[error("revoked by the log's policy")]
    Revoked,
    #[error("service key certificate: {0}")]
    Certificate(String),
}

impl VerifyError {
    /// The public code: everything here means the signed evidence did not check out.
    pub fn code(&self) -> seal_proto::ErrorCode {
        seal_proto::ErrorCode::VerificationFailed
    }
}

/// Everything a component trusts to accept releases and tenants. One value is compiled into
/// the guardian and the enclave and shipped with SDKs. Its JSON is `trust.json`'s
/// (`Trust::from_json`).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub releases: ReleaseTrust,
    pub tenants: TenantTrust,
    /// Each platform's guardian key (`PlatformMasterKey::guardian_key`), fixed for the
    /// platform's life. Published once when the platform root is created, attested by the
    /// guardian. SDKs check `ServiceKeyCertificate`s with it.
    #[serde(default)]
    pub guardians: BTreeMap<PlatformId, PublicKey>,
}

impl Trust {
    /// A trust from its JSON (`deploy/example/trust.json` is one): `releases`, `tenants` and
    /// `guardians`, keys as hex, no unknown fields. `Malformed` also when a threshold or quorum
    /// is 0 or more than its keys, which no signature set could meet or any would.
    pub fn from_json(json: &[u8]) -> Result<Self, TrustError> {
        let trust: Trust = serde_json::from_slice(json).map_err(|e| TrustError::Malformed(e.to_string()))?;
        let check = |what: &str, need: usize, keys: usize| match need {
            0 => Err(TrustError::Malformed(format!("{what} is 0"))),
            n if n > keys => Err(TrustError::Malformed(format!("{what} {n} is more than its {keys} keys"))),
            _ => Ok(()),
        };
        check("releases.release_threshold", trust.releases.release_threshold, trust.releases.release_keys.len())?;
        check("tenants.registrar_threshold", trust.tenants.registrar_threshold, trust.tenants.registrar_keys.len())?;
        for (what, tlog) in [("releases.tlog", &trust.releases.tlog), ("tenants.tlog", &trust.tenants.tlog)] {
            check(&format!("{what}.witness_quorum"), tlog.witness_quorum, tlog.witness_keys.len())?;
        }
        Ok(trust)
    }
}

/// `Trust::from_json` refused its input.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustError {
    #[error("trust: {0}")]
    Malformed(String),
}

impl TrustError {
    /// The public code: a trust that does not parse is a bad argument.
    pub fn code(&self) -> seal_proto::ErrorCode {
        seal_proto::ErrorCode::BadRequest
    }
}

/// Who may approve enclave releases. Compiled into the guardian; shipped with SDKs.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTrust {
    pub tlog: seal_tlog::TlogTrust,
    pub release_keys: Vec<PublicKey>,
    pub release_threshold: usize,
    #[serde(default)]
    pub required_auditor: Option<PublicKey>,
    /// Guardian: 14 days. SDKs and enclaves: 0, because they also require the guardian's
    /// `ServiceKeyCertificate`, which exists only for keys the guardian released after the wait.
    pub time_lock_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRelease {
    manifest: ReleaseManifest,
    public_since: UnixTime,
    /// From the fresh checkpoint: the rules in force now.
    policy: ReleaseConstraints,
}

/// M-of-N signatures on the manifest; auditor if required; manifest included in
/// the log; fresh checkpoint cosigned by a quorum within `FRESH_CHECKPOINT_SECS` of `latest`
/// and no smaller than the inclusion checkpoint; `public_since + time_lock_secs` no later than
/// either `earliest` or the fresh checkpoint's witness time (`fresh_at`), so the lock holds by
/// witness clocks even if the local clock is wrong; manifest `service_key_version` ≥ the fresh
/// policy's minimum for its platform. The fresh policy's revocations apply: signatures from
/// `revoked_keys` (release, auditor, witness) do not count, and a measurement in
/// `revoked_measurements` is refused (`Revoked`).
///
/// "Within" means `latest < fresh_at + FRESH_CHECKPOINT_SECS`. The evidence carries no
/// consistency proof between its two checkpoints, so "no smaller" is checked as: the fresh
/// tree has at least as many leaves (`StaleCheckpoint` otherwise); trees of equal size have
/// equal roots; and the fresh policy does not loosen the inclusion checkpoint's
/// (`policy_not_loosened`). The last two failing mean a fork or a loosening no honest witness
/// cosigns (`Log(BadConsistency)`); append-only growth in between is what the witnesses check.
pub struct ReleaseVerifier {
    trust: ReleaseTrust,
}
impl ReleaseVerifier {
    pub fn new(trust: ReleaseTrust) -> Self {
        Self { trust }
    }
    /// The time lock uses `time.earliest()`; checkpoint freshness uses `time.latest()`.
    /// Clients without a trusted clock pass `TrustedTime::exact`.
    pub fn verify(&self, evidence: &ReleaseEvidence, time: &TrustedTime) -> Result<VerifiedRelease, VerifyError> {
        let trust = &self.trust;
        // The fresh checkpoint's policy decides which keys still count, everywhere below.
        let fresh = LogVerifier::new(trust.tlog.clone()).checkpoint(&evidence.fresh)?;
        let policy = fresh.checkpoint().policy.clone();
        let live = |keys: &[PublicKey]| -> Vec<PublicKey> {
            keys.iter().filter(|k| !policy.revoked_keys.contains(&key_id(k))).copied().collect()
        };

        let manifest = &evidence.manifest;
        verify_threshold(&live(&trust.release_keys), trust.release_threshold, RELEASE_LABEL, manifest)
            .map_err(|e| VerifyError::ReleaseSignatures(e.to_string()))?;
        if let Some(auditor) = &trust.required_auditor {
            let sig = evidence.auditor.as_ref().ok_or(VerifyError::Auditor)?;
            if policy.revoked_keys.contains(&key_id(auditor)) {
                return Err(VerifyError::Auditor);
            }
            verify(auditor, AUDITOR_LABEL, &manifest.body, sig).map_err(|_| VerifyError::Auditor)?;
        }

        let mut inclusion_trust = trust.tlog.clone();
        inclusion_trust.witness_keys = live(&inclusion_trust.witness_keys);
        let included = LogVerifier::new(inclusion_trust)
            .inclusion(&LogEntry::Release(manifest.body.clone()), &evidence.included)?;

        if time.latest() >= fresh.fresh_at().saturating_add(FRESH_CHECKPOINT_SECS) {
            return Err(VerifyError::StaleCheckpoint);
        }
        let (old, new) = (included.checkpoint(), fresh.checkpoint());
        if new.size < old.size {
            return Err(VerifyError::StaleCheckpoint);
        }
        if (new.size == old.size && new.root_hash != old.root_hash) || !policy_not_loosened(&old.policy, &new.policy) {
            return Err(VerifyError::Log(TlogError::BadConsistency));
        }

        let release = &manifest.body;
        if policy
            .revoked_measurements
            .get(&release.platform)
            .is_some_and(|revoked| revoked.contains(&release.measurement))
        {
            return Err(VerifyError::Revoked);
        }
        if policy.min_service_key_version.get(&release.platform).is_some_and(|min| release.service_key_version < *min) {
            return Err(VerifyError::RetiredServiceKeyVersion);
        }

        let public_since = included.public_since();
        let now = lock_time(time, fresh.fresh_at());
        if public_since.saturating_add(trust.time_lock_secs) > now {
            return Err(VerifyError::TimeLock { public_since, needed_secs: trust.time_lock_secs, now });
        }
        Ok(VerifiedRelease { manifest: release.clone(), public_since, policy })
    }
}

/// When a time lock is measured: the earlier of `time.earliest()` and the log's witnessed
/// time, so the lock holds by witness clocks even if the local clock is ahead. The release
/// time lock and the tenant pending window both pass once `public_since + secs` is at most
/// this.
pub(crate) fn lock_time(time: &TrustedTime, witnessed_at: UnixTime) -> UnixTime {
    time.earliest().min(witnessed_at)
}

/// Evidence TCB passes the policy's minimum for `platform` component by component, a family's
/// floor only for that family, and a family the floor does not list refused (`Tcb::passes`;
/// absent minimum = accept).
impl ReleaseVerifier {
    pub fn check_tcb(
        policy: &ReleaseConstraints,
        platform: PlatformId,
        tcb: &seal_proto::release::Tcb,
    ) -> Result<(), VerifyError> {
        match policy.min_tcb.get(&platform) {
            Some(min) if !tcb.passes(min) => Err(VerifyError::TcbTooLow),
            _ => Ok(()),
        }
    }
}

/// Who may create tenants (sign root version 1).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantTrust {
    pub tlog: seal_tlog::TlogTrust,
    pub registrar_keys: Vec<PublicKey>,
    pub registrar_threshold: usize,
}

/// A tenant after every signature and log proof checked out. Fields are read-only.
///
/// `root()` and `state()` are the documents **in force**, which enclaves and the guardian obey;
/// newer logged ones may be pending (`pending`, `seal_verify::change`).
#[derive(Clone, Debug)]
pub struct VerifiedTenant {
    root_id: TenantRootId,
    /// When the earliest-expiring required freshness statement for the latest state runs out,
    /// by the shorter window of the latest state and the state in force.
    fresh_until: UnixTime,
    /// The chain, versions 1..=N.
    roots: Vec<Public<TenantRoot>>,
    /// Consecutive versions, oldest first, from one known to have been in force to the latest.
    states: Vec<Public<TenantState>>,
    /// Index into `states`.
    in_force: usize,
    /// When it took effect, at the latest (by the log's witnessed time).
    in_force_since: UnixTime,
    /// The time the window was measured at (`lock_time`).
    checked_at: UnixTime,
    signals: Vec<IntegritySignal>,
    ended_sessions: Vec<SessionEnd>,
}

/// A state newer than the one in force, waiting or never to apply.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Pending {
    pub version: u64,
    pub root_version: u64,
    /// The state compared with the one in force; `Widening` also when its newer root widens
    /// the root in force.
    pub change: Change,
    pub public_since: UnixTime,
    /// When it takes effect unless a newer state does first, by the log's witnessed time.
    /// `None`: never (signed under an older root than the one in force).
    pub effective_at: Option<UnixTime>,
}

impl VerifiedTenant {
    /// The chain's `TenantRootId` (from its version 1).
    pub fn root_id(&self) -> &TenantRootId {
        &self.root_id
    }
    /// The root in force: the one that signed `state()`.
    pub fn root(&self) -> &TenantRoot {
        let version = self.state().root_version;
        self.roots[usize::try_from(version - 1).expect("verified root version")].body()
    }
    /// After this, the state must not be used: holders refuse service until a newer
    /// statement arrives (`ErrorCode::Unavailable`).
    pub fn fresh_until(&self) -> UnixTime {
        self.fresh_until
    }
    /// The state in force.
    pub fn state(&self) -> &TenantState {
        self.states[self.in_force].body()
    }
    /// Since when `state()` is in force, at the latest.
    pub fn in_force_since(&self) -> UnixTime {
        self.in_force_since
    }
    /// The latest logged root (the end of the chain).
    pub fn latest_root(&self) -> &TenantRoot {
        self.roots.last().expect("a verified chain is not empty").body()
    }
    /// The latest logged state, the one the freshness statements are for.
    pub fn latest_state(&self) -> &TenantState {
        self.states.last().expect("verified states are not empty").body()
    }
    /// The verified chain, versions 1..=N, with when each became public.
    pub fn roots(&self) -> &[Public<TenantRoot>] {
        &self.roots
    }
    /// The verified states, oldest first: from one known to have been in force through the
    /// latest.
    pub fn states(&self) -> &[Public<TenantState>] {
        &self.states
    }
    /// The time pending windows were measured at: the earlier of the verifier's clock and the
    /// log's witnessed time.
    pub fn checked_at(&self) -> UnixTime {
        self.checked_at
    }
    /// The states newer than the one in force, oldest first.
    pub fn pending(&self) -> Vec<Pending> {
        let in_force = self.state();
        (self.in_force + 1..self.states.len())
            .map(|k| {
                let doc = self.states[k].body();
                let mut change = change::classify_state(in_force, doc);
                if doc.root_version > in_force.root_version {
                    let newer = self.roots[usize::try_from(doc.root_version - 1).expect("verified")].body();
                    change = change.max(change::classify_root(self.root(), newer));
                }
                Pending {
                    version: doc.version,
                    root_version: doc.root_version,
                    change,
                    public_since: self.states[k].public_since,
                    effective_at: window::admissible_at(&self.roots, &self.states, self.in_force, k)
                        .map(|t| t.max(self.in_force_since)),
                }
            })
            .collect()
    }
    /// How state `version` (and its root, when newer) differs from the documents in force:
    /// root differences first. `None` when the verified states do not hold it.
    pub fn differences(&self, version: u64) -> Option<Vec<change::Difference>> {
        let state = self.states.iter().map(Public::body).find(|s| s.version == version)?;
        let mut out = Vec::new();
        if state.root_version > self.root().version {
            let root = self.roots.get(usize::try_from(state.root_version - 1).ok()?)?;
            out.extend(change::diff_roots(self.root(), root.body()));
        }
        out.extend(change::diff_states(self.state(), state));
        Some(out)
    }
    /// Verified integrity signals, deduplicated; evaluated under `state().integrity`.
    pub fn signals(&self) -> &[IntegritySignal] {
        &self.signals
    }
    /// Verified early session ends, deduplicated by `session_id`.
    pub fn ended_sessions(&self) -> &[SessionEnd] {
        &self.ended_sessions
    }
    /// The end of `session_id`, if it was ended early.
    pub fn session_end(&self, session_id: &[u8; 16]) -> Option<&SessionEnd> {
        self.ended_sessions.iter().find(|e| &e.session_id == session_id)
    }
    /// Merge for caches, which remember the state in force: keeps the longer chain and the
    /// newer latest state, the later `fresh_until`, and unions signals and ended sessions,
    /// never dropping one. The state in force never goes back: if `newer` (verified without
    /// memory) puts an older state in force than `self`, `self`'s moves on from where it is
    /// over `newer`'s states, at `newer`'s time. Errors if `newer` is older than `self` in root
    /// or latest state version, or names another root id; also if it holds a different root
    /// or state under the same version (equivocation). The later `fresh_until` is kept for the
    /// same latest state; when it advances, `newer`'s applies, since one state's freshness
    /// never carries over to another. On error `self` is unchanged.
    pub fn merge(&mut self, newer: VerifiedTenant) -> Result<(), VerifyError> {
        if newer.root_id != self.root_id {
            return Err(VerifyError::RootChain("another root id".into()));
        }
        if newer.roots.len() < self.roots.len() {
            return Err(VerifyError::RootChain("older root version".into()));
        }
        if self.roots.iter().zip(&newer.roots).any(|(a, b)| a.body() != b.body()) {
            return Err(VerifyError::RootChain("two roots with the same version".into()));
        }
        let (latest, newer_latest) = (self.latest_state().version, newer.latest_state().version);
        if newer_latest < latest {
            return Err(VerifyError::State("older state version".into()));
        }
        for s in &self.states {
            if newer.states.iter().any(|n| n.body().version == s.body().version && n.body() != s.body()) {
                return Err(VerifyError::State("two states with the same version".into()));
            }
        }
        let fresh_until =
            if newer_latest > latest { newer.fresh_until } else { self.fresh_until.max(newer.fresh_until) };

        let (states, in_force, in_force_since) = if newer.state().version >= self.state().version {
            (newer.states, newer.in_force, newer.in_force_since)
        } else {
            let from = self.state().version;
            let mut states = vec![self.states[self.in_force].clone()];
            states.extend(newer.states.into_iter().filter(|s| s.body().version > from));
            let (k, since) = window::advance(&newer.roots, &states, 0, self.in_force_since, newer.checked_at);
            (states, k, since)
        };
        self.fresh_until = fresh_until;
        self.roots = newer.roots;
        self.states = states;
        self.in_force = in_force;
        self.in_force_since = in_force_since;
        self.checked_at = self.checked_at.max(newer.checked_at);
        let mut seen: BTreeSet<[u8; 32]> = self.signals.iter().map(digest).collect();
        for signal in newer.signals {
            if seen.insert(digest(&signal)) {
                self.signals.push(signal);
            }
        }
        for end in newer.ended_sessions {
            if self.session_end(&end.session_id).is_none() {
                self.ended_sessions.push(end);
            }
        }
        Ok(())
    }
}

/// Root chain from version 1 (registrar-signed) with every link logged and signed by
/// `threshold` keys of the previous link; latest state for `tenant`, signed by the latest root,
/// `state.root_version == latest.version`; freshness: a `StateFreshness` for exactly the latest
/// state (version and digest) signed by the log key, and, when `state.freshness_keys` is
/// non-empty, one signed by one of them, each with `signed_at <= time.latest() < signed_at +
/// window`, the window being the shorter `TenantState::freshness_window` of the latest state
/// and the state in force (`StateNotFresh` otherwise, which also stops a truncated root chain,
/// since the latest state names the latest root); the bundle's `states`: consecutive versions
/// ending with the latest, each for `tenant`, signed by the root it names (no older than the
/// previous state's), logged in version order under this chain's root id; then the state in
/// force (`window`), from the newest anchor to `lock_time(time, witnessed)`, where `witnessed`
/// is the latest `fresh_at` of every checkpoint in the bundle. Anchors are the documents' own
/// (`window`) and the bundle's `TenantAnchor`s signed by one of `anchor_keys` for this tenant
/// and chain, dated no later than that time, for a state in `states` (`State` error when there
/// is none); signals for `tenant` with a valid `code`, signed by one of `telemetry_keys`
/// (sources `Enclave` and `Sdk`) or by the in-force state's `integrity.sources[source]`
/// (source `External`); session ends for `tenant` signed by one of `telemetry_keys` under
/// `SESSION_END_LABEL`. Invalid signals and session ends are dropped, not fatal, so junk
/// cannot suspend anyone or end a session.
///
/// Signals are deduplicated by content, session ends by `session_id` (the first valid one
/// counts); both keep bundle order. For each required freshness signer the latest valid
/// statement counts, and `fresh_until` is the earliest of their expiries.
pub struct TenantVerifier {
    trust: TenantTrust,
    telemetry_keys: Vec<PublicKey>,
    anchor_keys: Vec<PublicKey>,
}
impl TenantVerifier {
    pub fn new(trust: TenantTrust, telemetry_keys: Vec<PublicKey>) -> Self {
        Self { trust, telemetry_keys, anchor_keys: Vec::new() }
    }

    /// Also start from `TenantAnchor`s these guardian keys signed: an enclave its platform's
    /// guardian, a guardian itself, admin tools every guardian they trust.
    pub fn with_anchor_keys(mut self, keys: Vec<PublicKey>) -> Self {
        self.anchor_keys = keys;
        self
    }

    pub fn verify(
        &self,
        tenant: &TenantId,
        bundle: &TenantBundle,
        time: &TrustedTime,
    ) -> Result<VerifiedTenant, VerifyError> {
        self.verify_until(tenant, bundle, time, UnixTime::MAX)
    }

    /// The `TenantAnchor` for `bundle` that `platform`'s guardian signs: `verify`, with the state
    /// in force worked out no later than the bundle is known to be complete, when the freshness
    /// statements were signed (`fresh_since`): a newer state logged after
    /// that, which the bundle cannot show, must not be missing from what the anchor vouches for.
    pub fn anchor(
        &self,
        platform: PlatformId,
        tenant: &TenantId,
        bundle: &TenantBundle,
        time: &TrustedTime,
    ) -> Result<TenantAnchor, VerifyError> {
        let state = &bundle.state.body;
        let complete = fresh_since(&self.trust.tlog.log_key, state, &bundle.freshness, state.freshness_window(), time)?;
        let v = self.verify_until(tenant, bundle, time, complete)?;
        Ok(TenantAnchor {
            platform,
            tenant: tenant.clone(),
            root_id: v.root_id,
            version: v.state().version,
            digest: labeled_digest(TENANT_STATE_LABEL, v.state()),
            since: v.in_force_since,
            at: v.checked_at,
        })
    }

    /// `verify`, with windows measured at the earlier of `lock_time` and `until`.
    fn verify_until(
        &self,
        tenant: &TenantId,
        bundle: &TenantBundle,
        time: &TrustedTime,
        until: UnixTime,
    ) -> Result<VerifiedTenant, VerifyError> {
        let log = LogVerifier::new(self.trust.tlog.clone());
        let mut witnessed = 0;
        let roots = self.verify_chain(tenant, &bundle.root_chain, &log, &mut witnessed)?;
        let latest_root = roots.last().expect("verify_chain returns a chain").body();
        let root_id = seal_proto::state::root_id(roots[0].body());

        let signed_state = &bundle.state;
        let state = &signed_state.body;
        if &state.tenant != tenant {
            return Err(VerifyError::WrongTenant);
        }
        if state.root_version != latest_root.version {
            return Err(VerifyError::State(format!(
                "signed for root version {}, the latest is {}",
                state.root_version, latest_root.version
            )));
        }
        Self::verify_admin_signed(latest_root, TENANT_STATE_LABEL, signed_state)?;
        // The latest state's own window first; the state in force may shorten it below.
        let fresh_since =
            fresh_since(&self.trust.tlog.log_key, state, &bundle.freshness, state.freshness_window(), time)?;

        let states = match bundle.states.last() {
            // Without log proofs only a first state, which applies at once, can be in force.
            None if state.version != 1 => {
                return Err(VerifyError::State(format!(
                    "the bundle carries no log proof for state version {}",
                    state.version
                )));
            }
            None => vec![Public { signed: signed_state.clone(), public_since: 0 }],
            Some(last) if last.state.body != *state => {
                return Err(VerifyError::State("the last of the bundle's states is not its latest state".into()));
            }
            Some(_) => self.verify_states(tenant, &root_id, &roots, &bundle.states, &log, &mut witnessed)?,
        };
        if let Some(cp) = &bundle.checkpoint {
            witnessed = witnessed.max(log.checkpoint(cp)?.fresh_at());
        }
        let checked_at = lock_time(time, witnessed).min(until);
        let signed_anchor = self.guardian_anchor(tenant, &root_id, &bundle.anchors, &states, checked_at);
        let (anchor, since) = window::anchor(&roots, &states, checked_at)
            .into_iter()
            .chain(signed_anchor)
            .max_by_key(|&(k, _)| k)
            .ok_or_else(|| {
                VerifyError::State(
                    "cannot tell which state is in force: the bundle reaches back to none known to have been".into(),
                )
            })?;
        let (in_force, in_force_since) = window::advance(&roots, &states, anchor, since, checked_at);
        // A longer window widens access, so it waits like any widening change: until the state
        // that sets it is in force, the shorter window of the one in force applies.
        let window = state.freshness_window().min(states[in_force].body().freshness_window());
        let fresh_until = fresh_since.saturating_add(window);
        if time.latest() >= fresh_until {
            return Err(VerifyError::StateNotFresh);
        }

        let signals = self.signals(tenant, states[in_force].body(), &bundle.signals);
        Ok(VerifiedTenant {
            root_id,
            fresh_until,
            roots,
            states,
            in_force,
            in_force_since,
            checked_at,
            signals,
            ended_sessions: self.session_ends(tenant, &bundle.ended_sessions),
        })
    }

    /// The newest of `anchors` signed by one of `anchor_keys` for this tenant and chain, dated
    /// no later than `checked_at`, for a state in `states`: its index there and since when.
    fn guardian_anchor(
        &self,
        tenant: &TenantId,
        root_id: &TenantRootId,
        anchors: &[SignedTenantAnchor],
        states: &[Public<TenantState>],
        checked_at: UnixTime,
    ) -> Option<(usize, UnixTime)> {
        anchors
            .iter()
            .filter(|a| signed_by_any(&self.anchor_keys, TENANT_ANCHOR_LABEL, a))
            .map(|a| &a.body)
            .filter(|a| &a.tenant == tenant && &a.root_id == root_id && a.at <= checked_at)
            .filter_map(|a| {
                let k = states.iter().position(|s| {
                    s.body().version == a.version && labeled_digest(TENANT_STATE_LABEL, s.body()) == a.digest
                })?;
                Some((k, a.since))
            })
            .max_by_key(|&(k, _)| k)
    }

    /// A tenant's logged documents without the freshness of a bundle: the root chain as
    /// `verify` checks it, and `states` (consecutive versions, each signed by the root it names
    /// and logged in order) with when each became public. Says nothing about which state is in
    /// force; for showing a tenant's history.
    pub fn verify_documents(
        &self,
        tenant: &TenantId,
        root_chain: &[LoggedRoot],
        states: &[LoggedState],
        checkpoint: Option<&SignedCheckpoint>,
    ) -> Result<VerifiedDocuments, VerifyError> {
        let log = LogVerifier::new(self.trust.tlog.clone());
        let mut witnessed_at = 0;
        let roots = self.verify_chain(tenant, root_chain, &log, &mut witnessed_at)?;
        let root_id = seal_proto::state::root_id(roots[0].body());
        let states = self.verify_states(tenant, &root_id, &roots, states, &log, &mut witnessed_at)?;
        if let Some(cp) = checkpoint {
            witnessed_at = witnessed_at.max(log.checkpoint(cp)?.fresh_at());
        }
        Ok(VerifiedDocuments { root_id, roots, states, witnessed_at })
    }

    /// The chain from version 1, every link logged, with when each became public; `witnessed`
    /// rises to the latest `fresh_at` of their checkpoints.
    fn verify_chain(
        &self,
        tenant: &TenantId,
        root_chain: &[LoggedRoot],
        log: &LogVerifier,
        witnessed: &mut UnixTime,
    ) -> Result<Vec<Public<TenantRoot>>, VerifyError> {
        let mut chain: Vec<Public<TenantRoot>> = Vec::new();
        for link in root_chain {
            let root = &link.root.body;
            if &root.tenant != tenant {
                return Err(VerifyError::WrongTenant);
            }
            match chain.last() {
                None => {
                    if root.version != 1 {
                        return Err(VerifyError::RootChain("does not start at version 1".into()));
                    }
                    verify_threshold(
                        &self.trust.registrar_keys,
                        self.trust.registrar_threshold,
                        TENANT_ROOT_LABEL,
                        &link.root,
                    )
                    .map_err(|e| VerifyError::RootChain(format!("version 1 registrar signatures: {e}")))?;
                }
                Some(prev) => {
                    let prev = prev.body();
                    if prev.version.checked_add(1) != Some(root.version) {
                        return Err(VerifyError::RootChain("versions are not consecutive".into()));
                    }
                    Self::verify_admin_signed(prev, TENANT_ROOT_LABEL, &link.root).map_err(|_| {
                        VerifyError::RootChain(format!(
                            "version {} not signed by version {}",
                            root.version, prev.version
                        ))
                    })?;
                }
            }
            let included = log.inclusion(&LogEntry::TenantRoot(root.clone()), &link.proof)?;
            *witnessed = (*witnessed).max(included.fresh_at());
            chain.push(Public { signed: link.root.clone(), public_since: included.public_since() });
        }
        if chain.is_empty() {
            return Err(VerifyError::RootChain("empty".into()));
        }
        Ok(chain)
    }

    /// `states`, each with when it became public; `witnessed` rises as in `verify_chain`.
    fn verify_states(
        &self,
        tenant: &TenantId,
        root_id: &TenantRootId,
        roots: &[Public<TenantRoot>],
        states: &[LoggedState],
        log: &LogVerifier,
        witnessed: &mut UnixTime,
    ) -> Result<Vec<Public<TenantState>>, VerifyError> {
        let mut out: Vec<Public<TenantState>> = Vec::with_capacity(states.len());
        let mut prev_index = None;
        for logged in states {
            let state = &logged.state.body;
            if &state.tenant != tenant {
                return Err(VerifyError::WrongTenant);
            }
            if let Some(prev) = out.last() {
                let prev = prev.body();
                if prev.version.checked_add(1) != Some(state.version) {
                    return Err(VerifyError::State("the bundle's states are not consecutive versions".into()));
                }
                if state.root_version < prev.root_version || prev_index.is_some_and(|i| logged.proof.leaf_index <= i) {
                    return Err(VerifyError::State(format!(
                        "state version {} is logged or signed out of order",
                        state.version
                    )));
                }
            }
            let root = usize::try_from(state.root_version)
                .ok()
                .and_then(|v| v.checked_sub(1))
                .and_then(|i| roots.get(i))
                .ok_or_else(|| {
                    VerifyError::State(format!("state version {} names no root of the chain", state.version))
                })?;
            Self::verify_admin_signed(root.body(), TENANT_STATE_LABEL, &logged.state)?;
            let leaf = TenantStateLeaf {
                tenant: tenant.clone(),
                root_id: *root_id,
                version: state.version,
                digest: labeled_digest(TENANT_STATE_LABEL, state),
            };
            let included = log.inclusion(&LogEntry::TenantState(leaf), &logged.proof)?;
            *witnessed = (*witnessed).max(included.fresh_at());
            prev_index = Some(logged.proof.leaf_index);
            out.push(Public { signed: logged.state.clone(), public_since: included.public_since() });
        }
        Ok(out)
    }

    /// Valid signals for `tenant`, deduplicated, in bundle order.
    fn signals(&self, tenant: &TenantId, state: &TenantState, signals: &[SignedSignal]) -> Vec<IntegritySignal> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for signal in signals {
            let body = &signal.body;
            if &body.tenant != tenant || validate_code(&body.code).is_err() {
                continue;
            }
            let signers: &[PublicKey] = match &body.source {
                SignalSource::Enclave { .. } | SignalSource::Sdk => &self.telemetry_keys,
                SignalSource::External { source } => match state.integrity.sources.get(source) {
                    Some(key) => std::slice::from_ref(key),
                    None => continue,
                },
            };
            if signed_by_any(signers, SIGNAL_LABEL, signal) && seen.insert(digest(body)) {
                out.push(body.clone());
            }
        }
        out
    }

    /// Valid session ends for `tenant`, the first one per `session_id`.
    fn session_ends(&self, tenant: &TenantId, ends: &[SignedSessionEnd]) -> Vec<SessionEnd> {
        let mut out: Vec<SessionEnd> = Vec::new();
        for end in ends {
            let body = &end.body;
            if &body.tenant == tenant
                && !out.iter().any(|e| e.session_id == body.session_id)
                && signed_by_any(&self.telemetry_keys, SESSION_END_LABEL, end)
            {
                out.push(body.clone());
            }
        }
        out
    }
}

/// What `TenantVerifier::verify_documents` returns.
#[derive(Clone, Debug, serde::Serialize)]
pub struct VerifiedDocuments {
    pub root_id: TenantRootId,
    /// The chain, versions 1..=N.
    pub roots: Vec<Public<TenantRoot>>,
    /// Consecutive versions, oldest first.
    pub states: Vec<Public<TenantState>>,
    /// The latest `fresh_at` of every checkpoint given: the log's witnessed time.
    pub witnessed_at: UnixTime,
}

/// Where a bundle's `states` can start: the index into `states` (consecutive versions, oldest
/// first, the last the latest) from which every verifier trusting one of `guardians` finds an
/// anchor at `time`: the newest the documents give, or, when every one of `guardians` signed an
/// anchor in `anchors` for a state there, the oldest of those (each verifier starts from its
/// own guardian's). 0 when neither, or when a proof does not verify: then send them all. For
/// whoever assembles bundles; it checks log proofs and anchor signatures, not admin signatures.
pub fn anchor_index(
    tlog: &seal_tlog::TlogTrust,
    guardians: &[PublicKey],
    root_chain: &[LoggedRoot],
    states: &[LoggedState],
    anchors: &[SignedTenantAnchor],
    checkpoint: Option<&SignedCheckpoint>,
    time: &TrustedTime,
) -> usize {
    let log = LogVerifier::new(tlog.clone());
    let Some(first) = root_chain.first() else { return 0 };
    let root_id = seal_proto::state::root_id(&first.root.body);
    let mut witnessed = 0;
    let mut roots = Vec::new();
    for link in root_chain {
        let Ok(included) = log.inclusion(&LogEntry::TenantRoot(link.root.body.clone()), &link.proof) else { return 0 };
        witnessed = witnessed.max(included.fresh_at());
        roots.push(Public { signed: link.root.clone(), public_since: included.public_since() });
    }
    let mut public = Vec::new();
    for logged in states {
        let state = &logged.state.body;
        let leaf = TenantStateLeaf {
            tenant: state.tenant.clone(),
            root_id,
            version: state.version,
            digest: labeled_digest(TENANT_STATE_LABEL, state),
        };
        let Ok(included) = log.inclusion(&LogEntry::TenantState(leaf), &logged.proof) else { return 0 };
        witnessed = witnessed.max(included.fresh_at());
        public.push(Public { signed: logged.state.clone(), public_since: included.public_since() });
    }
    if let Some(cp) = checkpoint.and_then(|cp| log.checkpoint(cp).ok()) {
        witnessed = witnessed.max(cp.fresh_at());
    }
    let now = lock_time(time, witnessed);
    let documents = window::anchor(&roots, &public, now).map_or(0, |(k, _)| k);
    let Some(tenant) = public.first().map(|s| s.body().tenant.clone()) else { return 0 };
    let mut signed = Vec::new();
    for key in guardians {
        let verifier = TenantVerifier {
            trust: TenantTrust { tlog: tlog.clone(), registrar_keys: Vec::new(), registrar_threshold: 0 },
            telemetry_keys: Vec::new(),
            anchor_keys: vec![*key],
        };
        match verifier.guardian_anchor(&tenant, &root_id, anchors, &public, now) {
            Some((k, _)) => signed.push(k),
            None => return documents,
        }
    }
    signed.into_iter().min().map_or(documents, |k| k.max(documents))
}

/// Some signature of `signed` verifies under one of `keys` (Ed25519).
fn signed_by_any<T: serde::Serialize>(keys: &[PublicKey], label: &str, signed: &Signed<T>) -> bool {
    signed.signatures.iter().any(|sig| {
        keys.iter().find(|k| key_id(k) == sig.signer).is_some_and(|k| verify(k, label, &signed.body, sig).is_ok())
    })
}

/// When the required statements for `state` last vouched for it, the earlier of: the log's
/// latest, and a tenant-run signer's latest when the state names `freshness_keys`. Each must
/// be younger than `window` (`StateNotFresh` otherwise); the state is fresh until this plus
/// `window`.
fn fresh_since(
    log_key: &PublicKey,
    state: &TenantState,
    statements: &[SignedStateFreshness],
    window: u64,
    time: &TrustedTime,
) -> Result<UnixTime, VerifyError> {
    let digest = labeled_digest(TENANT_STATE_LABEL, state);
    let latest = |keys: &[PublicKey]| -> Option<UnixTime> {
        statements
            .iter()
            .filter(|f| f.body.tenant == state.tenant && f.body.version == state.version && f.body.digest == digest)
            .filter(|f| signed_by_any(keys, STATE_FRESHNESS_LABEL, f))
            // A statement dated after now could only have been signed in advance, to keep a
            // state alive past its replacement: it never counts.
            .filter(|f| f.body.signed_at <= time.latest())
            .map(|f| f.body.signed_at)
            .filter(|&at| time.latest() < at.saturating_add(window))
            .max()
    };
    let log = latest(std::slice::from_ref(log_key)).ok_or(VerifyError::StateNotFresh)?;
    if state.freshness_keys.is_empty() {
        return Ok(log);
    }
    let tenant_keys: Vec<PublicKey> = state.freshness_keys.iter().copied().collect();
    let tenant = latest(&tenant_keys).ok_or(VerifyError::StateNotFresh)?;
    Ok(log.min(tenant))
}

/// Signed by `guardians[cert.platform]` under `SERVICE_KEY_CERTIFICATE_LABEL`. Callers then
/// compare its keys with the attestation binding and its tenant and root with what they expect.
pub fn verify_service_certificate<'c>(
    guardians: &BTreeMap<PlatformId, PublicKey>,
    cert: &'c SignedServiceKeyCertificate,
) -> Result<&'c ServiceKeyCertificate, VerifyError> {
    let key = guardians
        .get(&cert.body.platform)
        .ok_or_else(|| VerifyError::Certificate("no guardian key for its platform".into()))?;
    if signed_by_any(std::slice::from_ref(key), SERVICE_KEY_CERTIFICATE_LABEL, cert) {
        Ok(&cert.body)
    } else {
        Err(VerifyError::Certificate("not signed by its platform's guardian".into()))
    }
}

/// `threshold` distinct admin keys of `root` signed `signed` under `label` (Ed25519 or passkey).
/// Each signature is matched to its key by `admin_key_id(key) == signature.signer`; unknown
/// signers, duplicates and invalid signatures are ignored, and a threshold of 0 accepts
/// nothing. Fails with `State`; callers checking something else map the error.
impl TenantVerifier {
    pub fn verify_admin_signed<T: serde::Serialize>(
        root: &TenantRoot,
        label: &str,
        signed: &Signed<T>,
    ) -> Result<(), VerifyError> {
        let need = usize::from(root.threshold);
        let mut counted = BTreeSet::new();
        for sig in &signed.signatures {
            if counted.contains(&sig.signer) {
                continue;
            }
            let Some(key) = root.admin_keys.iter().find(|k| admin_key_id(k) == sig.signer) else {
                continue;
            };
            if verify_admin(key, label, &signed.body, sig).is_ok() {
                counted.insert(sig.signer);
            }
        }
        if need == 0 || counted.len() < need {
            return Err(VerifyError::State(format!(
                "admin signatures: need {need} from distinct admin keys, have {}",
                counted.len()
            )));
        }
        Ok(())
    }
}

impl VerifiedRelease {
    pub fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }
    pub fn public_since(&self) -> UnixTime {
        self.public_since
    }
    pub fn constraints(&self) -> &ReleaseConstraints {
        &self.policy
    }
}

//! Signed state: everything the stateless enclave needs to remember, stored by
//! the untrusted control service and verified (by `seal-verify`) on every load.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::identity::IdentityMatcher;
use crate::release::{SignedCheckpoint, TlogProof};
use crate::signed::Signed;
use crate::{codec, AppName, PlatformId, PublicKey, TenantId, TenantKeyVersion, TenantRootId, UnixTime};

/// A public key that can sign tenant documents. Its `KeyId`, which `Signature::signer` names:
/// an Ed25519 key's plain key id (SHA-256 of its 32 bytes, as for every Ed25519 key); a
/// passkey's SHA-256 of `canonical(&AdminKey)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdminKey {
    Ed25519 {
        public_key: PublicKey,
    },
    /// A passkey: uncompressed SEC1 P-256 point (65 bytes) and the RP ID it is scoped to.
    WebAuthnEs256 {
        #[serde(with = "codec::bytes_b64")]
        sec1: Vec<u8>,
        rp_id: String,
    },
}

/// The tenant's trust anchor. Every version is logged; version 1 is signed by
/// Seal's tenant registrar, every later version by `threshold` keys of the
/// version before it. Verifiers walk the whole chain (`TenantBundle::root_chain`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRoot {
    pub tenant: TenantId,
    pub version: u64,
    pub admin_keys: BTreeSet<AdminKey>,
    /// Signatures needed from `admin_keys`, for `TenantState`s and for the next root.
    pub threshold: u8,
    /// Opt-in: this tenant's keys go only to releases its admins co-signed.
    /// Lives in the root (not `TenantState`) so it is in the transparency log.
    pub cosign_releases: bool,
}
pub const TENANT_ROOT_LABEL: &str = "seal/tenant-root/v1";
pub const TENANT_ROOT_ID_LABEL: &str = "seal/tenant-root-id/v1";

/// The `TenantRootId` of a chain: the digest of its version 1.
pub fn root_id(root_v1: &TenantRoot) -> TenantRootId {
    TenantRootId(codec::labeled_digest(TENANT_ROOT_ID_LABEL, root_v1))
}

/// One link of a root chain: the signed root and its log inclusion. The log
/// leaf is `LogEntry::TenantRoot(root.body)`; signatures are checked separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggedRoot {
    pub root: Signed<TenantRoot>,
    pub proof: TlogProof,
}

/// A signed state and its log inclusion (`LogEntry::TenantState`, the state's digest). The
/// proof's checkpoint is the first one that included it, so its witness times are when the
/// state became public.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggedState {
    pub state: SignedTenantState,
    pub proof: TlogProof,
}

/// Grants and tenant key versions, signed by the current root's admin keys and logged
/// (`LogEntry::TenantState`, digest only). Verifiers accept it only with a current
/// `StateFreshness`, and the enclave keeps the highest `version` it has seen and rejects older.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantState {
    pub tenant: TenantId,
    pub version: u64,
    /// The root version whose keys signed this state.
    pub root_version: u64,
    pub apps: BTreeMap<AppName, BTreeSet<IdentityMatcher>>,
    pub tenant_key_versions: TenantKeyVersions,
    /// Platforms new blobs get DEK wraps for.
    pub platforms: BTreeSet<PlatformId>,
    /// Integrity rules: allowed artifacts, trusted signal sources, responses.
    pub integrity: crate::integrity::IntegrityPolicy,
    /// Enclave deployments allowed to serve this tenant, by their deployment identity: an
    /// ACI container group's managed identity (`Azure`), a Nitro parent instance's role
    /// (`AwsRole`, proved with SigV4) or a Confidential Space VM's project and service account
    /// (`ConfidentialSpace`, from its attestation). A replica whose identity matches none
    /// requests no keys, and one whose entry is removed refuses everything from its next reload.
    /// Empty = no deployment may serve. `seal deploy azure|aws|gcp` adds what it creates; the
    /// entry for Seal's hosted replicas carries the Seal-hosted mark (`HostedMode`).
    pub deployments: BTreeSet<IdentityMatcher>,
    /// Tenant-run freshness signers (Ed25519). Empty = the log's statement alone keeps this
    /// state fresh. Otherwise a statement from one of these keys is required as well, so
    /// not even the log operator can keep an older state alive on its own.
    pub freshness_keys: BTreeSet<PublicKey>,
    /// X25519 keys telemetry is encrypted to. Empty = telemetry batches travel in clear (still
    /// signed). Otherwise only these keys' holders can read entries; the control plane sees
    /// only batch metadata.
    pub telemetry_readers: BTreeSet<PublicKey>,
    pub issued_at: UnixTime,
    /// How long a change that widens access waits in public before it takes effect, in
    /// seconds, at most `MAX_PENDING_WINDOW_SECS`. A newer state or root that widens the one in
    /// force applies only once its `public_since` plus the window of the state in force has
    /// passed by the log's witnessed time (`seal_verify::change`). Omitted when 0; a written 0
    /// or a longer window does not decode, so each window has one signed encoding.
    #[serde(default, skip_serializing_if = "is_zero", deserialize_with = "pending_window")]
    pub pending_window_secs: u64,
    /// The networks each app may start and extend sessions from, checked by the enclave
    /// against the connection's source address. An app not listed here may connect from
    /// anywhere; one listed with an empty set from nowhere. Adding an app's first network
    /// narrows access and removing its last widens it, like an artifact rule
    /// (`seal_verify::change`). It guards a stolen credential used from elsewhere, not against
    /// the host, which controls the network; a replica that sees no client address (behind a
    /// proxy) refuses the listed apps. Only meaningful where the replica sees clients' own
    /// addresses: Azure Container Instances with a public IP translates every caller to a private
    /// address, so there a rule cannot tell callers apart. Omitted when empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub app_networks: BTreeMap<AppName, BTreeSet<crate::net::Cidr>>,
}
pub const TENANT_STATE_LABEL: &str = "seal/tenant-state/v1";

/// The longest pending window that counts: a longer `pending_window_secs` waits this long. It
/// bounds how far back a verifier needs a tenant's states (`TenantBundle::states`).
pub const MAX_PENDING_WINDOW_SECS: u64 = 86_400;

fn is_zero(secs: &u64) -> bool {
    *secs == 0
}

/// `pending_window_secs` as written: 1 to `MAX_PENDING_WINDOW_SECS` (0 is the omitted field).
fn pending_window<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let secs = <u64 as serde::Deserialize>::deserialize(d)?;
    if secs == 0 || secs > MAX_PENDING_WINDOW_SECS {
        return Err(serde::de::Error::custom(format!(
            "pending_window_secs: 1 to {MAX_PENDING_WINDOW_SECS} (omit it for no window)"
        )));
    }
    Ok(secs)
}

impl TenantState {
    /// Whether `app` may hold a session from `source` (`app_networks`): any address when the
    /// app has no network rule; otherwise only an address in one of its networks, and never
    /// an unknown one.
    pub fn admits_source(&self, app: &AppName, source: Option<std::net::IpAddr>) -> bool {
        match self.app_networks.get(app) {
            None => true,
            Some(networks) => source.is_some_and(|ip| networks.iter().any(|n| n.contains(ip))),
        }
    }
}

/// "State `version` (with this digest) of the chain `root_id` was in force at `at`, and had
/// been since `since` at the latest", signed by `platform`'s guardian key after verifying the
/// tenant's bundle (`POST /v1/anchors`). Verifiers that trust that guardian start from it, so
/// a bundle needs only the states from it on: every state newer than the one in force at `at`
/// became public within `MAX_PENDING_WINDOW_SECS` before `at`, or after it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantAnchor {
    pub platform: PlatformId,
    pub tenant: TenantId,
    pub root_id: TenantRootId,
    pub version: u64,
    /// `labeled_digest(TENANT_STATE_LABEL, state)`.
    #[serde(with = "codec::array_b64")]
    pub digest: [u8; 32],
    pub since: UnixTime,
    pub at: UnixTime,
}
pub const TENANT_ANCHOR_LABEL: &str = "seal/tenant-anchor/v1";
pub type SignedTenantAnchor = Signed<TenantAnchor>;

/// "The latest `TenantState` of `tenant` is `version`, with this digest, as of `signed_at`."
/// Signed by the transparency log (`TlogTrust::log_key`), which holds every state as a
/// `LogEntry::TenantState` leaf, and by a tenant-run signer when the state names
/// `freshness_keys`. Verifiers accept a state only with statements for exactly it that are
/// less than `STATE_FRESHNESS_SECS` old, so a replayed older state stops working within that
/// window. A log statement for an older version than one it had already logged is a
/// signed, provable lie.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFreshness {
    pub tenant: TenantId,
    pub version: u64,
    /// `labeled_digest(TENANT_STATE_LABEL, state)`.
    #[serde(with = "codec::array_b64")]
    pub digest: [u8; 32],
    pub signed_at: UnixTime,
}
pub const STATE_FRESHNESS_LABEL: &str = "seal/state-freshness/v1";
pub type SignedStateFreshness = Signed<StateFreshness>;

/// How long a freshness statement keeps its state usable: the most a rollback can buy, and
/// how long a tenant survives an unreachable log before its enclaves refuse service.
pub const STATE_FRESHNESS_SECS: u64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyVersions {
    /// New blobs are sealed under this tenant key version.
    pub current: TenantKeyVersion,
    /// Blobs from tenant key versions below this are dead. Between this and `current`: decrypt-only, resealed on open.
    pub oldest_accepted: TenantKeyVersion,
}

pub type SignedTenantState = Signed<TenantState>;

/// What the control service returns for one tenant. Every piece is
/// independently verifiable; the service itself is not trusted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantBundle {
    /// Versions 1..=N in order, each logged.
    pub root_chain: Vec<LoggedRoot>,
    pub state: SignedTenantState,
    /// Integrity signals for this tenant. Only accumulate; verifiers drop invalid ones
    /// (so junk cannot suspend anyone) and evaluate the rest under `state.integrity`.
    pub signals: Vec<crate::integrity::SignedSignal>,
    /// Sessions ended early. Verifiers drop invalid ones; the control plane drops those no
    /// longer live (`SessionEnd::is_live`).
    pub ended_sessions: Vec<crate::session::SignedSessionEnd>,
    /// The newest freshness statements for `state`: the log's, plus a tenant-run signer's
    /// when `state.freshness_keys` is non-empty.
    pub freshness: Vec<SignedStateFreshness>,
    /// Guardian-certified wrap keys of `state.platforms` for the tenant key versions in
    /// `state.tenant_key_versions`, fetched by the control plane from each platform's guardian.
    /// Sealing wraps to the `current` ones; a platform with no valid key for `current` makes
    /// sealing fail (`Unavailable`) rather than produce a blob that platform cannot open.
    pub wrap_keys: Vec<crate::release::SignedTenantWrapKey>,
    /// States with their log proofs, oldest first, consecutive versions, the last one
    /// `state`, reaching back to one verifiers know was in force: a guardian's anchor
    /// (`anchors`), the tenant's first state, or one that stayed the latest for
    /// `MAX_PENDING_WINDOW_SECS`. Verifiers work out from them which state is in force and
    /// which are pending. Empty: only a first state (version 1) can be in force.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub states: Vec<LoggedState>,
    /// A recent checkpoint of the log. The latest witness time of every checkpoint in the
    /// bundle is the log's witnessed time, by which pending windows are measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<SignedCheckpoint>,
    /// The newest anchor from each platform's guardian (`TenantAnchor`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<SignedTenantAnchor>,
}

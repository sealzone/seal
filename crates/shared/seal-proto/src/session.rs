//! Sessions: what starting a session returns and what every data-plane request carries.

use serde::{Deserialize, Serialize};

use crate::blob::Blob;
use crate::identity::WorkloadIdentity;
use crate::{AppName, BlobId, PlatformId, ServiceKeyVersion, TenantId, UnixTime};

/// Every session token lives this long.
pub const SESSION_TOKEN_SECS: u64 = 600;
/// The SDK extends a session this often, re-proving its identity each time. So identity is
/// re-verified at least every `SESSION_EXTEND_SECS`, and a workload disabled at its identity
/// provider loses access within one extend.
pub const SESSION_EXTEND_SECS: u64 = 300;

/// A session ended before its tokens expired: by its client (`POST /v1/sessions/end`) or
/// by the enclave (an integrity `Verdict::End` or a suspension). The ending replica signs it
/// with its telemetry key and publishes it, so every replica refuses the session's tokens and
/// closes its connections within `STATE_RELOAD_SECS`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEnd {
    pub tenant: TenantId,
    #[serde(with = "crate::codec::array_b64")]
    pub session_id: [u8; 16],
    /// `SessionEnded` (client) or `IntegrityFailed` (enclave). What `Session::ended` resolves with.
    pub reason: crate::ErrorCode,
    pub ended_at: UnixTime,
}
pub const SESSION_END_LABEL: &str = "seal/session-end/v1";
pub type SignedSessionEnd = crate::signed::Signed<SessionEnd>;

/// How long a `SessionEnd` stays in the tenant bundle after `ended_at`. Covers the last token
/// any replica may issue for the session (an extend on a replica that has not reloaded yet),
/// so every token of an ended session is refused until it expires anyway.
pub const SESSION_END_RETAIN_SECS: u64 = 900;

impl SessionEnd {
    /// Still needed in the bundle at `time`.
    pub fn is_live(&self, time: &crate::TrustedTime) -> bool {
        time.earliest() < self.ended_at.saturating_add(SESSION_END_RETAIN_SECS)
    }
}

/// How well the enclave itself is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformTier {
    Sim,
    Sealed,
}

/// How sure Seal is about who is calling, one blended cumulative axis: each tier implies
/// the ones below it.
///
/// - `Base`: identity, grants and the artifact rule — we know who is asking.
/// - `Hardened`: Base, and the session runs inside the SDK's pinned channel (tunnel; the
///   token alone is not enough), and the endpoint presents verified integrity evidence
///   from outside its process at every start and extend — the machine vouched, not just
///   the caller. Achieved only where the enclave could verify evidence (a compiled-in
///   check for an enrolled provider); unreachable in images that cannot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerTier {
    Base,
    Hardened,
}

/// Prefix of every session token.
pub const TOKEN_PREFIX: &str = "sealtok_";

/// What a session token decrypts to. Only ever exists inside an enclave.
///
/// Token format: `TOKEN_PREFIX + base64url(version:u8 || service_key_version:u32 ||
/// salt:32 || nonce:12 || AES-256-GCM(HKDF(token_key, salt), canonical(claims)))`.
/// The per-token salt gives every token its own AEAD key (no nonce-reuse
/// ceiling); the service key version selects the token key. The blob travels inside, still
/// sealed: the resolver opens it with the tenant wrapping key on each connection. So any of
/// the tenant's replicas can serve any request, and the token key alone reveals no secret.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub tenant: TenantId,
    pub app: AppName,
    /// Random at session start; the same across extends, so an extend reaches live connections.
    #[serde(with = "crate::codec::array_b64")]
    pub session_id: [u8; 16],
    /// Who started it: re-checked against current grants on every resolve; re-proven on every extend.
    pub caller: WorkloadIdentity,
    pub authentication: crate::identity::AuthenticationScope,
    /// The exact blob the session was started on. Its header names the producer (re-checked
    /// against current producers on every resolve), root and tenant key version; its policy
    /// is the session's policy.
    pub blob: Blob,
    pub service_key_version: ServiceKeyVersion,
    pub tier: ConsumerTier,
    pub platform: PlatformId,
    pub issued_at: UnixTime,
    pub expires_at: UnixTime,
}

/// `s.info` in the SDK: read-only facts about a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    #[serde(with = "crate::codec::array_b64")]
    pub session_id: [u8; 16],
    pub platform: PlatformTier,
    pub tier: ConsumerTier,
    pub tenant: TenantId,
    pub app: AppName,
    pub blob_id: BlobId,
    pub expires_at: UnixTime,
}

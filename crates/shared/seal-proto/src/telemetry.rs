//! Telemetry: the signed record of what the enclave did. Only the enclave writes it;
//! everything that comes in (endpoint reports, signals) is an input, recorded here once the
//! enclave has acted on it. Signals in, telemetry out.
//!
//! One `TelemetryEntry` per event (seal, session, extend, end, refusal, data-plane request,
//! integrity action), shipped in `TelemetryBatch`es signed with the enclave's telemetry key.
//! Metrics, later, are telemetry aggregated. Data-plane entries come from the adapters'
//! per-request `Completion`.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::identity::WorkloadIdentity;
use crate::integrity::{IntegrityAction, Severity, SignalSource};
use crate::policy::Protocol;
use crate::session::ConsumerTier;
use crate::signed::Signed;
use crate::{codec, AppName, BlobId, ErrorCode, KeyId, PlatformId, PublicKey, TenantId, TenantKeyVersion, UnixTime};

/// How one data-plane request ended, reported by its adapter (`Session::complete`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completion {
    pub protocol: Protocol,
    /// Protocol-level summary from a fixed vocabulary per adapter, e.g. `POST /v1/chat/completions`
    /// (path truncated to 128 chars, query dropped), `QUERY`, `AUTH`, `GET`.
    pub action: String,
    pub outcome: Outcome,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Denied(ErrorCode),
    UpstreamError(UpstreamErrorKind),
    /// Cut before it finished: the client went away or the session ended mid-transfer.
    Aborted,
}

/// What went wrong upstream, without any upstream-supplied text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamErrorKind {
    Connect,
    Tls,
    AuthRejected,
    Protocol,
    Closed,
    Timeout,
    /// HTTP status from upstream (status only; bodies never recorded).
    HttpStatus(u16),
    /// A Postgres `ErrorResponse` answered the request (SQL errors included): its SQLSTATE
    /// only, never its text.
    Sqlstate(Sqlstate),
}

/// A Postgres SQLSTATE (`42P01`): five ASCII digits or upper-case letters. Serialized as that
/// string; anything else is refused when decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sqlstate([u8; 5]);

impl Sqlstate {
    pub const fn new(code: [u8; 5]) -> Option<Self> {
        let mut i = 0;
        while i < code.len() {
            if !(code[i].is_ascii_digit() || code[i].is_ascii_uppercase()) {
                return None;
            }
            i += 1;
        }
        Some(Self(code))
    }
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("checked ASCII")
    }
}

impl std::fmt::Display for Sqlstate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Sqlstate {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Sqlstate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        <[u8; 5]>::try_from(text.as_bytes())
            .ok()
            .and_then(Sqlstate::new)
            .ok_or_else(|| serde::de::Error::custom("a SQLSTATE is five digits or upper-case letters"))
    }
}

/// One telemetry entry, written by the enclave runtime. Never contains the secret, a
/// credential, payload bodies or upstream-supplied text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEntry {
    /// From the enclave's trusted clock (`seal_tee::Clock`, accurate to its radius); set by the runtime.
    pub at: UnixTime,
    pub tenant: TenantId,
    /// The authenticated workload that acted; `None` for entries the enclave records about
    /// itself (`Dropped`) and for `Refused` operations whose caller was not authenticated (an
    /// app key no grant names, a proof that does not verify).
    pub identity: Option<WorkloadIdentity>,
    pub event: TelemetryEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryEvent {
    /// Someone sealed a blob (sealing is open, so no identity). `destination` is the policy's
    /// `to` (never a password).
    Seal { blob_id: BlobId, destination: String, apps: BTreeSet<AppName> },
    /// A consumer started a session.
    Session {
        #[serde(with = "codec::array_b64")]
        session_id: [u8; 16],
        app: AppName,
        blob_id: BlobId,
        tier: ConsumerTier,
    },
    /// The session was extended with a fresh identity proof.
    Extend {
        #[serde(with = "codec::array_b64")]
        session_id: [u8; 16],
        expires_at: UnixTime,
    },
    /// The session ended before its tokens expired (`SessionEnd`).
    End {
        #[serde(with = "codec::array_b64")]
        session_id: [u8; 16],
        reason: ErrorCode,
    },
    /// A control operation was refused: the code the caller heard, and why (`context`), which
    /// the caller is not told. Entries written before refusals said why have no context, and
    /// encode as they did.
    Refused {
        operation: Operation,
        code: ErrorCode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<RefusalContext>,
    },
    /// One data-plane request on a session.
    Request {
        #[serde(with = "codec::array_b64")]
        session_id: [u8; 16],
        app: AppName,
        blob_id: BlobId,
        connection_id: u64,
        completion: Completion,
    },
    /// An integrity signal about `identity` was applied, and what it caused.
    Integrity { source: SignalSource, code: String, severity: Severity, action: IntegrityAction },
    /// This replica dropped entries because its buffer was full: data-plane `Request`
    /// entries first, other kinds only once no `Request` entries are left to drop.
    Dropped { requests: u64, other: u64 },
}

/// Why the enclave refused an operation (`TelemetryEvent::Refused::context`), with the values
/// behind it. Text fields (`what`) hold one of the enclave's own fixed sentences, never text
/// from the caller or an upstream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RefusalContext {
    // Who is asking.
    /// The verified caller matches no grant of `apps`: the blob's apps, or empty for any app
    /// of the tenant.
    NoGrant { caller: WorkloadIdentity, apps: BTreeSet<AppName> },
    /// An app key that no grant names.
    UnknownAppKey { key_id: KeyId },
    /// The identity proof does not verify; `what` says which check it failed.
    BadProof { what: String },
    /// The identity token expired at `expired_at`.
    TokenExpired { expired_at: UnixTime },
    /// The proof's ticket expired at `expired_at`.
    TicketExpired { expired_at: UnixTime },
    /// The proof was made for another enclave (another TLS key).
    WrongEnclave,
    /// The proof was made for another request.
    WrongRequest,
    /// The extend's proof is from `caller`, not the session's caller.
    OtherCaller { caller: WorkloadIdentity },
    /// The request, proof, blob or session is `tenant`'s, not this enclave's tenant.
    OtherTenant { tenant: TenantId },

    // Where it comes from.
    /// The caller connected from outside `app`'s networks. `from` is the address the enclave
    /// saw (`None` when it saw none); on a Seal-hosted replica that is the front door's.
    OutsideNetworks { app: AppName, from: Option<IpAddr> },

    // Grants and integrity.
    /// A live session's caller no longer holds `app`'s grant on the blob: the app left the
    /// blob's apps, or its grant no longer matches the caller.
    GrantLost { app: AppName },
    /// The caller is suspended by an integrity signal with `code`, until `until` (`None`: until
    /// an admin clears it).
    Suspended { code: String, until: Option<UnixTime> },
    /// The endpoint report fails the app's artifact rule.
    ArtifactMismatch,
    /// The endpoint's evidence failed an integrity check.
    EvidenceFailed,

    // The blob.
    /// The blob stopped working at `expired_at`.
    BlobExpired { blob_id: BlobId, expired_at: UnixTime },
    /// The blob's tenant key version is older than the oldest the tenant still accepts.
    KeyVersionRetired { version: TenantKeyVersion, oldest_accepted: TenantKeyVersion },
    /// The blob was sealed under tenant key `version`, newer than this replica's state.
    NewerState { version: TenantKeyVersion },
    /// The blob's minimum platform excludes this replica's `platform`.
    PlatformExcluded { platform: PlatformId },
    /// The blob was sealed before the tenant enabled `platform`, this replica's: reseal it.
    NotSealedForPlatform { platform: PlatformId },
    /// No platform the tenant enables meets the policy's minimum: nothing to seal for.
    NoPlatform,

    // The session.
    /// The session would be at `offered`, below the `required` tier.
    TierTooLow { required: ConsumerTier, offered: ConsumerTier },
    /// The session's token expired at `expired_at`.
    SessionExpired { expired_at: UnixTime },
    /// The session was ended early.
    SessionEnded,
    /// The session token is malformed, or no enclave of this tenant issued it.
    BadSessionToken,

    // This replica.
    /// The enclave's verified tenant state was fresh only until `fresh_until` (when known).
    StaleState { fresh_until: Option<UnixTime> },
    /// The enclave has no verified tenant state yet.
    NoState,
    /// The tenant no longer lists this replica's deployment.
    DeploymentNotListed,
    /// The replica is stopping.
    Stopping,
    /// A service the enclave needed did not answer.
    Unavailable { service: Dependency },

    // The request itself.
    /// The request is malformed; `what` says how.
    Malformed { what: String },
    /// An external signal's signer is not a source the tenant enrolled, or its signature
    /// does not verify.
    UnknownSignalSource,
}

/// A service the enclave depends on (`RefusalContext::Unavailable`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dependency {
    /// The trusted clock.
    Clock,
    /// Seal's control plane.
    ControlPlane,
    /// The key service (the guardian) or its certified wrapping keys.
    KeyService,
    /// An identity token's issuer (OIDC discovery or keys).
    Issuer,
    /// AWS STS, for an AWS caller's signed request.
    Sts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Seal,
    Session,
    Extend,
    End,
    Signal,
}

/// What a replica signs with its telemetry key and ships to the control plane
/// (`POST /v1/tenants/{tenant}/telemetry`). `stream` is random per replica boot and `sequence`
/// counts its batches from 0, so a dropped batch shows up as a gap; entries are numbered
/// across the stream, so an `TelemetryReceipt` names exactly one. The signature covers the batch
/// as shipped (sealed entries included), so anyone can check it without reading entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryBatch {
    pub tenant: TenantId,
    #[serde(with = "codec::array_b64")]
    pub stream: [u8; 16],
    pub sequence: u64,
    /// Stream-wide number of the first entry; this batch holds `first_entry..first_entry + count`.
    pub first_entry: u64,
    pub count: u32,
    /// Earliest and latest entry `at`, so `?since=` works on sealed batches.
    pub from: UnixTime,
    pub to: UnixTime,
    pub entries: TelemetryEntries,
    /// Set on the final batch of a stream (graceful shutdown). A stream that ends without
    /// one may have lost its unsent tail.
    pub last: bool,
}
pub const TELEMETRY_BATCH_LABEL: &str = "seal/telemetry-batch/v1";
pub type SignedTelemetryBatch = Signed<TelemetryBatch>;

/// Entries in clear when the tenant names no `TenantState::telemetry_readers`, sealed to them otherwise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryEntries {
    Clear {
        entries: Vec<TelemetryEntry>,
    },
    /// `ciphertext = AES-256-GCM(batch key, canonical(entries))` with a fresh batch key,
    /// `aad = canonical((tenant, stream, sequence, first_entry, count))`. The batch key is
    /// HPKE-sealed (ingest suite, `info = TELEMETRY_READER_INFO`, same aad) once per reader.
    Sealed {
        readers: Vec<TelemetryReaderKey>,
        #[serde(with = "codec::array_b64")]
        nonce: [u8; 12],
        #[serde(with = "codec::bytes_b64")]
        ciphertext: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryReaderKey {
    pub reader: PublicKey,
    #[serde(with = "codec::bytes_b64")]
    pub enc: Vec<u8>,
    #[serde(with = "codec::bytes_b64")]
    pub wrapped_key: Vec<u8>,
}
pub const TELEMETRY_READER_INFO: &[u8] = b"seal/telemetry-reader/v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlstates_are_five_ascii_upper_case_alphanumerics() {
        let outcome = Outcome::UpstreamError(UpstreamErrorKind::Sqlstate(Sqlstate::new(*b"42P01").unwrap()));
        let json = serde_json::to_string(&outcome).unwrap();
        assert_eq!(json, r#"{"upstream_error":{"sqlstate":"42P01"}}"#);
        assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);
        assert!(Sqlstate::new(*b"42p01").is_none());
        for bad in [r#""42p01""#, r#""4201""#, r#""42P010""#, r#""42 01""#] {
            assert!(serde_json::from_str::<Sqlstate>(bad).is_err(), "{bad}");
        }
    }
}

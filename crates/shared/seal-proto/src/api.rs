//! The enclave's control API (JSON over the attested TLS channel).
//!
//! | Method | Path                | Request               | Response              | Authorized by |
//! |--------|---------------------|-----------------------|-----------------------|---------------|
//! | GET    | /v1/attestation     | (none)                | `AttestationResponse` | nobody (public) |
//! | GET    | /v1/attestation?nonce=<b64url> | (none)     | `ChallengedAttestation` | nobody (public) |
//! | POST   | /v1/tickets         | (empty)               | `ProofTicket`         | nobody (public) |
//! | POST   | /v1/blobs           | `SealRequest`         | `SealResponse`        | nobody (public) |
//! | POST   | /v1/sessions        | `SessionRequest`      | `SessionResponse`     | identity proof |
//! | POST   | /v1/sessions/extend | `ExtendRequest`       | `ExtendResponse`      | identity proof + token |
//! | POST   | /v1/sessions/end    | `EndRequest`          | (empty)               | token |
//! | POST   | /v1/signals         | `SignalRequest`       | (empty)               | identity proof |
//!
//! `/v1/attestation` serves the enclave's latest periodic attestation
//! (`freshness::ATTESTATION_REFRESH_SECS`). With `?nonce=` (32 bytes, base64url, the only
//! parameter) it answers that challenge for the TLS connection it arrives on
//! (`ChallengedAttestation`), which only TLS 1.3 connections can ask. `/v1/tickets` is rate
//! limited per connection source.
//!
//! Tickets are for the enclave's one tenant (its tenant pin). Ending a session needs
//! only its token: holding the token already allows using the session, and ending it only
//! takes access away.
//!
//! Errors: HTTP `ErrorCode::http_status()` with an `ApiError` body.

use serde::{Deserialize, Serialize};

use crate::identity::{IdentityProof, ProofContext, ProofPurpose};
use crate::integrity::{EndpointReport, Severity};
use crate::policy::{Destination, Injection, SecretPolicy};
use crate::release::ReleaseEvidence;
use crate::session::{ConsumerTier, SessionInfo};
use crate::{codec, Bearer, BlobId, ErrorCode, PublicKey, SecretVec, ServiceKeyVersion, TenantId};

/// What the enclave commits to in its attestation's report data:
/// `labeled_digest(ATTESTATION_BINDING_LABEL, &AttestationBinding)`.
/// A client that verified the evidence, the release and this binding knows
/// the TLS key it talks to and the ingest key it encrypts to live in that release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBinding {
    /// The enclave's `TrustedTime::now` when it attested. Clients accept it within
    /// `ATTESTATION_MAX_AGE_SECS` of their own clock.
    pub attested_at: crate::UnixTime,
    pub service_key_version: ServiceKeyVersion,
    /// SHA-256 of the inbound TLS SubjectPublicKeyInfo DER. Same for every replica of this tenant and service key version.
    #[serde(with = "codec::array_b64")]
    pub tls_spki_sha256: [u8; 32],
    /// X25519 public key secrets are HPKE-sealed to.
    pub ingest_public_key: PublicKey,
    /// Telemetry public keys of service key versions 1..=`service_key_version`. A client that
    /// verified this enclave can verify `TelemetryBatch`es and enclave-signed signals with them.
    pub telemetry_public_keys: Vec<(ServiceKeyVersion, PublicKey)>,
}

pub const ATTESTATION_BINDING_LABEL: &str = "seal/attestation-binding/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// The enclave's latest periodic evidence; its report data is the binding's digest.
    pub evidence: crate::Evidence,
    pub binding: AttestationBinding,
    /// Release manifest, log proofs, fresh checkpoint: everything to accept this measurement.
    pub release: ReleaseEvidence,
    /// The guardian's certificate over the binding's keys. Proves the guardian released them,
    /// so every guardian check (time lock, co-signature, tenant freshness) passed; it also
    /// names the tenant and root the enclave serves.
    pub certificate: crate::release::SignedServiceKeyCertificate,
}

/// `GET /v1/attestation?nonce=`: proof that the TLS connection it arrives on ends in a replica
/// of an approved release that serves the attested keys, now. The service keys alone prove
/// neither: every replica of a tenant and service key version shares them, so a holder of keys
/// copied out of a build later revoked, or out of hardware later below `min_tcb`, could serve
/// TLS with them and any replica's periodic attestation.
///
/// Every replica generates a challenge key in its own memory when it starts; it never leaves
/// the replica. With each periodic attestation the replica also attests to it: `evidence`
/// commits to `labeled_digest(ATTESTATION_KEY_LABEL, &AttestationKeyBinding)`, under the same
/// age rule as `AttestationResponse`. Per challenge it signs `AttestationChallenge`: the
/// caller's nonce and the TLS exporter of the connection the request came on, which only the
/// two ends of that connection know. A relay holding the TLS key ends its own connection to an
/// honest replica, whose exporter differs, so the signature it can obtain fails. One signature
/// per challenge, no hardware report: answering costs the TEE nothing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengedAttestation {
    /// The latest evidence over the challenge key; its report data is the
    /// `AttestationKeyBinding`'s digest.
    pub evidence: crate::Evidence,
    pub binding: AttestationBinding,
    pub challenge_key: PublicKey,
    pub release: ReleaseEvidence,
    pub certificate: crate::release::SignedServiceKeyCertificate,
    /// `challenge_key`'s signature (`ATTESTATION_CHALLENGE_LABEL`) over the `AttestationChallenge`.
    pub signature: crate::signed::Signature,
}

/// What a replica's challenge-key evidence commits to:
/// `labeled_digest(ATTESTATION_KEY_LABEL, &AttestationKeyBinding)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationKeyBinding {
    pub binding: AttestationBinding,
    /// Ed25519; generated in the replica's memory at start, never released or stored.
    pub challenge_key: PublicKey,
}

pub const ATTESTATION_KEY_LABEL: &str = "seal/attestation-key/v1";

/// What `ChallengedAttestation::signature` signs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationChallenge {
    /// The caller's, from the query.
    #[serde(with = "codec::array_b64")]
    pub nonce: [u8; 32],
    /// The connection's TLS exporter (RFC 8446 section 7.5): label `ATTESTATION_EXPORTER_LABEL`,
    /// no context, 32 bytes.
    #[serde(with = "codec::array_b64")]
    pub tls_exporter: [u8; 32],
}

pub const ATTESTATION_CHALLENGE_LABEL: &str = "seal/attestation-challenge/v1";
pub const ATTESTATION_EXPORTER_LABEL: &[u8] = b"EXPORTER-seal-attestation-challenge-v1";

/// HPKE plaintext of `SealRequest::sealed_payload`. Only the enclave ever decrypts it.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealPayload {
    pub secret: SecretVec,
    pub policy: SecretPolicy,
}

/// `seal()`. HPKE: base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, with
/// info `ingest_info(tenant)` and `canonical(IngestContext)` as AAD. Anyone may seal: the
/// request carries no proof, and the enclave decrypts it only if it was sealed for this
/// enclave's tenant, service key version and TLS key.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealRequest {
    pub service_key_version: ServiceKeyVersion,
    #[serde(with = "codec::bytes_b64")]
    pub hpke_enc: Vec<u8>,
    #[serde(with = "codec::bytes_b64")]
    pub sealed_payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealResponse {
    /// Text form of the blob (`seal1.…`).
    pub blob: String,
    pub blob_id: BlobId,
    /// Where telemetry records this seal.
    pub telemetry: TelemetryReceipt,
}

/// Start a session. `expected_purpose()` binds the blob and every option.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRequest {
    pub blob: String,
    pub context: ProofContext,
    pub proof: IdentityProof,
    pub min_tier: Option<ConsumerTier>,
    /// What the endpoint reports about itself; checked against the app's artifact rule.
    pub endpoint: Option<EndpointReport>,
}

/// The caller signals that its own endpoint may be compromised (an SDK or a host agent
/// holding the workload identity). The enclave signs it as `SignalSource::Sdk` for the
/// authenticated caller only, so nobody can signal about another identity this way.
/// One body, two credentials, and the payload itself says which: a workload `proof`
/// (the caller signals about itself; identity, `Sdk` source, tenant and time are all
/// derived) or `signatures` by an enrolled external source (only what the sender
/// uniquely knows travels: code, severity, identity, observed_at, optional blob_id —
/// the tenant is the replica's pin and the source is the enrolled key the signature
/// names, both derived and both still covered by the signature).
///
/// Exactly one credential: `signatures` non-empty XOR `context`+`proof` present, and a
/// proof carries none of the external fields (a caller naming its own identity is
/// impersonation).
#[derive(Debug, Serialize, Deserialize)]
pub struct SignalRequest {
    /// Opaque to Seal; `integrity::validate_code` shape.
    pub code: String,
    pub severity: Severity,
    /// Self-signal: the shared proof binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ProofContext>,
    /// Self-signal: the workload proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<IdentityProof>,
    /// External: whose endpoint the finding is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<crate::identity::WorkloadIdentity>,
    /// External: when the source observed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<crate::UnixTime>,
    /// External: the secret in use, when it came from traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_id: Option<crate::BlobId>,
    /// External: signatures over the full signal (derived fields included).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<crate::signed::Signature>,
}

/// Extend a live session with a fresh identity proof. The enclave redeems `token`, requires
/// the proof to be from the same caller, rechecks grants, suspension, expiry and the endpoint
/// report, and issues a new token for the same `session_id` with a new `expires_at`.
/// `token` must not have expired: an expired session is started again instead.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtendRequest {
    pub token: Bearer,
    pub endpoint: Option<EndpointReport>,
    pub context: ProofContext,
    pub proof: IdentityProof,
}

/// End a session now, on every replica: the enclave refuses its tokens from then on and
/// closes its connections (`SessionEnd`). The SDK sends it from `Session::close`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EndRequest {
    pub token: Bearer,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtendResponse {
    pub token: Bearer,
    pub expires_at: crate::UnixTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub token: Bearer,
    pub info: SessionInfo,
    pub destination: Destination,
    /// Set when the blob's tenant key version is decrypt-only: the same secret resealed under
    /// the current tenant key version. The SDK hands it to `on_reseal`.
    pub resealed: Option<String>,
    /// HTTP destinations: where clients put `s.key`.
    pub injection: Option<Injection>,
    /// Where telemetry records this session's start.
    pub telemetry: TelemetryReceipt,
}

/// The telemetry entry a response's operation was recorded as (`TelemetryBatch::first_entry`
/// numbers entries within a stream). A client that keeps receipts can prove an entry was
/// withheld, including a whole stream the control plane never showed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryReceipt {
    #[serde(with = "codec::array_b64")]
    pub stream: [u8; 16],
    pub entry: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    /// Human-readable, safe to show: never contains secrets or internal detail.
    pub message: String,
}

/// The seal upload's HPKE AAD: the enclave it was sealed for. The enclave computes it from
/// its own tenant pin, service key version and TLS key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestContext {
    pub tenant: TenantId,
    pub service_key_version: ServiceKeyVersion,
    #[serde(with = "codec::array_b64")]
    pub tls_spki_sha256: [u8; 32],
}
impl SessionRequest {
    pub fn expected_purpose(&self) -> ProofPurpose {
        ProofPurpose::Session {
            request_digest: codec::labeled_digest(
                "seal/session-request/v1",
                &(&self.blob, self.min_tier, &self.endpoint),
            ),
        }
    }
    /// The challenge an endpoint reporter binds evidence to: the request digest with the
    /// report stripped, so it is computable before the report exists (using
    /// `expected_purpose` directly would be circular). Covers blob and tier.
    pub fn evidence_challenge(&self) -> [u8; 32] {
        codec::labeled_digest("seal/session-request/v1", &(&self.blob, self.min_tier, &Option::<EndpointReport>::None))
    }
}
impl ExtendRequest {
    pub fn expected_purpose(&self) -> ProofPurpose {
        ProofPurpose::Extend {
            request_digest: codec::labeled_digest("seal/extend-request/v1", &(&self.token, &self.endpoint)),
        }
    }
    /// The evidence challenge for an extend: the token and nothing else (see
    /// `SessionRequest::evidence_challenge`).
    pub fn evidence_challenge(&self) -> [u8; 32] {
        codec::labeled_digest("seal/extend-request/v1", &(&self.token, &Option::<EndpointReport>::None))
    }
}
impl SignalRequest {
    pub fn expected_purpose(&self) -> ProofPurpose {
        ProofPurpose::Signal {
            request_digest: codec::labeled_digest("seal/signal-request/v1", &(&self.code, self.severity)),
        }
    }
}

//! Freshness: the enclave's periodic attestation, guardian challenges and proof tickets.
//! AEAD nonces remain encryption metadata.
use serde::{Deserialize, Serialize};

use crate::{codec, UnixTime};

/// The enclave attests on its own schedule, not per client: every `ATTESTATION_REFRESH_SECS`
/// it gets fresh evidence binding its keys and its trusted time (`AttestationBinding::
/// attested_at`), and serves the latest to everyone. One hardware report (or one Confidential
/// Space token, which Google rate-limits per project) serves every client, and the public
/// endpoint costs nothing to call.
pub const ATTESTATION_REFRESH_SECS: u64 = 30;
/// Clients accept an attestation whose `attested_at` is within this of their own clock, in
/// either direction. A replayed recent one convinces only a client that also gets the TLS
/// handshake with the attested key, which every replica of those keys shares; so before
/// anything secret goes out, the SDK also asks the connection it goes on for a
/// `crate::api::ChallengedAttestation`, which a replay cannot answer.
pub const ATTESTATION_MAX_AGE_SECS: u64 = 120;

/// Guardian-issued and stateless, so any guardian instance verifies it and no one can exhaust
/// a challenge table: `mac = HMAC-SHA256(challenge_key, canonical((value, expires_at)))`, the
/// key derived from the platform master key. Reusable until expiry, and that is harmless: a
/// replayed `KeyRequest` only gets keys sealed again to the original requester's ephemeral key.
/// It bounds how old the requester's evidence can be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianChallenge {
    #[serde(with = "codec::array_b64")]
    pub value: [u8; 32],
    pub expires_at: UnixTime,
    #[serde(with = "codec::array_b64")]
    pub mac: [u8; 32],
}

/// Guardian challenges live 60 seconds.
pub const GUARDIAN_CHALLENGE_TTL_SECS: u64 = 60;

/// Enclave-issued (`POST /v1/tickets`) and stateless, so any replica can verify it:
/// `mac = HMAC-SHA256(ticket_key, canonical((tenant, value, expires_at)))`.
/// Reusable until expiry; identity proofs bind to it through `ProofContext`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTicket {
    #[serde(with = "codec::array_b64")]
    pub value: [u8; 32],
    pub expires_at: UnixTime,
    #[serde(with = "codec::array_b64")]
    pub mac: [u8; 32],
}

/// Proof tickets live 120 seconds.
pub const TICKET_TTL_SECS: u64 = 120;

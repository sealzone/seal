//! Who reads a tenant's documents on the control plane. Grants, telemetry and proposals are
//! not public: a request for them carries one of
//!
//! - a console control token (`Authorization: Bearer sealct_…`, the console's own format);
//! - a `SignedControlRequest` (`Authorization: SealSigned <base64url(JSON)>`), signed by an
//!   admin key of the tenant's latest root (admin tools) or by a telemetry key of a
//!   guardian-certified `ServiceKeyCertificate` (the tenant's enclaves);
//! - an `AttestedControlRequest` (`Authorization: SealAttested <base64url(JSON)>`): an enclave
//!   at boot, before the guardian released the keys it would sign with, reads its bundle with
//!   evidence that a released enclave build pinned to the tenant makes the request.
//!
//! Each names exactly one request: the tenant and root chain, the method, the path with its
//! query, and the body's SHA-256, so it cannot be used for another request or tenant.

use serde::{Deserialize, Serialize};

use crate::signed::Signed;
use crate::{codec, Evidence, TenantId, TenantRootId, UnixTime};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRequest {
    pub tenant: TenantId,
    /// The chain the requester belongs to; the control plane serves it only for that chain.
    pub root_id: TenantRootId,
    /// `GET`, `PUT`, `POST` or `DELETE`.
    pub method: String,
    /// Path and query exactly as sent (`/v1/tenants/acme/telemetry?since=0`).
    pub path: String,
    /// SHA-256 of the request body (of no bytes for a request without one).
    #[serde(with = "codec::array_b64")]
    pub body_sha256: [u8; 32],
    /// When the requester made it. The control plane accepts it within
    /// `CONTROL_REQUEST_MAX_AGE_SECS` of its own clock, either way.
    pub issued_at: UnixTime,
}
/// What request signatures sign, and what an attested request's evidence commits to
/// (`labeled_digest(CONTROL_REQUEST_LABEL, request)` as report data).
pub const CONTROL_REQUEST_LABEL: &str = "seal/control-request/v1";

/// How far a request's `issued_at` may be from the control plane's clock.
pub const CONTROL_REQUEST_MAX_AGE_SECS: u64 = 300;

pub type SignedControlRequest = Signed<ControlRequest>;

/// A request made by an enclave that holds no keys yet: its evidence's report data is
/// `labeled_digest(CONTROL_REQUEST_LABEL, request)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedControlRequest {
    pub request: ControlRequest,
    pub evidence: Evidence,
}

/// `Authorization` scheme of a `SignedControlRequest`.
pub const SIGNED_SCHEME: &str = "SealSigned";
/// `Authorization` scheme of an `AttestedControlRequest`.
pub const ATTESTED_SCHEME: &str = "SealAttested";

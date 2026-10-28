//! App Integrity in the enclave: what adapters report per request, and the detectors that
//! judge it. Findings become signals; the runtime applies the tenant's policy and records
//! the outcome in telemetry.
//!
//! - Adapters report each request twice through their session: an `Observation` before
//!   forwarding (`seal_adapter::Session::observe`, obeying the returned `Verdict`) and a
//!   `Completion` after it ends (`Session::complete`). They never judge integrity, never
//!   write telemetry and never see which identity is behind the session.
//! - A `Detector` (SQL injection, unusual API calls) is pure and judges one `Observation`,
//!   returning an opaque `Finding`. Detectors are compiled into the image, so
//!   customer-specific detectors need the Custom plan.
//! - The enclave runtime (`seal-enclave`) owns the sessions. From each report it runs the
//!   detectors (signing an `IntegritySignal` per finding and applying the tenant's
//!   `IntegrityPolicy`) and writes the telemetry entry; metrics will come from the same
//!   reports.
//!
//! Observation content stays in the enclave: never logged, exported or put in a signal.
#![forbid(unsafe_code)]

use seal_proto::integrity::Severity;
use seal_proto::integrity::{EndpointEvidence, EndpointReport};
use seal_proto::policy::Protocol;
use seal_proto::{ErrorCode, TrustedTime};

pub use seal_proto::telemetry::{Completion, Outcome, UpstreamErrorKind};

/// One request as an adapter sees it, after the adapter's own policy checks pass.
#[derive(Debug)]
pub struct Observation<'a> {
    pub protocol: Protocol,
    /// The same fixed-vocabulary summary as `Completion::action`.
    pub action: &'a str,
    /// What detectors may inspect: SQL text, the Redis command line, or the HTTP method,
    /// path and query. Never the client's credential or the injected secret.
    pub content: &'a [u8],
}

/// What the adapter must do with the observed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Forward,
    /// Refuse this request in the protocol's own error format; keep the connection.
    Refuse(ErrorCode),
    /// Refuse it and end the whole session: the runtime publishes a `SessionEnd`, so every
    /// replica refuses its tokens and closes its connections. Whether the identity's other
    /// sessions end too is up to the tenant's integrity policy (a suspension).
    End(ErrorCode),
}

/// What a detector found. Opaque to Seal beyond `severity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    /// `seal_proto::telemetry::validate_code` shape, e.g. `sqli`.
    pub code: String,
}

/// One pluggable in-enclave detector. Pure: no IO, no clock, no state across calls.
/// Its two halves mirror `seal_adapter::Session::{observe, complete}`; implement whichever
/// it needs, both default to no finding.
pub trait Detector: Send + Sync {
    /// Short name recorded as `SignalSource::Enclave { detector }`.
    fn name(&self) -> &'static str;
    fn protocols(&self) -> &[Protocol];
    /// Before forwarding: may refuse the request through the policy's action.
    fn observe(&self, observation: &Observation<'_>) -> Option<Finding> {
        let _ = observation;
        None
    }
    /// After completion (e.g. upstream auth failures): affects later requests only.
    fn complete(&self, completion: &Completion) -> Option<Finding> {
        let _ = completion;
        None
    }
}

/// Verifies one provider's opaque endpoint evidence (`EndpointReport.evidence`), e.g. a
/// host agent's signed statement, an EDR posture token or a device attestation. Seal
/// never reads the bytes itself. Pure: every input arrives as an argument, no IO.
pub trait EvidenceCheck: Send + Sync {
    /// Matches `EndpointEvidence::provider`; also the name the tenant registers the
    /// provider's public key under in `IntegrityPolicy::sources`.
    fn provider(&self) -> &'static str;
    /// `None` = acceptable; `Some` = a finding against the identity starting or extending
    /// the session. `key` is the tenant's registered public key for this provider, `None`
    /// when the tenant registered none (ignore the evidence then). `challenge` is the
    /// request digest the reporter bound the evidence to; a check that verifies signatures
    /// must refuse evidence whose challenge is not the request being authorized, so signed
    /// statements cannot be replayed across requests. The whole `report` is given so a
    /// check can hold the self-asserted fields (e.g. `report.artifact`) to the signed ones.
    fn check(
        &self,
        report: &EndpointReport,
        evidence: &EndpointEvidence,
        key: Option<&seal_proto::PublicKey>,
        challenge: &[u8; 32],
        time: &TrustedTime,
    ) -> Option<Finding>;
}

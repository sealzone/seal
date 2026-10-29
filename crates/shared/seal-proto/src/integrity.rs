//! Integrity wire types: signals that a workload's endpoint may be compromised, and the
//! tenant's rules for acting on them. The App Integrity add-on (crate `seal-integrity`)
//! plugs detectors and evidence checks in on top of these.
//!
//! Signals are the enclave's inputs; telemetry (`crate::telemetry`) is its output. Every
//! source produces the same record, a `SignedSignal`:
//! - the SDK, through its `EndpointReport` at session start and extend, and signals about
//!   itself (`SignalRequest`);
//! - detectors inside the enclave that see protocol traffic (`seal-integrity`);
//! - external systems (EDR, host agents) signing with a key the tenant registered.
//!
//! Signals are opaque to Seal: it acts only on whose endpoint (`identity`) and how bad
//! (`severity`). What a source detected, and how, stays inside the source; the signal
//! carries a short `code` for telemetry and admins, never interpreted by Seal. Integrating an
//! EDR or a detector means producing `(identity, severity, code)`, nothing more.
//!
//! Signals from the enclave and the SDK are signed by the enclave's telemetry key; external
//! ones by their source's key. Every replica evaluates the same admin-signed
//! `IntegrityPolicy` over the same verified signals, so replicas agree on suspensions
//! without coordinating. Phase 1 enforces one check, the endpoint's artifact hash.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::identity::WorkloadIdentity;
use crate::signed::Signed;
use crate::{codec, AppName, BlobId, PublicKey, TenantId, UnixTime};

/// What the SDK reports about its endpoint at session start and every extend, bound into
/// `SessionRequest::expected_purpose()`. Self-asserted: it catches drift and tampering
/// below full endpoint compromise, not an attacker who controls the endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointReport {
    /// What the endpoint runs. Checked against `IntegrityPolicy::artifacts` (Phase 1).
    pub artifact: Option<ArtifactHash>,
    /// Opaque provider evidence (EDR posture token, device attestation), passed to a
    /// provider-specific verifier later. Not evaluated in Phase 1.
    pub evidence: Vec<EndpointEvidence>,
}

/// A named SHA-256, e.g. `executable`, `image` or an app-defined bundle name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactHash {
    pub name: String,
    #[serde(with = "codec::array_b64")]
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEvidence {
    /// Who produced it, e.g. `defender` or `tpm`.
    pub provider: String,
    #[serde(with = "codec::bytes_b64")]
    pub bytes: Vec<u8>,
}

/// One observation that the endpoint behind `identity` may be compromised.
/// Never carries payloads, credentials or secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegritySignal {
    pub tenant: TenantId,
    pub identity: WorkloadIdentity,
    pub source: SignalSource,
    /// Source-defined, opaque to Seal: shown in telemetry and to admins only. 1..=64 bytes of
    /// `[a-z0-9-.]`, e.g. `artifact-mismatch`, `sqli`, `edr-high`.
    pub code: String,
    pub severity: Severity,
    pub observed_at: UnixTime,
    /// The blob in use, when the signal came from traffic.
    pub blob_id: Option<BlobId>,
}
pub const SIGNAL_LABEL: &str = "seal/integrity-signal/v1";
pub type SignedSignal = Signed<IntegritySignal>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalSource {
    /// An in-enclave detector, by name. Signed by the enclave's telemetry key.
    Enclave { detector: String },
    /// The SDK at session start or extend, or a signal about itself. Signed by the enclave for the authenticated caller.
    Sdk,
    /// An external system, signing with `IntegrityPolicy::sources[source]`.
    External { source: String },
}

/// Codes Seal itself emits. Sources pick their own.
pub const CODE_ARTIFACT_MISMATCH: &str = "artifact-mismatch";

/// Checks the `IntegritySignal::code` shape; the meaning stays the source's.
pub fn validate_code(code: &str) -> Result<(), crate::ProtoError> {
    let ok = (1..=64).contains(&code.len())
        && code.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(crate::ProtoError::invalid("code", "1-64 chars of [a-z0-9-.]"))
    }
}

/// Ordered: `Low < Medium < High < Critical`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntegrityAction {
    /// Only record it in telemetry.
    LogOnly,
    /// Refuse the request or session start that produced the signal.
    Deny,
    /// No session starts, extends or seals by the identity, and its live sessions end. `secs: None` lasts
    /// until an admin clears it. Blobs the identity sealed keep working for others.
    Suspend { secs: Option<u64> },
}

/// The tenant's integrity rules, part of the admin-signed `TenantState`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityPolicy {
    /// Allowed artifacts per app. An app listed here starts sessions only with a matching
    /// `EndpointReport`; an app not listed is not checked.
    pub artifacts: BTreeMap<AppName, BTreeSet<ArtifactHash>>,
    /// External sources this tenant trusts, by name.
    pub sources: BTreeMap<String, PublicKey>,
    /// Response from each severity upward; the highest entry at or below a signal's
    /// severity applies. Empty = log only.
    pub actions: BTreeMap<Severity, IntegrityAction>,
    /// Admin clearances: signals for the identity (`WorkloadIdentity::same_subject`) observed at
    /// or before `before` are ignored.
    pub cleared: BTreeSet<Clearance>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Clearance {
    pub identity: WorkloadIdentity,
    pub before: UnixTime,
}

impl IntegrityPolicy {
    pub fn action_for(&self, severity: Severity) -> IntegrityAction {
        self.actions.range(..=severity).next_back().map_or(IntegrityAction::LogOnly, |(_, action)| *action)
    }

    /// Whether `app` may start or extend a session with `report` under the artifact rule.
    pub fn admits(&self, app: &AppName, report: Option<&EndpointReport>) -> bool {
        match self.artifacts.get(app) {
            None => true,
            Some(allowed) => {
                report.and_then(|r| r.artifact.as_ref()).is_some_and(|artifact| allowed.contains(artifact))
            }
        }
    }

    /// Whether `signal` still has an effect at `time` (its earliest end, so a suspension never ends early): its action is `Suspend`, no clearance
    /// covers it, and a timed suspension has not run out. Replicas publish only signals that
    /// are live when created; the control plane may drop signals that are no longer live
    /// under the latest policy.
    pub fn is_live(&self, signal: &IntegritySignal, time: &crate::TrustedTime) -> bool {
        if self.is_cleared(signal) {
            return false;
        }
        match self.action_for(signal.severity) {
            IntegrityAction::Suspend { secs: None } => true,
            IntegrityAction::Suspend { secs: Some(secs) } => time.earliest() < signal.observed_at.saturating_add(secs),
            IntegrityAction::LogOnly | IntegrityAction::Deny => false,
        }
    }

    /// Whether an admin cleared `signal` (its identity by `WorkloadIdentity::same_subject`,
    /// observed at or before a clearance).
    fn is_cleared(&self, signal: &IntegritySignal) -> bool {
        self.cleared.iter().any(|c| c.identity.same_subject(&signal.identity) && signal.observed_at <= c.before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyId;

    fn hash(name: &str, b: u8) -> ArtifactHash {
        ArtifactHash { name: name.into(), sha256: [b; 32] }
    }

    #[test]
    fn action_is_the_highest_entry_at_or_below_the_severity() {
        let mut p = IntegrityPolicy::default();
        assert_eq!(p.action_for(Severity::Critical), IntegrityAction::LogOnly);
        p.actions.insert(Severity::Medium, IntegrityAction::Deny);
        p.actions.insert(Severity::Critical, IntegrityAction::Suspend { secs: None });
        assert_eq!(p.action_for(Severity::Low), IntegrityAction::LogOnly);
        assert_eq!(p.action_for(Severity::High), IntegrityAction::Deny);
        assert_eq!(p.action_for(Severity::Critical), IntegrityAction::Suspend { secs: None });
    }

    #[test]
    fn artifact_rule_applies_only_to_listed_apps() {
        let app = AppName::new("checkout").unwrap();
        let other = AppName::new("billing").unwrap();
        let mut p = IntegrityPolicy::default();
        p.artifacts.insert(app.clone(), [hash("image", 1)].into());
        let good = EndpointReport { artifact: Some(hash("image", 1)), evidence: vec![] };
        let bad = EndpointReport { artifact: Some(hash("image", 2)), evidence: vec![] };
        assert!(p.admits(&app, Some(&good)));
        assert!(!p.admits(&app, Some(&bad)));
        assert!(!p.admits(&app, None));
        assert!(p.admits(&other, None));
    }

    #[test]
    fn clearance_covers_only_earlier_signals_of_that_identity() {
        let id = WorkloadIdentity::AppKey { key_id: KeyId([1; 32]) };
        let signal = |identity: WorkloadIdentity, observed_at| IntegritySignal {
            tenant: TenantId::new("acme").unwrap(),
            identity,
            source: SignalSource::Sdk,
            code: "self-signal".into(),
            severity: Severity::High,
            observed_at,
            blob_id: None,
        };
        let mut p = IntegrityPolicy::default();
        p.cleared.insert(Clearance { identity: id.clone(), before: 100 });
        assert!(p.is_cleared(&signal(id.clone(), 100)));
        assert!(!p.is_cleared(&signal(id, 101)));
        assert!(!p.is_cleared(&signal(WorkloadIdentity::AppKey { key_id: KeyId([2; 32]) }, 50)));
    }

    #[test]
    fn only_uncleared_suspensions_in_force_are_live() {
        let id = WorkloadIdentity::AppKey { key_id: KeyId([1; 32]) };
        let signal = |severity| IntegritySignal {
            tenant: TenantId::new("acme").unwrap(),
            identity: id.clone(),
            source: SignalSource::Sdk,
            code: "self-signal".into(),
            severity,
            observed_at: 100,
            blob_id: None,
        };
        let mut p = IntegrityPolicy::default();
        p.actions.insert(Severity::Low, IntegrityAction::Deny);
        p.actions.insert(Severity::High, IntegrityAction::Suspend { secs: Some(60) });
        p.actions.insert(Severity::Critical, IntegrityAction::Suspend { secs: None });
        assert!(!p.is_live(&signal(Severity::Low), &crate::TrustedTime::exact(100)));
        assert!(p.is_live(&signal(Severity::High), &crate::TrustedTime::exact(159)));
        assert!(!p.is_live(&signal(Severity::High), &crate::TrustedTime::exact(160)));
        assert!(p.is_live(&signal(Severity::Critical), &crate::TrustedTime::exact(u64::MAX)));
        p.cleared.insert(Clearance { identity: id.clone(), before: 100 });
        assert!(!p.is_live(&signal(Severity::Critical), &crate::TrustedTime::exact(101)));
    }

    #[test]
    fn codes_are_short_opaque_labels() {
        for ok in [CODE_ARTIFACT_MISMATCH, "self-signal", "sqli", "defender.alert-7"] {
            assert!(validate_code(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Has Spaces", "x".repeat(65).as_str(), "secret=sk-123"] {
            assert!(validate_code(bad).is_err(), "{bad}");
        }
    }
}

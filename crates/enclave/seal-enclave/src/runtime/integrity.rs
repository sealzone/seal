//! Signals this replica creates (self-signals, `artifact-mismatch`, detector and evidence
//! findings): each is signed with the telemetry key, recorded with the action the tenant's
//! policy takes, applied here at once when it suspends, and then published so the other
//! replicas apply it within `STATE_RELOAD_SECS`.

use std::sync::Arc;

use seal_integrity::{Finding, Verdict};
use seal_proto::identity::WorkloadIdentity;
use seal_proto::integrity::Severity;
use seal_proto::integrity::{
    validate_code, EndpointReport, IntegrityAction, IntegrityPolicy, IntegritySignal, SignalSource, SignedSignal,
    SIGNAL_LABEL,
};
use seal_proto::telemetry::TelemetryEvent;
use seal_proto::{BlobId, ErrorCode, TrustedTime};

use super::state::Local;
use super::{fail, Runtime};
use crate::ServiceError;

/// What a request the signal came from gets: `LogOnly` forwards, `Deny` refuses it, `Suspend`
/// ends the session (the suspension ends the identity's other sessions too).
pub(super) fn verdict(action: IntegrityAction) -> Verdict {
    match action {
        IntegrityAction::LogOnly => Verdict::Forward,
        IntegrityAction::Deny => Verdict::Refuse(ErrorCode::IntegrityFailed),
        IntegrityAction::Suspend { .. } => Verdict::End(ErrorCode::IntegrityFailed),
    }
}

/// The stricter of two verdicts: `End` over `Refuse` over `Forward`.
pub(super) fn stricter(a: Verdict, b: Verdict) -> Verdict {
    let rank = |v: &Verdict| match v {
        Verdict::Forward => 0,
        Verdict::Refuse(_) => 1,
        Verdict::End(_) => 2,
    };
    if rank(&b) > rank(&a) {
        b
    } else {
        a
    }
}

impl Runtime {
    /// Signs and records `signal`; applies it when it is live (`IntegrityPolicy::is_live`, it
    /// suspends) and returns it then, for publishing. A signal that is not live has no effect
    /// beyond the request it came from, so it exists only in telemetry.
    pub(super) fn raise(&self, signal: IntegritySignal, time: &TrustedTime) -> (IntegrityAction, Option<SignedSignal>) {
        let policy = self.state.get().map(|t| t.state().integrity.clone()).unwrap_or_default();
        let signed = self.service.telemetry.signer().sign_into(SIGNAL_LABEL, signal);
        self.take_signal(signed, &policy, time)
    }

    /// A verified signal under `policy`: recorded with the action the policy takes, and applied
    /// here when it is live; returned then, for publishing.
    pub(super) fn take_signal(
        &self,
        signed: SignedSignal,
        policy: &IntegrityPolicy,
        time: &TrustedTime,
    ) -> (IntegrityAction, Option<SignedSignal>) {
        let signal = &signed.body;
        let action = policy.action_for(signal.severity);
        self.record(
            Some(signal.identity.clone()),
            TelemetryEvent::Integrity {
                source: signal.source.clone(),
                code: signal.code.clone(),
                severity: signal.severity,
                action,
            },
        );
        if !policy.is_live(signal, time) {
            return (action, None);
        }
        self.apply_local(Local::Signal(signed.clone()));
        (action, Some(signed))
    }

    /// `raise`, then publishes the signal if it is live.
    pub(super) async fn raise_and_publish(
        &self,
        signal: IntegritySignal,
        time: &TrustedTime,
    ) -> Result<IntegrityAction, ServiceError> {
        let (action, publish) = self.raise(signal, time);
        if let Some(signed) = publish {
            self.tenants.publish_signal(&signed).await?;
        }
        Ok(action)
    }

    /// `raise` from synchronous code (adapter reports): publishing runs in the background.
    pub(super) fn raise_detached(self: &Arc<Self>, signal: IntegritySignal, time: &TrustedTime) -> IntegrityAction {
        let (action, publish) = self.raise(signal, time);
        if let Some(signed) = publish {
            let runtime = self.clone();
            tokio::spawn(async move {
                if let Err(e) = runtime.tenants.publish_signal(&signed).await {
                    tracing::warn!(error = %e, "publishing a signal failed");
                }
            });
        }
        action
    }

    /// The signal a finding about `identity` becomes; `None` for a finding whose code is not
    /// a valid signal code.
    pub(super) fn finding_signal(
        &self,
        identity: &WorkloadIdentity,
        source: SignalSource,
        finding: Finding,
        blob_id: Option<BlobId>,
        time: &TrustedTime,
    ) -> Option<IntegritySignal> {
        validate_code(&finding.code).ok()?;
        Some(IntegritySignal {
            tenant: self.pin.tenant.clone(),
            identity: identity.clone(),
            source,
            code: finding.code,
            severity: finding.severity,
            observed_at: time.now,
            blob_id,
        })
    }

    /// Runs the compiled-in `EvidenceCheck`s over the report's evidence (evidence from a
    /// provider without one is ignored). A finding whose action is more than `LogOnly` refuses
    /// the session start or extend (`IntegrityFailed`). Returns whether the endpoint
    /// attested: true only when the tenant has enrolled at least one provider the image
    /// can verify and every such provider's evidence was present and passed. An image
    /// without compiled-in checks, or a tenant without enrolled sources, can never attest —
    /// `Hardened` is unreachable there, so hardened blobs fail closed instead of trusting
    /// unverified bytes.
    pub(super) async fn check_evidence(
        &self,
        identity: &WorkloadIdentity,
        report: Option<&EndpointReport>,
        challenge: [u8; 32],
        blob_id: Option<BlobId>,
        time: &TrustedTime,
    ) -> Result<bool, ServiceError> {
        let Some(report) = report else { return Ok(false) };
        let sources = &self.state.get().map(|t| t.state().integrity.sources.clone()).unwrap_or_default();
        let required: std::collections::BTreeSet<&str> =
            self.evidence_checks.iter().map(|c| c.provider()).filter(|p| sources.contains_key(*p)).collect();
        let mut verified = std::collections::BTreeSet::new();
        let mut refused = false;
        for evidence in &report.evidence {
            let Some(check) = self.evidence_checks.iter().find(|c| c.provider() == evidence.provider) else {
                continue;
            };
            let key = sources.get(evidence.provider.as_str());
            match check.check(report, evidence, key, &challenge, time) {
                None => {
                    verified.insert(check.provider());
                }
                Some(finding) => {
                    let source = SignalSource::Enclave { detector: check.provider().into() };
                    if let Some(signal) = self.finding_signal(identity, source, finding, blob_id, time) {
                        if self.raise_and_publish(signal, time).await? != IntegrityAction::LogOnly {
                            refused = true;
                        }
                    }
                }
            }
        }
        if refused {
            return Err(fail(ErrorCode::IntegrityFailed, "endpoint evidence failed an integrity check"));
        }
        Ok(!required.is_empty() && required.is_subset(&verified))
    }

    /// A hardened blob was refused because its endpoint's attestation went silent (the
    /// session was otherwise eligible: its evidence was missing or unverified).
    /// Recorded for every attempt, published and applied when the tenant's policy says so.
    pub(super) async fn note_silent_agent(
        &self,
        identity: &WorkloadIdentity,
        blob_id: Option<BlobId>,
        time: &TrustedTime,
    ) {
        let Some(signal) = self.finding_signal(
            identity,
            SignalSource::Enclave { detector: "tier".into() },
            seal_integrity::Finding { severity: Severity::High, code: "agent-silent".into() },
            blob_id,
            time,
        ) else {
            return;
        };
        if let Err(e) = self.raise_and_publish(signal, time).await {
            tracing::warn!(error = %e, "publishing agent-silent failed");
        }
    }
}

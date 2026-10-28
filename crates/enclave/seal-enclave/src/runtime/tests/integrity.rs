//! The artifact rule's `artifact-mismatch` signal and in-enclave detectors.

use super::*;
use seal_integrity::{Detector, Finding, Observation};
use seal_proto::integrity::{ArtifactHash, IntegrityAction, SignalSource, CODE_ARTIFACT_MISMATCH, SIGNAL_LABEL};
use seal_proto::telemetry::Operation;

fn report(b: u8) -> EndpointReport {
    EndpointReport { artifact: Some(ArtifactHash { name: "executable".into(), sha256: [b; 32] }), evidence: vec![] }
}

#[tokio::test]
async fn an_artifact_mismatch_is_signed_recorded_applied_and_published() {
    let h = Boot::with_state(|s| {
        s.integrity.artifacts.insert(checkout(), [report(1).artifact.unwrap()].into());
        s.integrity.actions.insert(Severity::High, IntegrityAction::Suspend { secs: Some(3600) });
    })
    .start()
    .await
    .map_err(|(e, _)| e)
    .unwrap();
    let blob = h.seal().await.unwrap().blob;
    // The allowed artifact starts a session.
    let good = h.start(CONSUMER, &blob, Some(report(1))).await.unwrap();
    let mut conn = h.connect(&good.token).await;
    assert_eq!(get(&mut conn, "/v1/chat", LOCAL_KEY).await.0, 200);

    // Another artifact: refused, and the signal suspends the caller (ending its live session).
    let refused = h.start(CONSUMER, &blob, Some(report(2))).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::IntegrityFailed);
    assert_eq!(h.ended(&good.info.session_id).await, ErrorCode::IntegrityFailed);
    let published = h.stores.signals.lock().unwrap().clone();
    assert_eq!(published.len(), 1);
    let signal = &published[0];
    assert_eq!(signal.body.code, CODE_ARTIFACT_MISMATCH);
    assert_eq!(signal.body.source, SignalSource::Sdk);
    assert_eq!(signal.body.identity, app_identity(CONSUMER));
    assert_eq!(signal.body.severity, Severity::High);
    // Signed with the tenant's telemetry key.
    let keys = service_keys(&h.world.root_id);
    assert!(seal_crypto::sign::verify_threshold(&[keys.telemetry.public_key()], 1, SIGNAL_LABEL, signal).is_ok());
    let events = h.events();
    assert!(events.iter().any(|e| matches!(
        e,
        TelemetryEvent::Integrity { code, action: IntegrityAction::Suspend { .. }, .. } if code == CODE_ARTIFACT_MISMATCH
    )));
    assert!(matches!(
        events.last().unwrap(),
        TelemetryEvent::Refused { operation: Operation::Session, code: ErrorCode::IntegrityFailed }
    ));
    // Suspended now, even with the allowed artifact.
    let again = h.start(CONSUMER, &blob, Some(report(1))).await.unwrap_err();
    assert_eq!(again.code, ErrorCode::IntegrityFailed);
}

#[tokio::test]
async fn an_artifact_mismatch_at_extend_is_applied_too() {
    let h = Boot::with_state(|s| {
        s.integrity.artifacts.insert(checkout(), [report(1).artifact.unwrap()].into());
    })
    .start()
    .await
    .map_err(|(e, _)| e)
    .unwrap();
    let blob = h.seal().await.unwrap().blob;
    let session = h.start(CONSUMER, &blob, Some(report(1))).await.unwrap();
    let refused = h.extend(CONSUMER, &session.token, Some(report(3))).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::IntegrityFailed);
    // Log only by default: recorded, not published.
    assert!(h.stores.signals.lock().unwrap().is_empty());
    assert!(h.events().iter().any(|e| matches!(
        e,
        TelemetryEvent::Integrity { code, action: IntegrityAction::LogOnly, .. } if code == CODE_ARTIFACT_MISMATCH
    )));
    assert!(matches!(
        h.events().last().unwrap(),
        TelemetryEvent::Refused { operation: Operation::Extend, code: ErrorCode::IntegrityFailed }
    ));
}

/// Flags requests to `/v1/admin` (Medium) and `/v1/exfiltrate` (Critical).
struct PathDetector;
impl Detector for PathDetector {
    fn name(&self) -> &'static str {
        "path"
    }
    fn protocols(&self) -> &[Protocol] {
        &[Protocol::Http]
    }
    fn observe(&self, observation: &Observation<'_>) -> Option<Finding> {
        let content = std::str::from_utf8(observation.content).unwrap();
        if content.contains("/v1/admin") {
            Some(Finding { severity: Severity::Medium, code: "admin-path".into() })
        } else if content.contains("/v1/exfiltrate") {
            Some(Finding { severity: Severity::Critical, code: "exfiltration".into() })
        } else {
            None
        }
    }
}

#[tokio::test]
async fn detector_findings_refuse_or_end_through_the_policy() {
    let mut boot = Boot::with_state(|s| {
        s.integrity.actions.insert(Severity::Medium, IntegrityAction::Deny);
        s.integrity.actions.insert(Severity::Critical, IntegrityAction::Suspend { secs: None });
    });
    boot.detectors = vec![Arc::new(PathDetector)];
    let h = boot.start().await.map_err(|(e, _)| e).unwrap();
    let session = h.sealed_session().await;
    let session_id = session.info.session_id;
    let mut conn = h.connect(&session.token).await;
    assert_eq!(get(&mut conn, "/v1/chat", LOCAL_KEY).await.0, 200);

    // Deny: this request is refused, the connection stays.
    let (status, body) = get(&mut conn, "/v1/admin", LOCAL_KEY).await;
    assert_eq!((status, seal_error(&body)), (403, ErrorCode::IntegrityFailed));
    assert_eq!(get(&mut conn, "/v1/chat", LOCAL_KEY).await.0, 200);
    assert!(h.stores.signals.lock().unwrap().is_empty());

    // Suspend: the session ends on every replica (a published SessionEnd) and the caller is suspended.
    let live = h.live(&session_id)[0].clone();
    let (status, body) = get(&mut conn, "/v1/exfiltrate", LOCAL_KEY).await;
    assert_eq!((status, seal_error(&body)), (403, ErrorCode::IntegrityFailed));
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), live.ended()).await.unwrap(), ErrorCode::IntegrityFailed);
    // The adapter closed the connection.
    tokio::time::timeout(Duration::from_secs(5), conn.served).await.unwrap().unwrap().ok();
    let published = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (signals, ends) = (h.stores.signals.lock().unwrap().len(), h.stores.ends.lock().unwrap().len());
            if signals == 1 && ends == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(published.is_ok());
    let end = h.stores.ends.lock().unwrap()[0].body.clone();
    assert_eq!((end.session_id, end.reason), (session_id, ErrorCode::IntegrityFailed));
    let signal = h.stores.signals.lock().unwrap()[0].body.clone();
    assert_eq!(signal.source, SignalSource::Enclave { detector: "path".into() });
    assert_eq!(signal.blob_id, Some(session.info.blob_id));
    // Upstream never saw the refused requests.
    let paths: Vec<String> = h.seen.lock().unwrap().iter().map(|s| s.path.clone()).collect();
    assert_eq!(paths, ["/v1/chat", "/v1/chat"]);
    let refusals: Vec<_> = h
        .events()
        .into_iter()
        .filter_map(|e| match e {
            TelemetryEvent::Request { completion, .. } => Some(completion.outcome),
            _ => None,
        })
        .collect();
    assert_eq!(
        refusals.iter().filter(|o| **o == seal_proto::telemetry::Outcome::Denied(ErrorCode::IntegrityFailed)).count(),
        2
    );
}

// --- endpoint evidence checks -----------------------------------------------------------

use seal_integrity::EvidenceCheck;
use seal_proto::integrity::EndpointEvidence;
use seal_proto::{PublicKey, TrustedTime};

/// Interprets the evidence bytes as the challenge it must match; findings are High.
/// Unenrolled providers (`key: None`) are ignored, like the host-agent check.
struct ChallengeCheck;

impl EvidenceCheck for ChallengeCheck {
    fn provider(&self) -> &'static str {
        "host-agent"
    }
    fn check(
        &self,
        _report: &EndpointReport,
        evidence: &EndpointEvidence,
        key: Option<&PublicKey>,
        challenge: &[u8; 32],
        _time: &TrustedTime,
    ) -> Option<Finding> {
        if key.is_none() || evidence.bytes == challenge {
            return None;
        }
        Some(Finding { severity: Severity::High, code: "ev-challenge".into() })
    }
}

fn evidence_report(bytes: Vec<u8>) -> EndpointReport {
    EndpointReport {
        artifact: Some(ArtifactHash { name: "executable".into(), sha256: [1; 32] }),
        evidence: vec![EndpointEvidence { provider: "host-agent".into(), bytes }],
    }
}

/// The challenge `start` will bind: the digest of the same request with no report.
fn start_challenge(blob: &str) -> [u8; 32] {
    SessionRequest {
        blob: blob.to_owned(),
        context: ProofContext {
            tenant: acme(),
            purpose: ProofPurpose::Session { request_digest: [0; 32] },
            tls_spki_sha256: [0; 32],
            ticket: ProofTicket { value: [0; 32], expires_at: 0, mac: [0; 32] },
        },
        proof: IdentityProof::AppKey { key_id: key(CONSUMER).key_id(), signature: vec![] },
        min_tier: None,
        endpoint: None,
    }
    .evidence_challenge()
}

#[tokio::test]
async fn evidence_bound_to_the_request_passes_and_replays_are_refused() {
    let mut boot = Boot::with_state(|s| {
        s.integrity.sources.insert("host-agent".into(), PublicKey([7; 32]));
        // Suspend (not Deny) so the finding is live and published, like the artifact test.
        s.integrity.actions.insert(Severity::High, IntegrityAction::Suspend { secs: Some(3600) });
    });
    boot.evidence_checks = vec![Arc::new(ChallengeCheck)];
    let h = boot.start().await.map_err(|(e, _)| e).unwrap();
    let blob = h.seal().await.unwrap().blob;

    // Evidence bound to exactly this request starts the session.
    let challenge = start_challenge(&blob);
    let good = h.start(CONSUMER, &blob, Some(evidence_report(challenge.to_vec()))).await;
    assert!(good.is_ok(), "{:?}", good.err().map(|e| e.detail));

    // Evidence replayed from another request (different blob): finding, refusal, signal out.
    let other = h.seal().await.unwrap().blob;
    let stale = start_challenge(&other);
    let refused = h.start(CONSUMER, &blob, Some(evidence_report(stale.to_vec()))).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::IntegrityFailed);
    let published = h.stores.signals.lock().unwrap().clone();
    let signal = published.last().unwrap();
    assert_eq!(signal.body.code, "ev-challenge");
    assert_eq!(signal.body.source, SignalSource::Enclave { detector: "host-agent".into() });
    assert_eq!(signal.body.severity, Severity::High);
}

#[tokio::test]
async fn evidence_from_an_unenrolled_provider_is_ignored() {
    let mut boot = Boot::with_state(|s| {
        s.integrity.actions.insert(Severity::High, IntegrityAction::Deny);
    });
    boot.evidence_checks = vec![Arc::new(ChallengeCheck)];
    let h = boot.start().await.map_err(|(e, _)| e).unwrap();
    let blob = h.seal().await.unwrap().blob;
    // No key registered for the provider: the check must not fire (fail-open), so hosts
    // running a reporter without the add-on keep working.
    let session = h.start(CONSUMER, &blob, Some(evidence_report(vec![0; 32]))).await;
    assert!(session.is_ok());
    assert!(h.stores.signals.lock().unwrap().is_empty());
}

// --- the hardened tier -----------------------------------------------------------------

use seal_proto::session::ConsumerTier;

/// A hardened blob, a stub-verifying image, an enrolled agent key.
async fn hardened_world() -> (Harness, String) {
    let mut boot = Boot::with_state(|s| {
        s.integrity.sources.insert("host-agent".into(), PublicKey([7; 32]));
    });
    boot.evidence_checks = vec![Arc::new(ChallengeCheck)];
    let h = boot.start().await.map_err(|(e, _)| e).unwrap();
    let sealed = h.seal_with(|p| p.with_min_tier(ConsumerTier::Hardened)).await.unwrap();
    (h, sealed.blob)
}

/// The extend challenge for `token`, as the harness's `extend` will bind it.
fn extend_challenge(token: &Bearer) -> [u8; 32] {
    ExtendRequest {
        token: token.duplicate(),
        endpoint: None,
        context: ProofContext {
            tenant: acme(),
            purpose: ProofPurpose::Extend { request_digest: [0; 32] },
            tls_spki_sha256: [0; 32],
            ticket: ProofTicket { value: [0; 32], expires_at: 0, mac: [0; 32] },
        },
        proof: IdentityProof::AppKey { key_id: key(CONSUMER).key_id(), signature: vec![] },
    }
    .evidence_challenge()
}

#[tokio::test]
async fn hardened_needs_verified_evidence() {
    let (h, blob) = hardened_world().await;

    // Evidence bound to this exact request: Hardened, and the session says so.
    let challenge = start_challenge(&blob);
    let report = evidence_report(challenge.to_vec());
    let session = h.start(CONSUMER, &blob, Some(report)).await.unwrap();
    assert_eq!(session.info.tier, ConsumerTier::Hardened);

    // Evidence replayed from another request: below the floor, and the
    // endpoint's silence is recorded as `agent-silent` (log-only by default).
    let other = h.seal().await.unwrap().blob;
    let stale = start_challenge(&other);
    let report = evidence_report(stale.to_vec());
    let err = h.start(CONSUMER, &blob, Some(report)).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::TierTooLow);
    assert!(h.events().iter().any(|e| matches!(
        e,
        TelemetryEvent::Integrity { code, .. } if code == "agent-silent"
    )));

    // Tunnel but no report at all: same refusal.
    let err = h.start(CONSUMER, &blob, None).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::TierTooLow);
}

#[tokio::test]
async fn a_hardened_blob_stops_at_extend_when_the_agent_goes_silent() {
    let (h, blob) = hardened_world().await;
    let challenge = start_challenge(&blob);
    let report = evidence_report(challenge.to_vec());
    let session = h.start(CONSUMER, &blob, Some(report)).await.unwrap();

    // The agent dies: no report at the next extend, so the tier drops below the floor.
    let err = h.extend(CONSUMER, &session.token, None).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::TierTooLow);

    // The agent is back: the extend binds fresh evidence to the new token and works.
    let challenge = extend_challenge(&session.token);
    let report = evidence_report(challenge.to_vec());
    h.extend(CONSUMER, &session.token, Some(report)).await.unwrap();
}

#[tokio::test]
async fn images_that_cannot_verify_never_attest() {
    // No compiled-in checks: Hardened is unreachable, so a hardened blob fails closed
    // even with evidence bytes present (nothing verified them).
    let h = Boot::with_state(|_| {}).start().await.map_err(|(e, _)| e).unwrap();
    let sealed = h.seal_with(|p| p.with_min_tier(ConsumerTier::Hardened)).await.unwrap();
    let err = h.start(CONSUMER, &sealed.blob, Some(evidence_report(vec![0; 32]))).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::TierTooLow);
    // A base blob is unaffected.
    let base = h.seal().await.unwrap().blob;
    assert!(h.start(CONSUMER, &base, None).await.is_ok());
}

// --- agent findings submitted straight to the replica -----------------------------------

use seal_proto::integrity::IntegritySignal;

/// An external finding as it travels: the sender's fields only — the tenant and source
/// are derived at the replica and still covered by the signature.
fn agent_finding(key: &seal_crypto::sign::SigningKey, severity: Severity) -> SignalRequest {
    let signed = key.sign_into(
        seal_proto::integrity::SIGNAL_LABEL,
        IntegritySignal {
            tenant: acme(),
            identity: app_identity(CONSUMER),
            source: SignalSource::External { source: "host-agent".into() },
            code: "reverse-shell".into(),
            severity,
            observed_at: 1_900_000_000,
            blob_id: None,
        },
    );
    SignalRequest {
        code: signed.body.code,
        severity: signed.body.severity,
        context: None,
        proof: None,
        identity: Some(signed.body.identity),
        observed_at: Some(signed.body.observed_at),
        blob_id: signed.body.blob_id,
        signatures: signed.signatures,
    }
}

#[tokio::test]
async fn agent_findings_apply_at_once_when_the_replica_receives_them() {
    // The tenant enrolled the agent's key; Critical findings suspend.
    let agent_key = seal_crypto::sign::SigningKey::from_seed(&[7; 32]);
    let h = Boot::with_state(|s| {
        s.integrity.sources.insert("host-agent".into(), agent_key.public_key());
        s.integrity.actions.insert(Severity::Critical, IntegrityAction::Suspend { secs: Some(3600) });
    })
    .start()
    .await
    .map_err(|(e, _)| e)
    .unwrap();
    let blob = h.seal().await.unwrap().blob;

    // Sessions work before the finding.
    assert!(h.start(CONSUMER, &blob, None).await.is_ok());

    // The agent's finding arrives at the replica: verified, applied here and now, published.
    h.service.signal(agent_finding(&agent_key, Severity::Critical)).await.unwrap();
    let published = h.stores.signals.lock().unwrap().clone();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].body.code, "reverse-shell");
    assert_eq!(published[0].body.source, SignalSource::External { source: "host-agent".into() });

    // Applied at once: the identity's next start fails without waiting for any reload.
    let err = h.start(CONSUMER, &blob, None).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::IntegrityFailed);

    // A forged finding (a key the tenant never enrolled) is refused: the derived-source
    // lookup finds no enrolled key for its signer.
    let forged = agent_finding(&seal_crypto::sign::SigningKey::from_seed(&[8; 32]), Severity::Critical);
    let err = h.service.signal(forged).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest);
    // Correctly signed but naming another signer id: no enrolled key matches it either.
    let mut wrong_id = agent_finding(&agent_key, Severity::Critical);
    wrong_id.signatures[0].signer = seal_proto::KeyId([9; 32]);
    let err = h.service.signal(wrong_id).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest);
    // Both credentials at once: refused.
    let mut both = agent_finding(&agent_key, Severity::Critical);
    both.proof = Some(IdentityProof::AppKey { key_id: key(CONSUMER).key_id(), signature: vec![] });
    let err = h.service.signal(both).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest);
    // A proof plus an asserted identity: refused — with a proof, identity is derived.
    let mut named = {
        let mut context = h.context(ProofPurpose::Signal { request_digest: [0; 32] }).await;
        let request = SignalRequest {
            code: "edr-low".into(),
            severity: Severity::Low,
            context: Some(context.clone()),
            proof: Some(IdentityProof::AppKey { key_id: key(CONSUMER).key_id(), signature: vec![] }),
            identity: None,
            observed_at: None,
            blob_id: None,
            signatures: Vec::new(),
        };
        context.purpose = request.expected_purpose();
        SignalRequest { context: Some(context.clone()), proof: Some(proof(CONSUMER, &context)), ..request }
    };
    named.identity = Some(app_identity(CONSUMER));
    let err = h.service.signal(named).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest);
    // A log-only finding is recorded but neither published nor applied.
    let logged = agent_finding(&agent_key, Severity::Low);
    h.service.signal(logged).await.unwrap();
    assert_eq!(h.stores.signals.lock().unwrap().len(), 1);
}

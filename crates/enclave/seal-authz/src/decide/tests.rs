use super::*;
use crate::testing::*;
use crate::AuthenticatedCaller;
use seal_proto::api::{ExtendRequest, SealRequest, SessionRequest, SignalRequest};
use seal_proto::freshness::ProofTicket;
use seal_proto::identity::{IdentityProof, ProofContext, ProofPurpose};
use seal_proto::integrity::{ArtifactHash, Clearance, IntegrityAction, IntegritySignal, Severity, SignalSource};
use seal_proto::session::SessionEnd;
use seal_proto::state::{TenantKeyVersions, TenantState, STATE_FRESHNESS_SECS};
use seal_proto::{Bearer, KeyId, PlatformId, ServiceKeyVersion, TenantId, TenantKeyVersion};

const PRODUCER: u8 = 41;
const CONSUMER: u8 = 42;
const STRANGER: u8 = 43;

fn ctx(tenant: TenantId) -> ProofContext {
    ProofContext {
        tenant,
        purpose: ProofPurpose::Seal { request_digest: [0; 32] },
        tls_spki_sha256: [0; 32],
        ticket: ProofTicket { value: [0; 32], expires_at: 0, mac: [0; 32] },
    }
}
fn proof() -> IdentityProof {
    IdentityProof::AppKey { key_id: KeyId([0; 32]), signature: vec![] }
}

/// The app-key caller `n`, authenticated against its own matcher.
fn who(n: u8) -> AuthenticatedCaller {
    let (m, id) = app_key(n);
    caller(id, &[m], None)
}

/// Producers {41}, apps {checkout: {42}, billing: {}}.
fn state(change: impl FnOnce(&mut TenantState)) -> TenantState {
    let mut s = base_state(1);
    s.producers.insert(app_key(PRODUCER).0);
    s.apps.insert(app("checkout"), [app_key(CONSUMER).0].into());
    s.apps.insert(app("billing"), Default::default());
    change(&mut s);
    s
}

fn tenant(change: impl FnOnce(&mut TenantState)) -> VerifiedTenant {
    verified(state(change))
}

fn seal_request(tenant: TenantId, caller: AuthenticatedCaller) -> AuthenticatedRequest<SealRequest> {
    let req = SealRequest {
        service_key_version: ServiceKeyVersion(1),
        hpke_enc: vec![1],
        sealed_payload: vec![2],
        context: ctx(tenant),
        proof: proof(),
    };
    AuthenticatedRequest::new(req, caller)
}

fn session_request(blob: &Blob, caller: AuthenticatedCaller) -> AuthenticatedRequest<SessionRequest> {
    session_request_with(blob, caller, |_| {})
}

fn session_request_with(
    blob: &Blob,
    caller: AuthenticatedCaller,
    change: impl FnOnce(&mut SessionRequest),
) -> AuthenticatedRequest<SessionRequest> {
    let mut req =
        SessionRequest { blob: blob_text(blob), context: ctx(acme()), proof: proof(), min_tier: None, endpoint: None };
    change(&mut req);
    AuthenticatedRequest::new(req, caller)
}

fn producer_id() -> WorkloadIdentity {
    app_key(PRODUCER).1
}

fn code<T>(r: Result<T, AuthzError>) -> ErrorCode {
    match r {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e.code(),
    }
}

fn claims(blob: Blob, caller: &AuthenticatedCaller, app_name: &str) -> SessionClaims {
    SessionClaims {
        tenant: acme(),
        app: app(app_name),
        session_id: [5; 16],
        caller: caller.identity().clone(),
        authentication: caller.scope().clone(),
        blob,
        service_key_version: ServiceKeyVersion(1),
        tier: ConsumerTier::Base,
        platform: PlatformId::Sim,
        issued_at: T,
        expires_at: T + 600,
    }
}

fn extend_request(
    caller: AuthenticatedCaller,
    endpoint: Option<EndpointReport>,
) -> AuthenticatedRequest<ExtendRequest> {
    AuthenticatedRequest::new(
        ExtendRequest { token: Bearer::new("sealtok_x".into()), endpoint, context: ctx(acme()), proof: proof() },
        caller,
    )
}

fn signal_of(identity: WorkloadIdentity, severity: Severity, observed_at: UnixTime) -> IntegritySignal {
    IntegritySignal {
        tenant: acme(),
        identity,
        source: SignalSource::Sdk,
        code: "edr-high".into(),
        severity,
        observed_at,
        blob_id: None,
    }
}

/// Low → deny, High → suspend 60 s, Critical → suspend until cleared.
fn with_actions(s: &mut TenantState) {
    s.integrity.actions.insert(Severity::Low, IntegrityAction::Deny);
    s.integrity.actions.insert(Severity::High, IntegrityAction::Suspend { secs: Some(60) });
    s.integrity.actions.insert(Severity::Critical, IntegrityAction::Suspend { secs: None });
}

fn azure(audience: &str) -> IdentityMatcher {
    IdentityMatcher::Azure {
        entra_tenant: "tid".into(),
        object_id: "oid".into(),
        audience: audience.into(),
        hosted: None,
    }
}
fn azure_id() -> WorkloadIdentity {
    WorkloadIdentity::Azure { entra_tenant: "tid".into(), object_id: "oid".into() }
}

fn report(b: u8) -> EndpointReport {
    EndpointReport { artifact: Some(ArtifactHash { name: "image".into(), sha256: [b; 32] }), evidence: vec![] }
}

// ---- seal ----

#[test]
fn seal_needs_a_current_producer_grant() {
    let t = tenant(|_| {});
    let auth = TenantAuthorizer::new(&t);
    let now = at(T + 1);
    let r = seal_request(acme(), who(PRODUCER));
    assert!(auth.seal(&r, &now).is_ok());
    // A consumer grant implies nothing about sealing.
    assert_eq!(code(auth.seal(&seal_request(acme(), who(CONSUMER)), &now)), ErrorCode::NotAllowed);
    assert_eq!(code(auth.seal(&seal_request(acme(), who(STRANGER)), &now)), ErrorCode::NotAllowed);
    // Another tenant's request.
    assert_eq!(code(auth.seal(&seal_request(other_tenant(), who(PRODUCER)), &now)), ErrorCode::NotAllowed);
    // Authentication expiry, against the latest end of the interval.
    let (m, id) = app_key(PRODUCER);
    let expiring = seal_request(acme(), caller(id.clone(), std::slice::from_ref(&m), Some(T + 10)));
    assert!(auth.seal(&expiring, &at(T + 9)).is_ok());
    assert_eq!(code(auth.seal(&expiring, &at(T + 10))), ErrorCode::NotAllowed);
    assert_eq!(code(auth.seal(&expiring, &TrustedTime { now: T + 8, radius: 2 })), ErrorCode::NotAllowed);
    // A matched grant that does not match the identity does not count.
    let confused = seal_request(acme(), caller(app_key(STRANGER).1, &[m], None));
    assert_eq!(code(auth.seal(&confused, &now)), ErrorCode::NotAllowed);

    // Removed from producers: refused.
    let removed = tenant(|s| s.producers.clear());
    assert_eq!(code(TenantAuthorizer::new(&removed).seal(&r, &now)), ErrorCode::NotAllowed);
}

#[test]
fn seal_refuses_a_suspended_producer() {
    let mut fx = Fixture::new(31);
    let t = fx.verified(state(with_actions), &[signal_of(producer_id(), Severity::Critical, T)], &[]);
    let r = seal_request(acme(), who(PRODUCER));
    assert_eq!(code(TenantAuthorizer::new(&t).seal(&r, &at(T + 1))), ErrorCode::IntegrityFailed);
}

#[test]
fn nothing_is_decided_on_a_state_past_its_freshness() {
    let t = tenant(|_| {});
    let auth = TenantAuthorizer::new(&t);
    let r = seal_request(acme(), who(PRODUCER));
    let last = T + STATE_FRESHNESS_SECS - 1;
    assert!(auth.seal(&r, &at(last)).is_ok());
    assert!(matches!(auth.seal(&r, &at(last + 1)), Err(AuthzError::Stale)));
    assert_eq!(code(auth.seal(&r, &TrustedTime { now: last, radius: 1 })), ErrorCode::Unavailable);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let opened = open(&b);
    let s = session_request(&b, who(CONSUMER));
    assert!(matches!(auth.session(&s, &opened, ConsumerTier::Base, &at(last + 1)), Err(AuthzError::Stale)));
    let c = claims(b, &who(CONSUMER), "checkout");
    assert!(matches!(auth.recheck(&c, &at(last + 1)), Err(AuthzError::Stale)));
}

// ---- session ----

#[test]
fn a_granted_consumer_starts_a_session() {
    let t = tenant(|_| {});
    let auth = TenantAuthorizer::new(&t);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let opened = open(&b);
    let r = session_request(&b, who(CONSUMER));
    let permit = auth.session(&r, &opened, ConsumerTier::Base, &at(T + 1)).unwrap();
    assert_eq!(permit.decision(), &SessionDecision { app: app("checkout"), tier: ConsumerTier::Base, reseal: false });
    assert_eq!(permit.opened().blob(), &b);
    assert_eq!(permit.request().caller().identity(), &app_key(CONSUMER).1);
    // Producers hold no consumer grant.
    let p = session_request(&b, who(PRODUCER));
    assert_eq!(code(auth.session(&p, &opened, ConsumerTier::Base, &at(T + 1))), ErrorCode::NotAllowed);
    let s = session_request(&b, who(STRANGER));
    assert_eq!(code(auth.session(&s, &opened, ConsumerTier::Base, &at(T + 1))), ErrorCode::NotAllowed);
}

#[test]
fn session_requires_the_exact_opened_blob() {
    let t = tenant(|_| {});
    let auth = TenantAuthorizer::new(&t);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let other = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let r = session_request(&b, who(CONSUMER));
    assert_eq!(code(auth.session(&r, &open(&other), ConsumerTier::Base, &at(T + 1))), ErrorCode::BadRequest);
    let garbage = session_request_with(&b, who(CONSUMER), |r| r.blob = "seal1.nope".into());
    assert_eq!(code(auth.session(&garbage, &open(&b), ConsumerTier::Base, &at(T + 1))), ErrorCode::BadRequest);
}

#[test]
fn session_refuses_a_blob_of_another_root_chain() {
    let t = tenant(|_| {});
    let other_root = Fixture::new(32).root_id();
    assert_ne!(&other_root, t.root_id());
    let b = blob(&other_root, 1, producer_id(), &["checkout"], None);
    let r = session_request(&b, who(CONSUMER));
    assert_eq!(
        code(TenantAuthorizer::new(&t).session(&r, &open(&b), ConsumerTier::Base, &at(T + 1))),
        ErrorCode::NotAllowed
    );
}

#[test]
fn session_needs_the_producer_still_allowed() {
    let t = tenant(|s| s.producers.clear());
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let r = session_request(&b, who(CONSUMER));
    assert_eq!(
        code(TenantAuthorizer::new(&t).session(&r, &open(&b), ConsumerTier::Base, &at(T + 1))),
        ErrorCode::NotAllowed
    );
}

#[test]
fn session_on_a_blob_of_a_suspended_producer_still_works() {
    let mut fx = Fixture::new(31);
    let t = fx.verified(state(with_actions), &[signal_of(producer_id(), Severity::Critical, T)], &[]);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let r = session_request(&b, who(CONSUMER));
    assert!(TenantAuthorizer::new(&t).session(&r, &open(&b), ConsumerTier::Base, &at(T + 1)).is_ok());
}

#[test]
fn session_refuses_an_expired_blob() {
    let t = tenant(|_| {});
    let auth = TenantAuthorizer::new(&t);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], Some(T + 100));
    let (r, opened) = (session_request(&b, who(CONSUMER)), open(&b));
    assert!(auth.session(&r, &opened, ConsumerTier::Base, &at(T + 99)).is_ok());
    assert_eq!(code(auth.session(&r, &opened, ConsumerTier::Base, &at(T + 100))), ErrorCode::Expired);
    assert_eq!(
        code(auth.session(&r, &opened, ConsumerTier::Base, &TrustedTime { now: T + 95, radius: 5 })),
        ErrorCode::Expired
    );
}

#[test]
fn tenant_key_version_window_and_reseal() {
    let versions = |current, oldest| {
        move |s: &mut TenantState| {
            s.tenant_key_versions =
                TenantKeyVersions { current: TenantKeyVersion(current), oldest_accepted: TenantKeyVersion(oldest) }
        }
    };
    let decide = |t: &VerifiedTenant, v: u32| {
        let b = blob(t.root_id(), v, producer_id(), &["checkout"], None);
        let r = session_request(&b, who(CONSUMER));
        TenantAuthorizer::new(t).session(&r, &open(&b), ConsumerTier::Base, &at(T + 1)).map(|p| p.decision().reseal)
    };
    let t = tenant(versions(2, 1));
    assert!(!decide(&t, 2).unwrap());
    // Decrypt-only: works and is resealed.
    assert!(decide(&t, 1).unwrap());
    // Newer than this snapshot knows: retryable.
    assert!(matches!(decide(&t, 3), Err(AuthzError::Stale)));
    // Retired.
    let t = tenant(versions(2, 2));
    assert_eq!(code(decide(&t, 1)), ErrorCode::Expired);
}

#[test]
fn session_grant_is_the_original_matchers_intersected_with_current_grants() {
    let b_apps = ["checkout"];
    // The caller authenticated against the Azure entry for audience `api://a`.
    let caller_a = caller(azure_id(), &[azure("api://a")], Some(T + 1000));
    let decide = |grants: Vec<IdentityMatcher>, c: &AuthenticatedCaller, time: TrustedTime| {
        let t = tenant(|s| {
            s.apps.insert(app("checkout"), grants.into_iter().collect());
        });
        let b = blob(t.root_id(), 1, producer_id(), &b_apps, None);
        let r = session_request(&b, c.clone());
        TenantAuthorizer::new(&t).session(&r, &open(&b), ConsumerTier::Base, &time).map(|p| p.decision().app.clone())
    };
    assert_eq!(decide(vec![azure("api://a")], &caller_a, at(T + 1)).unwrap(), app("checkout"));
    // Same identity, but the grant now names another audience: the original audience is kept.
    assert_eq!(code(decide(vec![azure("api://b")], &caller_a, at(T + 1))), ErrorCode::NotAllowed);
    // Authentication expiry caps it.
    assert_eq!(code(decide(vec![azure("api://a")], &caller_a, at(T + 1000))), ErrorCode::NotAllowed);
    // An app grant the blob does not list does not count.
    let t = tenant(|_| {});
    let b = blob(t.root_id(), 1, producer_id(), &["billing"], None);
    let r = session_request(&b, who(CONSUMER));
    assert_eq!(
        code(TenantAuthorizer::new(&t).session(&r, &open(&b), ConsumerTier::Base, &at(T + 1))),
        ErrorCode::NotAllowed
    );
}

#[test]
fn session_refuses_a_suspended_caller() {
    let mut fx = Fixture::new(31);
    let t = fx.verified(state(with_actions), &[signal_of(app_key(CONSUMER).1, Severity::High, T)], &[]);
    let auth = TenantAuthorizer::new(&t);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let (r, opened) = (session_request(&b, who(CONSUMER)), open(&b));
    assert_eq!(code(auth.session(&r, &opened, ConsumerTier::Base, &at(T + 59))), ErrorCode::IntegrityFailed);
    assert!(auth.session(&r, &opened, ConsumerTier::Base, &at(T + 60)).is_ok());
}

#[test]
fn artifact_rule_produces_an_artifact_mismatch_signal() {
    let t = tenant(|s| {
        s.integrity.artifacts.insert(app("checkout"), [report(1).artifact.unwrap()].into());
    });
    let auth = TenantAuthorizer::new(&t);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let opened = open(&b);
    let good = session_request_with(&b, who(CONSUMER), |r| r.endpoint = Some(report(1)));
    assert!(auth.session(&good, &opened, ConsumerTier::Base, &at(T + 1)).is_ok());
    for endpoint in [None, Some(report(2)), Some(EndpointReport::default())] {
        let bad = session_request_with(&b, who(CONSUMER), |r| r.endpoint = endpoint);
        let err = auth.session(&bad, &opened, ConsumerTier::Base, &at(T + 7)).err().unwrap();
        assert_eq!(err.code(), ErrorCode::IntegrityFailed);
        let AuthzError::ArtifactMismatch(signal) = err else { panic!("expected the artifact rule") };
        assert_eq!(
            *signal,
            IntegritySignal {
                tenant: acme(),
                identity: app_key(CONSUMER).1,
                source: SignalSource::Sdk,
                code: "artifact-mismatch".into(),
                severity: Severity::High,
                observed_at: T + 7,
                blob_id: Some(b.header.blob_id),
            }
        );
    }
}

#[test]
fn artifact_rule_picks_an_app_whose_rule_passes() {
    let t = tenant(|s| {
        s.integrity.artifacts.insert(app("billing"), [report(1).artifact.unwrap()].into());
        s.apps.insert(app("billing"), [app_key(CONSUMER).0].into());
        s.apps.insert(app("zeta"), [app_key(CONSUMER).0].into());
    });
    let auth = TenantAuthorizer::new(&t);
    let b = blob(t.root_id(), 1, producer_id(), &["billing", "zeta"], None);
    let opened = open(&b);
    let with = |report| session_request_with(&b, who(CONSUMER), |r| r.endpoint = report);
    let app_of = |r: &AuthenticatedRequest<SessionRequest>| {
        auth.session(r, &opened, ConsumerTier::Base, &at(T + 1)).unwrap().decision().app.clone()
    };
    assert_eq!(app_of(&with(Some(report(1)))), app("billing"));
    assert_eq!(app_of(&with(None)), app("zeta"));
}

#[test]
fn tier() {
    let t = tenant(|_| {});
    let auth = TenantAuthorizer::new(&t);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let opened = open(&b);
    // The caller's own floor: fail fast below it.
    let r = session_request_with(&b, who(CONSUMER), |r| r.min_tier = Some(ConsumerTier::Hardened));
    assert_eq!(code(auth.session(&r, &opened, ConsumerTier::Base, &at(T + 1))), ErrorCode::TierTooLow);
    assert_eq!(
        auth.session(&r, &opened, ConsumerTier::Hardened, &at(T + 1)).unwrap().decision().tier,
        ConsumerTier::Hardened
    );
}

#[test]
fn the_sealed_policy_floor_outranks_everyone() {
    let t = tenant(|_| {});
    let auth = TenantAuthorizer::new(&t);
    let hardened = hardened_blob(t.root_id(), 1, producer_id(), &["checkout"], ConsumerTier::Hardened);
    let opened = open(&hardened);
    let r = session_request_with(&hardened, who(CONSUMER), |_| {});
    // Below the floor, whatever the caller asks for.
    assert_eq!(code(auth.session(&r, &opened, ConsumerTier::Base, &at(T + 1))), ErrorCode::TierTooLow);
    // At the floor.
    assert!(auth.session(&r, &opened, ConsumerTier::Hardened, &at(T + 1)).is_ok());
    // A base blob never refuses.
    let base = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let opened = open(&base);
    let r = session_request_with(&base, who(CONSUMER), |_| {});
    assert!(auth.session(&r, &opened, ConsumerTier::Base, &at(T + 1)).is_ok());
}

// ---- extend and recheck ----

#[test]
fn extend_needs_the_same_caller_and_a_fresh_grant() {
    let t = tenant(|_| {});
    let auth = TenantAuthorizer::new(&t);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let current = claims(b, &who(CONSUMER), "checkout");
    let (m, id) = app_key(CONSUMER);
    let fresh = caller(id.clone(), std::slice::from_ref(&m), Some(T + 500));
    let r = extend_request(fresh.clone(), None);
    let permit = auth.extend(&r, &current, ConsumerTier::Base, &at(T + 300)).unwrap();
    assert_eq!(permit.scope(), fresh.scope());
    assert_eq!(permit.current().session_id, current.session_id);
    // Another caller.
    assert_eq!(
        code(auth.extend(&extend_request(who(STRANGER), None), &current, ConsumerTier::Base, &at(T + 300))),
        ErrorCode::NotAllowed
    );
    // The same identity, but the new proof matched no current grant (only the old claims did).
    let unmatched = caller(id, &[app_key(STRANGER).0], None);
    assert_eq!(
        code(auth.extend(&extend_request(unmatched, None), &current, ConsumerTier::Base, &at(T + 300))),
        ErrorCode::NotAllowed
    );
    // The new proof's own expiry.
    assert_eq!(
        code(auth.extend(&extend_request(fresh.clone(), None), &current, ConsumerTier::Base, &at(T + 500))),
        ErrorCode::NotAllowed
    );
    // The current token expired.
    assert_eq!(
        code(auth.extend(&extend_request(who(CONSUMER), None), &current, ConsumerTier::Base, &at(T + 600))),
        ErrorCode::SessionExpired
    );
}

#[test]
fn extend_refuses_an_ended_session() {
    for reason in [ErrorCode::SessionEnded, ErrorCode::IntegrityFailed] {
        let end = SessionEnd { tenant: acme(), session_id: [5; 16], reason, ended_at: T + 10 };
        let t = Fixture::new(31).verified(state(|_| {}), &[], &[end]);
        let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
        let current = claims(b, &who(CONSUMER), "checkout");
        let r = extend_request(who(CONSUMER), None);
        assert_eq!(
            code(TenantAuthorizer::new(&t).extend(&r, &current, ConsumerTier::Base, &at(T + 20))),
            ErrorCode::SessionEnded
        );
    }
}

#[test]
fn extend_rechecks_producer_blob_suspension_and_endpoint() {
    let current_for = |t: &VerifiedTenant, v: u32, expires: Option<UnixTime>| {
        claims(blob(t.root_id(), v, producer_id(), &["checkout"], expires), &who(CONSUMER), "checkout")
    };
    let r = extend_request(who(CONSUMER), None);
    let now = at(T + 300);

    let t = tenant(|s| s.producers.clear());
    assert_eq!(
        code(TenantAuthorizer::new(&t).extend(&r, &current_for(&t, 1, None), ConsumerTier::Base, &now)),
        ErrorCode::NotAllowed
    );

    let t = tenant(|_| {});
    assert_eq!(
        code(TenantAuthorizer::new(&t).extend(&r, &current_for(&t, 1, Some(T + 200)), ConsumerTier::Base, &now)),
        ErrorCode::Expired
    );

    let t = tenant(|s| {
        s.tenant_key_versions = TenantKeyVersions { current: TenantKeyVersion(3), oldest_accepted: TenantKeyVersion(2) }
    });
    assert_eq!(
        code(TenantAuthorizer::new(&t).extend(&r, &current_for(&t, 1, None), ConsumerTier::Base, &now)),
        ErrorCode::Expired
    );

    let t =
        Fixture::new(31).verified(state(with_actions), &[signal_of(app_key(CONSUMER).1, Severity::Critical, T)], &[]);
    assert_eq!(
        code(TenantAuthorizer::new(&t).extend(&r, &current_for(&t, 1, None), ConsumerTier::Base, &now)),
        ErrorCode::IntegrityFailed
    );

    let t = tenant(|s| {
        s.integrity.artifacts.insert(app("checkout"), [report(1).artifact.unwrap()].into());
    });
    let auth = TenantAuthorizer::new(&t);
    let current = current_for(&t, 1, None);
    let err =
        auth.extend(&extend_request(who(CONSUMER), Some(report(2))), &current, ConsumerTier::Base, &now).err().unwrap();
    assert!(
        matches!(&err, AuthzError::ArtifactMismatch(s) if s.identity == app_key(CONSUMER).1 && s.code == "artifact-mismatch")
    );
    assert!(auth.extend(&extend_request(who(CONSUMER), Some(report(1))), &current, ConsumerTier::Base, &now).is_ok());
}

#[test]
fn recheck_uses_the_persisted_scope() {
    let t = tenant(|s| {
        s.apps.insert(app("checkout"), [azure("api://a")].into());
    });
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let c = claims(b.clone(), &caller(azure_id(), &[azure("api://a")], Some(T + 400)), "checkout");
    let auth = TenantAuthorizer::new(&t);
    auth.recheck(&c, &at(T + 1)).unwrap();
    // The authentication's own expiry.
    assert_eq!(code(auth.recheck(&c, &at(T + 400))), ErrorCode::NotAllowed);
    // The admin changes the entry's audience: the session, authenticated for `api://a`, ends.
    let changed = tenant(|s| {
        s.apps.insert(app("checkout"), [azure("api://b")].into());
    });
    let c = claims(
        blob(changed.root_id(), 1, producer_id(), &["checkout"], None),
        &caller(azure_id(), &[azure("api://a")], None),
        "checkout",
    );
    assert_eq!(code(TenantAuthorizer::new(&changed).recheck(&c, &at(T + 1))), ErrorCode::NotAllowed);
    // Grant removed.
    let removed = tenant(|s| {
        s.apps.remove(&app("checkout"));
    });
    let c = claims(blob(removed.root_id(), 1, producer_id(), &["checkout"], None), &who(CONSUMER), "checkout");
    assert_eq!(code(TenantAuthorizer::new(&removed).recheck(&c, &at(T + 1))), ErrorCode::NotAllowed);
    // Token expiry.
    let t = tenant(|_| {});
    let c = claims(blob(t.root_id(), 1, producer_id(), &["checkout"], None), &who(CONSUMER), "checkout");
    assert_eq!(code(TenantAuthorizer::new(&t).recheck(&c, &at(T + 600))), ErrorCode::SessionExpired);
}

#[test]
fn recheck_ends_sessions_with_the_end_reason_and_on_state_changes() {
    for reason in [ErrorCode::SessionEnded, ErrorCode::IntegrityFailed] {
        let end = SessionEnd { tenant: acme(), session_id: [5; 16], reason, ended_at: T + 10 };
        let t = Fixture::new(31).verified(state(|_| {}), &[], &[end]);
        let c = claims(blob(t.root_id(), 1, producer_id(), &["checkout"], None), &who(CONSUMER), "checkout");
        assert_eq!(code(TenantAuthorizer::new(&t).recheck(&c, &at(T + 20))), reason);
        // Another session is unaffected.
        let mut other = claims(blob(t.root_id(), 1, producer_id(), &["checkout"], None), &who(CONSUMER), "checkout");
        other.session_id = [6; 16];
        TenantAuthorizer::new(&t).recheck(&other, &at(T + 20)).unwrap();
    }
    let t = tenant(|s| s.producers.clear());
    let c = claims(blob(t.root_id(), 1, producer_id(), &["checkout"], None), &who(CONSUMER), "checkout");
    assert_eq!(code(TenantAuthorizer::new(&t).recheck(&c, &at(T + 1))), ErrorCode::NotAllowed);
    let t = tenant(|_| {});
    let c = claims(blob(t.root_id(), 1, producer_id(), &["checkout"], Some(T + 5)), &who(CONSUMER), "checkout");
    assert_eq!(code(TenantAuthorizer::new(&t).recheck(&c, &at(T + 5))), ErrorCode::Expired);
    let t =
        Fixture::new(31).verified(state(with_actions), &[signal_of(app_key(CONSUMER).1, Severity::High, T + 100)], &[]);
    let c = claims(blob(t.root_id(), 1, producer_id(), &["checkout"], None), &who(CONSUMER), "checkout");
    let auth = TenantAuthorizer::new(&t);
    assert_eq!(code(auth.recheck(&c, &at(T + 120))), ErrorCode::IntegrityFailed);
    let mut foreign = claims(blob(t.root_id(), 1, producer_id(), &["checkout"], None), &who(CONSUMER), "checkout");
    foreign.tenant = other_tenant();
    assert_eq!(code(auth.recheck(&foreign, &at(T + 1))), ErrorCode::NotAllowed);
}

// ---- suspensions ----

#[test]
fn suspension_timing_uses_the_earliest_time() {
    let id = app_key(CONSUMER).1;
    let t = Fixture::new(31).verified(state(with_actions), &[signal_of(id.clone(), Severity::High, T)], &[]);
    let auth = TenantAuthorizer::new(&t);
    let suspended = Some(Suspension { code: "edr-high".into(), until: Some(T + 60) });
    assert_eq!(auth.suspension(&id, &at(T)), suspended);
    assert_eq!(auth.suspension(&id, &at(T + 59)), suspended);
    assert_eq!(auth.suspension(&id, &at(T + 60)), None);
    // Clock uncertainty never ends a suspension early.
    assert_eq!(auth.suspension(&id, &TrustedTime { now: T + 65, radius: 10 }), suspended);
    assert_eq!(auth.suspension(&id, &TrustedTime { now: T + 70, radius: 10 }), None);
    // Only that identity.
    assert_eq!(auth.suspension(&app_key(STRANGER).1, &at(T)), None);
}

#[test]
fn suspension_needs_a_suspend_action_and_no_clearance() {
    let id = app_key(CONSUMER).1;
    let signals = [signal_of(id.clone(), Severity::Low, T), signal_of(id.clone(), Severity::Medium, T)];
    // Low maps to Deny, Medium to Deny (the highest entry at or below it): no suspension.
    let t = Fixture::new(31).verified(state(with_actions), &signals, &[]);
    assert_eq!(TenantAuthorizer::new(&t).suspension(&id, &at(T + 1)), None);
    // No actions at all: log only.
    let t = Fixture::new(31).verified(state(|_| {}), &[signal_of(id.clone(), Severity::Critical, T)], &[]);
    assert_eq!(TenantAuthorizer::new(&t).suspension(&id, &at(T + 1)), None);
    // Critical lasts until cleared, and wins over a timed one.
    let both = [signal_of(id.clone(), Severity::High, T), signal_of(id.clone(), Severity::Critical, T + 1)];
    let t = Fixture::new(31).verified(state(with_actions), &both, &[]);
    assert_eq!(
        TenantAuthorizer::new(&t).suspension(&id, &at(T + 10)),
        Some(Suspension { code: "edr-high".into(), until: None })
    );
    // A clearance covering both lifts it; a later signal suspends again.
    let cleared = |s: &mut TenantState| {
        with_actions(s);
        s.integrity.cleared.insert(Clearance { identity: id.clone(), before: T + 1 });
    };
    let t = Fixture::new(31).verified(state(cleared), &both, &[]);
    assert_eq!(TenantAuthorizer::new(&t).suspension(&id, &at(T + 10)), None);
    let later = [signal_of(id.clone(), Severity::Critical, T + 2)];
    let t = Fixture::new(31).verified(state(cleared), &later, &[]);
    assert!(TenantAuthorizer::new(&t).suspension(&id, &at(T + 10)).is_some());
}

// ---- signal ----

#[test]
fn signal_names_the_authenticated_caller() {
    let t = tenant(|_| {});
    let auth = TenantAuthorizer::new(&t);
    let req = |c: AuthenticatedCaller, code: &str| {
        AuthenticatedRequest::new(
            SignalRequest {
                code: code.into(),
                severity: Severity::High,
                context: Some(ctx(acme())),
                proof: Some(proof()),
                identity: None,
                observed_at: None,
                blob_id: None,
                signatures: Vec::new(),
            },
            c,
        )
    };
    for n in [CONSUMER, PRODUCER] {
        let r = req(who(n), "edr-high");
        let permit = auth.signal(&r, &at(T + 3)).unwrap();
        assert_eq!(
            permit.signal(),
            &IntegritySignal {
                tenant: acme(),
                identity: app_key(n).1,
                source: SignalSource::Sdk,
                code: "edr-high".into(),
                severity: Severity::High,
                observed_at: T + 3,
                blob_id: None,
            }
        );
    }
    assert_eq!(code(auth.signal(&req(who(STRANGER), "edr-high"), &at(T + 3))), ErrorCode::NotAllowed);
    assert_eq!(code(auth.signal(&req(who(CONSUMER), "Not A Code"), &at(T + 3))), ErrorCode::BadRequest);
    let foreign = AuthenticatedRequest::new(
        SignalRequest {
            code: "x".into(),
            severity: Severity::Low,
            context: Some(ctx(other_tenant())),
            proof: Some(proof()),
            identity: None,
            observed_at: None,
            blob_id: None,
            signatures: Vec::new(),
        },
        who(CONSUMER),
    );
    assert_eq!(code(auth.signal(&foreign, &at(T + 3))), ErrorCode::NotAllowed);
}

// ---- networks ----

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().unwrap()
}

/// checkout may start sessions only from 203.0.113.0/24.
fn with_networks(s: &mut TenantState) {
    s.app_networks.insert(app("checkout"), ["203.0.113.0/24".parse().unwrap()].into());
}

#[test]
fn a_network_rule_admits_its_networks_only() {
    let t = tenant(with_networks);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let (r, opened) = (session_request(&b, who(CONSUMER)), open(&b));
    let from = |source: Option<&str>| {
        TenantAuthorizer::new(&t)
            .with_source(source.map(ip))
            .session(&r, &opened, ConsumerTier::Base, &at(T + 1))
            .map(|_| ())
    };
    assert!(from(Some("203.0.113.9")).is_ok());
    assert!(from(Some("::ffff:203.0.113.9")).is_ok(), "an IPv4-mapped peer is its IPv4 address");
    assert_eq!(code(from(Some("198.51.100.1"))), ErrorCode::NotAllowed);
    assert_eq!(code(from(None)), ErrorCode::NotAllowed, "an unknown address is in no network");
}

#[test]
fn apps_without_a_rule_and_calls_without_a_source_are_not_checked() {
    let t = tenant(|_| {});
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let (r, opened) = (session_request(&b, who(CONSUMER)), open(&b));
    let auth = TenantAuthorizer::new(&t).with_source(None);
    assert!(auth.session(&r, &opened, ConsumerTier::Base, &at(T + 1)).is_ok(), "no rule: any address, even unknown");
    let ruled = tenant(with_networks);
    let c = claims(b.clone(), &who(CONSUMER), "checkout");
    assert!(
        TenantAuthorizer::new(&ruled).recheck(&c, &at(T + 1)).is_ok(),
        "a background recheck has no source to check"
    );
    assert_eq!(
        code(TenantAuthorizer::new(&ruled).with_source(Some(ip("198.51.100.1"))).recheck(&c, &at(T + 1))),
        ErrorCode::NotAllowed,
        "a connection's recheck does"
    );
}

#[test]
fn an_empty_rule_admits_nobody() {
    let t = tenant(|s| {
        s.app_networks.insert(app("checkout"), Default::default());
    });
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let (r, opened) = (session_request(&b, who(CONSUMER)), open(&b));
    let auth = TenantAuthorizer::new(&t).with_source(Some(ip("203.0.113.9")));
    assert_eq!(code(auth.session(&r, &opened, ConsumerTier::Base, &at(T + 1))), ErrorCode::NotAllowed);
}

#[test]
fn extend_checks_the_network_rule_again() {
    let t = tenant(with_networks);
    let b = blob(t.root_id(), 1, producer_id(), &["checkout"], None);
    let current = claims(b, &who(CONSUMER), "checkout");
    let r = extend_request(who(CONSUMER), None);
    let from = |s: &str| {
        TenantAuthorizer::new(&t)
            .with_source(Some(ip(s)))
            .extend(&r, &current, ConsumerTier::Base, &at(T + 300))
            .map(|_| ())
    };
    assert!(from("203.0.113.200").is_ok());
    assert_eq!(code(from("192.0.2.1")), ErrorCode::NotAllowed);
}

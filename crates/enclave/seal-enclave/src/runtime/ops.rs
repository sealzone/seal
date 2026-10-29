//! The enclave API operations. Each reads the trusted clock, takes the fresh tenant snapshot
//! (failing closed), checks the deployment still serves it (`Runtime::serving`), authenticates
//! the caller (all but sealing, which is open), counts as activity for the idle exit from then
//! on, and acts only through its `seal-authz` permit. Every success and every refusal is one
//! telemetry entry.

use seal_proto::telemetry::RefusalContext;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use seal_authz::{AuthzError, SealPermit, SessionPermit, TenantAuthorizer};
use seal_crypto::blob::{BlobSealer, OpenedBlob};
use seal_proto::api::{
    AttestationChallenge, AttestationResponse, ChallengedAttestation, EndRequest, ExtendRequest, ExtendResponse,
    IngestContext, SealPayload, SealRequest, SealResponse, SessionRequest, SessionResponse, SignalRequest,
    ATTESTATION_CHALLENGE_LABEL,
};
use seal_proto::blob::Blob;
use seal_proto::freshness::{ProofTicket, ATTESTATION_MAX_AGE_SECS};
use seal_proto::identity::WorkloadIdentity;
use seal_proto::release::TenantWrapKey;
use seal_proto::session::{
    ConsumerTier, SessionClaims, SessionEnd, SessionInfo, SignedSessionEnd, SESSION_END_LABEL, SESSION_TOKEN_SECS,
};
use seal_proto::state::TenantState;
use seal_proto::telemetry::{Operation, TelemetryEvent};
use seal_proto::{codec, ErrorCode, PlatformId, TrustedTime};

use super::state::Local;
use super::{fail, lock, random, rng, Runtime};
use crate::ServiceError;

/// A refused operation: what the caller gets, and who it was once authenticated.
pub(super) struct Refusal {
    error: ServiceError,
    identity: Option<Box<WorkloadIdentity>>,
}

impl From<ServiceError> for Refusal {
    fn from(error: ServiceError) -> Self {
        Self { error, identity: None }
    }
}

impl From<AuthzError> for Refusal {
    fn from(error: AuthzError) -> Self {
        ServiceError::from(error).into()
    }
}

/// Attributes a failure to the authenticated caller.
trait By<T> {
    fn by(self, identity: &WorkloadIdentity) -> Result<T, Refusal>;
}

impl<T, E: Into<ServiceError>> By<T> for Result<T, E> {
    fn by(self, identity: &WorkloadIdentity) -> Result<T, Refusal> {
        self.map_err(|e| Refusal { error: e.into(), identity: Some(Box::new(identity.clone())) })
    }
}

/// The tier this request earned: Hardened with verified endpoint evidence; Base otherwise.
fn offered_tier(attested: bool) -> ConsumerTier {
    if attested {
        ConsumerTier::Hardened
    } else {
        ConsumerTier::Base
    }
}

impl Runtime {
    /// Records a refusal as `Refused { operation, code, context }` and hands back the error.
    fn refused<T>(&self, operation: Operation, result: Result<T, Refusal>) -> Result<T, ServiceError> {
        result.map_err(|r| {
            let event =
                TelemetryEvent::Refused { operation, code: r.error.code, context: r.error.context.as_deref().cloned() };
            self.record(r.identity.map(|i| *i), event);
            r.error
        })
    }

    /// A session or extend decision's refusal for `identity` on `blob`. An `artifact-mismatch`
    /// is signed, recorded and applied (and published when it suspends) before the caller hears
    /// `IntegrityFailed`; a hardened floor missed for lack of attestation (`attested` false)
    /// means the endpoint went silent, which is noted first (`note_silent_agent`).
    async fn decision_refused(
        &self,
        error: AuthzError,
        attested: bool,
        blob: &Blob,
        identity: &WorkloadIdentity,
        time: &TrustedTime,
    ) -> ServiceError {
        if error.code() == ErrorCode::TierTooLow && !attested && blob.policy.min_tier() == Some(ConsumerTier::Hardened)
        {
            self.note_silent_agent(identity, Some(blob.header.blob_id), time).await;
        }
        match error {
            AuthzError::ArtifactMismatch(signal) => {
                if let Err(e) = self.raise_and_publish(*signal, time).await {
                    tracing::warn!(error = %e, "publishing an artifact-mismatch signal failed");
                }
                fail(ErrorCode::IntegrityFailed, "the endpoint report fails the app's artifact rule")
                    .with(RefusalContext::ArtifactMismatch)
            }
            error => error.into(),
        }
    }

    pub(crate) fn attestation(&self) -> Result<AttestationResponse, ServiceError> {
        self.fresh(&self.attestation)
    }

    /// The latest evidence over the challenge key, and its signature over `nonce` and the
    /// exporter of the connection that asked (`ChallengedAttestation`). Under the same age rule
    /// as `attestation`.
    pub(crate) fn challenged_attestation(
        &self,
        nonce: [u8; 32],
        tls_exporter: [u8; 32],
    ) -> Result<ChallengedAttestation, ServiceError> {
        let attested = self.fresh(&self.key_attestation)?;
        let challenge = AttestationChallenge { nonce, tls_exporter };
        Ok(ChallengedAttestation {
            evidence: attested.evidence,
            binding: attested.binding,
            challenge_key: self.challenge_key.public_key(),
            release: attested.release,
            certificate: attested.certificate,
            signature: self.challenge_key.sign(ATTESTATION_CHALLENGE_LABEL, &challenge),
        })
    }

    /// `latest`, unless it is missing or `ATTESTATION_MAX_AGE_SECS` old.
    fn fresh(&self, latest: &Mutex<Option<AttestationResponse>>) -> Result<AttestationResponse, ServiceError> {
        let response = lock(latest).clone().ok_or_else(|| fail(ErrorCode::Unavailable, "not attested yet"))?;
        let age_limit = response.binding.attested_at.saturating_add(ATTESTATION_MAX_AGE_SECS);
        if self.time.estimate().earliest() >= age_limit {
            return Err(fail(ErrorCode::Unavailable, "the latest attestation is too old"));
        }
        Ok(response)
    }

    pub(crate) async fn ticket(&self) -> Result<ProofTicket, ServiceError> {
        let (time, _) = self.serving_now().await?;
        Ok(self.service.ticket.issue(&self.pin.tenant, &time, &mut rng()))
    }

    /// The certified wrap keys a new blob is sealed to: the tenant's platforms at or above
    /// `min_platform`, at the `current` tenant key version.
    fn recipients(
        &self,
        state: &TenantState,
        min_platform: Option<seal_proto::session::PlatformTier>,
    ) -> Result<Vec<TenantWrapKey>, ServiceError> {
        let current = state.tenant_key_versions.current;
        let platforms: Vec<PlatformId> =
            state.platforms.iter().copied().filter(|p| min_platform.is_none_or(|min| p.tier() >= min)).collect();
        if platforms.is_empty() {
            return Err(fail(ErrorCode::BadRequest, "no platform of the tenant meets the policy's min_platform"));
        }
        let keys = lock(&self.wrap_keys);
        platforms
            .iter()
            .map(|platform| {
                keys.get(&(*platform, current)).cloned().ok_or_else(|| {
                    fail(
                        ErrorCode::Unavailable,
                        format!("no certified wrap key for {platform:?} at tenant key version {current}"),
                    )
                })
            })
            .collect()
    }

    pub(crate) async fn seal(&self, request: SealRequest) -> Result<SealResponse, ServiceError> {
        let result = self.seal_refusable(request).await;
        self.refused(Operation::Seal, result)
    }

    async fn seal_refusable(&self, request: SealRequest) -> Result<SealResponse, Refusal> {
        let (time, tenant) = self.serving_now().await?;
        let _busy = self.activity.begin_open()?;
        let permit = TenantAuthorizer::new(&tenant).seal(&time)?;
        Ok(self.seal_permitted(&request, permit, &time)?)
    }

    /// Opens the upload, checks the secret against its policy and the destination's protocol
    /// against the image's adapters, and seals it. Anyone may: the blob names no producer.
    fn seal_permitted(
        &self,
        request: &SealRequest,
        permit: SealPermit<'_>,
        time: &TrustedTime,
    ) -> Result<SealResponse, ServiceError> {
        let state = permit.tenant().state();
        if request.service_key_version != self.service_key_version {
            return Err(fail(ErrorCode::BadRequest, "upload sealed to another service key version"));
        }
        let ingest = IngestContext {
            tenant: self.pin.tenant.clone(),
            service_key_version: self.service_key_version,
            tls_spki_sha256: self.service.tls_spki_sha256,
        };
        let aad = codec::canonical(&ingest);
        let plaintext = seal_crypto::hpke::open_ingest(
            &self.service.ingest,
            &request.hpke_enc,
            &request.sealed_payload,
            &seal_crypto::hpke::ingest_info(&self.pin.tenant),
            &aad,
        )
        .map_err(|_| fail(ErrorCode::BadRequest, "the upload does not decrypt"))?;
        // The decoder's message can quote the decrypted payload, so it is not kept.
        let SealPayload { secret, policy } = codec::from_canonical(plaintext.expose())
            .map_err(|_| fail(ErrorCode::BadRequest, "the seal payload is malformed"))?;
        policy.validate_secret(secret.expose()).map_err(|e| fail(ErrorCode::BadRequest, e.to_string()))?;
        let protocol = policy.destination().protocol();
        if !self.adapters.iter().any(|a| a.protocol() == protocol) {
            return Err(fail(ErrorCode::BadRequest, format!("this enclave has no adapter for {protocol:?}")));
        }
        let recipients = self.recipients(state, policy.min_platform())?;
        let destination = policy.destination().to_string();
        let apps = policy.apps().clone();
        let blob = BlobSealer::new(&recipients)
            .and_then(|sealer| sealer.seal(secret.expose(), policy, time.now, &mut rng()))
            .map_err(|e| fail(ErrorCode::BadRequest, format!("seal: {e}")))?;
        let blob_id = blob.header.blob_id;
        let telemetry = self.record(None, TelemetryEvent::Seal { blob_id, destination, apps });
        Ok(SealResponse { blob: blob.to_string(), blob_id, telemetry })
    }

    pub(crate) async fn session(
        &self,
        request: SessionRequest,
        source: Option<SocketAddr>,
    ) -> Result<SessionResponse, ServiceError> {
        let result = self.session_refusable(request, source).await;
        self.refused(Operation::Session, result)
    }

    async fn session_refusable(
        &self,
        request: SessionRequest,
        source: Option<SocketAddr>,
    ) -> Result<SessionResponse, Refusal> {
        let (time, tenant) = self.serving_now().await?;
        let authenticated = self.authenticator.session(request, &tenant, &time).await?;
        let identity = authenticated.caller().identity().clone();
        let _busy = self.activity.begin().by(&identity)?;
        let request = authenticated.request();
        let blob =
            Blob::from_str(&request.blob).map_err(|_| fail(ErrorCode::BadRequest, "malformed blob")).by(&identity)?;
        let opened = self.open(&blob, &tenant).await.by(&identity)?;
        let attested = self
            .check_evidence(
                &identity,
                request.endpoint.as_ref(),
                request.evidence_challenge(),
                Some(blob.header.blob_id),
                &time,
            )
            .await
            .by(&identity)?;
        // The tier the endpoint earned from this request: Hardened needs verified evidence
        // from every enrolled provider.
        let offered = offered_tier(attested);
        let authorizer = TenantAuthorizer::new(&tenant).with_source(source.map(|s| s.ip()));
        let permit = match authorizer.session(&authenticated, &opened, offered, &time) {
            Ok(permit) => permit,
            Err(e) => {
                return Err(self.decision_refused(e, attested, opened.blob(), &identity, &time).await).by(&identity)
            }
        };
        self.issue_session(permit, &time, source).by(&identity)
    }

    /// The sole session issuance path: the claims come from the permit (its exact request,
    /// caller, opened blob and decision), and the token carries the blob still sealed.
    pub(crate) fn issue_session(
        &self,
        permit: SessionPermit<'_>,
        time: &TrustedTime,
        from: Option<SocketAddr>,
    ) -> Result<SessionResponse, ServiceError> {
        let caller = permit.request().caller();
        let (opened, decision) = (permit.opened(), permit.decision());
        let blob = opened.blob();
        let session_id: [u8; 16] = random();
        let expires_at = time.now.saturating_add(SESSION_TOKEN_SECS);
        let claims = SessionClaims {
            tenant: permit.tenant().state().tenant.clone(),
            app: decision.app.clone(),
            session_id,
            caller: caller.identity().clone(),
            authentication: caller.scope().clone(),
            blob: blob.clone(),
            service_key_version: self.service_key_version,
            tier: decision.tier,
            platform: self.platform,
            issued_at: time.now,
            expires_at,
            min_tier: permit.request().request().min_tier,
        };
        let token = self.service.token.issue(&claims, &mut rng());
        let resealed = if decision.reseal {
            self.reseal(opened, permit.tenant().state(), time)
                .map_err(|e| tracing::warn!(error = %e, "resealing under the current tenant key version failed"))
                .ok()
        } else {
            None
        };
        let telemetry = self.record(
            Some(caller.identity().clone()),
            TelemetryEvent::Session {
                session_id,
                app: decision.app.clone(),
                blob_id: blob.header.blob_id,
                tier: decision.tier,
                from,
            },
        );
        Ok(SessionResponse {
            token,
            info: SessionInfo {
                session_id,
                platform: self.platform.tier(),
                tier: decision.tier,
                tenant: claims.tenant.clone(),
                app: decision.app.clone(),
                blob_id: blob.header.blob_id,
                expires_at,
            },
            destination: blob.policy.destination().clone(),
            resealed,
            injection: blob.policy.injection().cloned(),
            telemetry,
        })
    }

    /// The opened blob's secret and policy sealed again under the current tenant key version.
    fn reseal(&self, opened: &OpenedBlob, state: &TenantState, time: &TrustedTime) -> Result<String, ServiceError> {
        let blob = opened.blob();
        let recipients = self.recipients(state, blob.policy.min_platform())?;
        let resealed = BlobSealer::new(&recipients)
            .and_then(|s| s.seal(opened.secret(), blob.policy.clone(), time.now, &mut rng()))
            .map_err(|e| fail(ErrorCode::Internal, format!("reseal: {e}")))?;
        Ok(resealed.to_string())
    }

    pub(crate) async fn extend(
        &self,
        request: ExtendRequest,
        source: Option<SocketAddr>,
    ) -> Result<ExtendResponse, ServiceError> {
        let result = self.extend_refusable(request, source).await;
        self.refused(Operation::Extend, result)
    }

    async fn extend_refusable(
        &self,
        request: ExtendRequest,
        source: Option<SocketAddr>,
    ) -> Result<ExtendResponse, Refusal> {
        let (time, tenant) = self.serving_now().await?;
        let current = self.redeem(request.token.expose())?;
        let authenticated = self.authenticator.extend(request, &tenant, &time).await?;
        let identity = authenticated.caller().identity().clone();
        let _busy = self.activity.begin().by(&identity)?;
        let endpoint = authenticated.request().endpoint.as_ref();
        let challenge = authenticated.request().evidence_challenge();
        let attested = self
            .check_evidence(&identity, endpoint, challenge, Some(current.blob.header.blob_id), &time)
            .await
            .by(&identity)?;
        // Recomputed from the fresh report on every extend: a hardened blob stops working
        // within one extend of its endpoint's attestation going silent.
        let offered = offered_tier(attested);
        let authorizer = TenantAuthorizer::new(&tenant).with_source(source.map(|s| s.ip()));
        let permit = match authorizer.extend(&authenticated, &current, offered, &time) {
            Ok(permit) => permit,
            Err(e) => {
                return Err(self.decision_refused(e, attested, &current.blob, &identity, &time).await).by(&identity)
            }
        };
        let c = permit.current();
        let expires_at = time.now.saturating_add(SESSION_TOKEN_SECS);
        let claims = SessionClaims {
            tenant: c.tenant.clone(),
            app: c.app.clone(),
            session_id: c.session_id,
            caller: c.caller.clone(),
            authentication: permit.scope().clone(),
            blob: c.blob.clone(),
            service_key_version: c.service_key_version,
            tier: offered,
            platform: c.platform,
            issued_at: time.now,
            expires_at,
            min_tier: c.min_tier,
        };
        let token = self.service.token.issue(&claims, &mut rng());
        self.record(Some(identity), TelemetryEvent::Extend { session_id: c.session_id, expires_at });
        Ok(ExtendResponse { token, expires_at })
    }

    pub(crate) async fn end(&self, request: EndRequest) -> Result<(), ServiceError> {
        let result = self.end_refusable(request).await;
        self.refused(Operation::End, result)
    }

    /// Only a token that has not expired ends its session: an older token of an extended
    /// session, once past its own expiry, ends nothing. Clock uncertainty counts in the
    /// caller's favour.
    async fn end_refusable(&self, request: EndRequest) -> Result<(), Refusal> {
        let claims = self.redeem(request.token.expose())?;
        let identity = claims.caller.clone();
        let _busy = self.activity.begin().by(&identity)?;
        let time = self.now().await.by(&identity)?;
        if time.earliest() >= claims.expires_at {
            return Err(fail(ErrorCode::SessionExpired, "session token expired")
                .with(RefusalContext::SessionExpired { expired_at: claims.expires_at }))
            .by(&identity);
        }
        self.snapshot(&time).by(&identity)?;
        let signed = self.close_session(claims.session_id, ErrorCode::SessionEnded, &identity, &time);
        self.tenants.publish_session_end(&signed).await.by(&identity)
    }

    /// Ends a session here and now: its live connections on this replica end with `reason`,
    /// and the `SessionEnd` is signed, applied and recorded. A session ended before keeps its
    /// first `SessionEnd`, which is returned again for publishing.
    pub(super) fn close_session(
        &self,
        session_id: [u8; 16],
        reason: ErrorCode,
        identity: &WorkloadIdentity,
        time: &TrustedTime,
    ) -> SignedSessionEnd {
        self.live.end(&session_id, reason);
        let mut ended = lock(&self.ended_here);
        ended.retain(|_, end| end.body.is_live(time));
        if let Some(signed) = ended.get(&session_id) {
            return signed.clone();
        }
        let end = SessionEnd { tenant: self.pin.tenant.clone(), session_id, reason, ended_at: time.now };
        let signed = self.service.telemetry.signer().sign_into(SESSION_END_LABEL, end);
        ended.insert(session_id, signed.clone());
        drop(ended);
        self.apply_local(Local::End(signed.clone()));
        self.record(Some(identity.clone()), TelemetryEvent::End { session_id, reason });
        signed
    }

    /// `close_session` from synchronous code (an integrity `Verdict::End`): publishing runs in
    /// the background.
    pub(super) fn close_session_detached(
        self: &Arc<Self>,
        session_id: [u8; 16],
        reason: ErrorCode,
        identity: &WorkloadIdentity,
        time: &TrustedTime,
    ) {
        let signed = self.close_session(session_id, reason, identity, time);
        let runtime = self.clone();
        tokio::spawn(async move {
            if let Err(e) = runtime.tenants.publish_session_end(&signed).await {
                tracing::warn!(error = %e, "publishing a session end failed");
            }
        });
    }

    pub(crate) async fn signal(&self, request: SignalRequest) -> Result<(), ServiceError> {
        let result = self.signal_refusable(request).await;
        self.refused(Operation::Signal, result)
    }

    async fn signal_refusable(&self, request: SignalRequest) -> Result<(), Refusal> {
        let (time, tenant) = self.serving_now().await?;
        // Exactly one credential: an enrolled source's signatures, or a workload proof.
        if !request.signatures.is_empty() {
            if request.context.is_some() || request.proof.is_some() {
                return Err(fail(ErrorCode::BadRequest, "a signal carries one credential").into());
            }
            return self.external_signal_refusable(request, &tenant, &time).await;
        }
        if request.context.is_none() || request.proof.is_none() {
            return Err(fail(ErrorCode::BadRequest, "a signal carries one credential").into());
        }
        if request.identity.is_some() || request.observed_at.is_some() || request.blob_id.is_some() {
            return Err(fail(ErrorCode::BadRequest, "with a proof, identity source and time are derived").into());
        }
        let authenticated = self.authenticator.signal(request, &tenant, &time).await?;
        let identity = authenticated.caller().identity().clone();
        let _busy = self.activity.begin().by(&identity)?;
        let authorizer = TenantAuthorizer::new(&tenant);
        let permit = authorizer.signal(&authenticated, &time).by(&identity)?;
        let signal = permit.signal().clone();
        self.raise_and_publish(signal, &time).await.map(drop).by(&identity)
    }

    /// An external source's finding (the host agent today; an EDR relay tomorrow): the
    /// request carries only what the sender uniquely knows — code, severity, identity,
    /// observed_at, optional blob_id, signatures. The tenant is this replica's pin and
    /// the source is the enrolled key the signature's signer names: both derived, both
    /// still inside the signed digest. Verified, applied at once (a suspension ends the
    /// identity's sessions here immediately), then published. Nothing a control plane
    /// does can undo the local application.
    async fn external_signal_refusable(
        &self,
        request: SignalRequest,
        tenant: &seal_verify::VerifiedTenant,
        time: &TrustedTime,
    ) -> Result<(), Refusal> {
        let state = tenant.state();
        let identity = request
            .identity
            .clone()
            .ok_or_else(|| fail(ErrorCode::BadRequest, "an external finding names an identity"))?;
        let observed_at =
            request.observed_at.ok_or_else(|| fail(ErrorCode::BadRequest, "an external finding carries its time"))?;
        let who = identity.clone();
        let refuse = |code, detail: &'static str| Err(fail(code, detail)).by(&who);

        if seal_proto::integrity::validate_code(&request.code).is_err() {
            return refuse(ErrorCode::BadRequest, "invalid signal code");
        }
        // The source is derived from the signer: the unique enrolled key its signature names.
        let Some(signer) = request.signatures.first().map(|s| s.signer) else {
            return refuse(ErrorCode::BadRequest, "an external finding carries its signature");
        };
        let named: Vec<(&String, &seal_proto::PublicKey)> =
            state.integrity.sources.iter().filter(|(_, key)| seal_crypto::sign::key_id(key) == signer).collect();
        if named.len() != 1 {
            return refuse(ErrorCode::BadRequest, "the signer is not one enrolled source key");
        }
        let (source, key) = named[0];
        let signal = seal_proto::integrity::IntegritySignal {
            tenant: state.tenant.clone(),
            identity,
            source: seal_proto::integrity::SignalSource::External { source: source.clone() },
            code: request.code,
            severity: request.severity,
            observed_at,
            blob_id: request.blob_id,
        };
        let signed = seal_proto::integrity::SignedSignal { body: signal, signatures: request.signatures };
        let signed_ok = signed
            .signatures
            .iter()
            .any(|sig| seal_crypto::sign::verify(key, seal_proto::integrity::SIGNAL_LABEL, &signed.body, sig).is_ok());
        if !signed_ok {
            return refuse(ErrorCode::BadRequest, "no signature by the enrolled source key");
        }

        if let (_, Some(signed)) = self.take_signal(signed, &state.integrity, time) {
            self.tenants.publish_signal(&signed).await?;
        }
        Ok(())
    }
}

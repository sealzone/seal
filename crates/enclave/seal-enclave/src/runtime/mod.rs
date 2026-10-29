//! The runtime behind `SealService`: boot, the enclave API operations (`ops`), the tenant
//! state (`state`), tenant wrapping keys (`keys`), integrity signals (`integrity`), live
//! sessions (`live`), the data plane (`conn`), what the deployment serves and the idle exit
//! (`hosted`), and the background tasks.
//!
//! One `Runtime` per replica. Everything that decides acts through `seal-authz` permits over
//! the newest verified `TenantState` in `StateCache`; signals and session ends this replica
//! signs are applied to that cache at once by re-verifying the latest bundle with them added.

use seal_proto::telemetry::{Dependency, RefusalContext};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use seal_adapter::{Adapter, UpstreamConnector};
use seal_authz::{DeploymentVerifier, RequestAuthenticator, StateCache};
use seal_crypto::{IngestKey, ServiceKeyScope, ServiceKeys, TelemetryKey, TicketKey, TokenKey};
use seal_integrity::{Detector, EvidenceCheck};
use seal_proto::api::AttestationResponse;
use seal_proto::freshness::ATTESTATION_REFRESH_SECS;
use seal_proto::identity::WorkloadIdentity;
use seal_proto::release::{
    Component, ReleaseEvidence, ServiceKeyCertificate, SignedServiceKeyCertificate, TenantWrapKey,
};
use seal_proto::session::{SessionClaims, SignedSessionEnd};
use seal_proto::state::TenantBundle;
use seal_proto::telemetry::{TelemetryEntry, TelemetryEvent};
use seal_proto::{
    ErrorCode, Measurement, PlatformId, PublicKey, ServiceKeyVersion, TenantKeyVersion, TenantPin, TrustedTime,
};
use seal_verify::{ReleaseVerifier, Trust, VerifiedTenant};

use crate::{
    Components, KeyProvider, ReleaseStore, ServiceConfig, ServiceError, Telemetry, TelemetrySigner, TenantStore,
    STATE_RELOAD_SECS,
};

pub(crate) mod conn;
mod hosted;
mod integrity;
mod keys;
mod live;
mod ops;
mod state;
mod time;

#[cfg(all(test, feature = "sim"))]
mod tests;

pub(crate) use crate::{fail, lock, random, rng};

impl From<seal_authz::AuthzError> for ServiceError {
    fn from(e: seal_authz::AuthzError) -> Self {
        ServiceError { code: e.code(), detail: e.to_string(), context: e.context().map(Box::new) }
    }
}

/// The service keys, split by use. The TLS key lives on in the inbound TLS configurations.
struct Service {
    token: TokenKey,
    ingest: IngestKey,
    telemetry: Arc<TelemetryKey>,
    ticket: Arc<TicketKey>,
    tls_spki_sha256: [u8; 32],
    telemetry_public_keys: Vec<(ServiceKeyVersion, PublicKey)>,
    certificate: SignedServiceKeyCertificate,
}

pub(crate) struct Runtime {
    pin: TenantPin,
    /// This replica's deployment identity, as verified at boot; its `deployments` entries in
    /// the newest state decide what it serves (`hosted::serving`).
    deployment: WorkloadIdentity,
    platform: PlatformId,
    measurement: Measurement,
    service_key_version: ServiceKeyVersion,
    trust: Trust,
    cloud: seal_cloud::Cloud,
    keys: Arc<dyn KeyProvider>,
    tenants: Arc<dyn TenantStore>,
    releases: Arc<dyn ReleaseStore>,
    upstream: Arc<dyn UpstreamConnector>,
    telemetry: Arc<dyn Telemetry>,
    adapters: Vec<Arc<dyn Adapter>>,
    detectors: Vec<Arc<dyn Detector>>,
    evidence_checks: Vec<Arc<dyn EvidenceCheck>>,
    /// `ServiceConfig::state_reload`: the reload interval and the live-session recheck bound.
    state_reload: Duration,
    service: Service,
    authenticator: RequestAuthenticator,
    /// Inbound TLS of the enclave's port: the API and tunnels.
    tls: Arc<rustls::ServerConfig>,
    state: Arc<StateCache>,
    /// The latest verified bundle, kept to apply this replica's own signals and session ends.
    /// Its lock also serializes every `StateCache::update`.
    bundle: Mutex<TenantBundle>,
    /// Guardian-certified wrap keys from the bundles, by platform and tenant key version.
    wrap_keys: Mutex<BTreeMap<(PlatformId, TenantKeyVersion), TenantWrapKey>>,
    tenant_keys: keys::TenantKeyCache,
    /// Session ends this replica signed, republished when the session is ended again.
    ended_here: Mutex<HashMap<[u8; 16], SignedSessionEnd>>,
    time: time::TimeBase,
    release: Mutex<ReleaseEvidence>,
    attestation: Mutex<Option<AttestationResponse>>,
    live: live::Registry,
    connections: AtomicU64,
    activity: hosted::Activity,
}

/// The background tasks; aborted when dropped.
pub(crate) struct Tasks(Vec<tokio::task::AbortHandle>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

impl Tasks {
    fn spawn(runtime: &Arc<Runtime>) -> Self {
        let attest = runtime.clone();
        let attestation = tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(ATTESTATION_REFRESH_SECS));
            every.tick().await;
            loop {
                every.tick().await;
                if let Err(e) = attest.attest(true).await {
                    tracing::warn!(error = %e, "periodic attestation failed");
                }
            }
        });
        let reload = runtime.clone();
        let state = tokio::spawn(async move {
            let mut every = tokio::time::interval(reload.state_reload);
            every.tick().await;
            loop {
                every.tick().await;
                if let Err(e) = reload.reload().await {
                    tracing::warn!(error = %e, "tenant state reload failed");
                }
            }
        });
        let monitor = tokio::spawn(live::monitor(runtime.clone()));
        Self(vec![attestation.abort_handle(), state.abort_handle(), monitor.abort_handle()])
    }
}

/// `evidence` is release evidence for exactly this build: verified against the trust, an
/// enclave release for this platform, measurement and service key version.
fn check_release(
    trust: &Trust,
    evidence: &ReleaseEvidence,
    platform: PlatformId,
    measurement: &Measurement,
    service_key_version: ServiceKeyVersion,
    time: &TrustedTime,
) -> Result<(), ServiceError> {
    let verified = ReleaseVerifier::new(trust.releases.clone())
        .verify(evidence, time)
        .map_err(|e| fail(e.code(), format!("release evidence: {e}")))?;
    let manifest = verified.manifest();
    if manifest.component != Component::Enclave || manifest.platform != platform || &manifest.measurement != measurement
    {
        return Err(fail(ErrorCode::VerificationFailed, "release evidence is for another build"));
    }
    if manifest.service_key_version != service_key_version {
        return Err(fail(ErrorCode::VerificationFailed, "release is for another service key version"));
    }
    Ok(())
}

/// The keys are exactly `scope`'s, and come with the guardian's certificate for exactly them.
fn check_service_keys(trust: &Trust, scope: &ServiceKeyScope, keys: &ServiceKeys) -> Result<(), ServiceError> {
    if &keys.scope != scope {
        return Err(fail(ErrorCode::VerificationFailed, "service keys for another scope"));
    }
    let certificate = seal_verify::verify_service_certificate(&trust.guardians, &keys.certificate)
        .map_err(|e| fail(e.code(), format!("service key certificate: {e}")))?;
    let expected = ServiceKeyCertificate {
        platform: scope.platform,
        tenant: scope.tenant.clone(),
        root_id: scope.root_id,
        service_key_version: scope.service_key_version,
        tls_spki_sha256: keys.tls.spki_sha256(),
        ingest_public_key: keys.ingest.public_key(),
        telemetry_public_keys: keys.telemetry_public_keys.clone(),
    };
    if certificate != &expected {
        return Err(fail(ErrorCode::VerificationFailed, "service key certificate is for other keys"));
    }
    if !keys.telemetry_public_keys.contains(&(scope.service_key_version, keys.telemetry.public_key())) {
        return Err(fail(ErrorCode::VerificationFailed, "telemetry public keys omit this version's key"));
    }
    Ok(())
}

impl Runtime {
    /// `SealService::boot`, in its documented order.
    pub(crate) async fn boot(config: ServiceConfig, c: Components) -> Result<(Arc<Self>, Tasks), ServiceError> {
        if config.state_reload.is_zero() || config.state_reload > Duration::from_secs(STATE_RELOAD_SECS) {
            return Err(fail(ErrorCode::Internal, format!("state_reload must be 1..={STATE_RELOAD_SECS} s")));
        }
        let pin = c.cloud.tenant_pin().clone();
        let time = c.cloud.clock().now().await.map_err(|e| fail(e.code(), format!("clock: {e}")))?;
        let (platform, measurement) = (c.cloud.attestor().platform(), c.cloud.attestor().measurement());

        let release = c.releases.load(platform, &measurement).await?;
        check_release(&config.trust, &release, platform, &measurement, config.service_key_version, &time)?;

        let bundle = c.tenants.load().await?;
        let tenant = state::verify_bundle(&config.trust, platform, &pin, &bundle, Vec::new(), &time)?;

        let https =
            Arc::new(seal_net::HttpsClient::new(Arc::new(seal_net::BakedRootsConnector::new(c.cloud.dialer()))));
        let proof = c
            .cloud
            .deployment(&tenant.state().deployments)
            .await
            .map_err(|e| fail(e.code(), format!("deployment proof: {e}")))?;
        let deployment = DeploymentVerifier::new(https.clone())
            .verify(&proof, &tenant, &time)
            .await
            .map_err(|e| fail(e.code(), format!("deployment identity: {e}")))?;

        let scope = ServiceKeyScope {
            platform,
            tenant: pin.tenant.clone(),
            root_id: pin.root_id,
            service_key_version: config.service_key_version,
        };
        let keys = c.keys.service_keys(&scope).await?;
        check_service_keys(&config.trust, &scope, &keys)?;
        c.tenants.publish_service_key_certificate(&keys.certificate).await?;

        let ServiceKeys { token, ingest, telemetry, tls, ticket, telemetry_public_keys, certificate, .. } = keys;
        let telemetry_keys = telemetry_public_keys.iter().map(|(_, k)| *k).collect();
        let tenant = state::verify_bundle(&config.trust, platform, &pin, &bundle, telemetry_keys, &time)?;
        let state = Arc::new(StateCache::new(pin.tenant.clone()));
        state.update(tenant)?;
        let wrap_keys = state::wrap_keys(&config.trust, &pin, &bundle);

        let tls_config = conn::tls_config(&tls)?;
        let tls_spki_sha256 = tls.spki_sha256();
        let telemetry_key = Arc::new(telemetry);
        let ticket = Arc::new(ticket);
        let authenticator = RequestAuthenticator::new(https, ticket.clone(), tls_spki_sha256);
        c.telemetry.start(TelemetrySigner::new(pin.tenant.clone(), telemetry_key.clone(), state.clone()));

        let runtime = Arc::new(Runtime {
            pin,
            deployment,
            platform,
            measurement,
            service_key_version: config.service_key_version,
            trust: config.trust,
            cloud: c.cloud,
            keys: c.keys,
            tenants: c.tenants,
            releases: c.releases,
            upstream: c.upstream,
            telemetry: c.telemetry,
            adapters: c.adapters,
            detectors: c.detectors,
            evidence_checks: c.evidence_checks,
            state_reload: config.state_reload,
            service: Service {
                token,
                ingest,
                telemetry: telemetry_key,
                ticket,
                tls_spki_sha256,
                telemetry_public_keys,
                certificate,
            },
            authenticator,
            tls: tls_config,
            state,
            bundle: Mutex::new(bundle),
            wrap_keys: Mutex::new(wrap_keys),
            tenant_keys: keys::TenantKeyCache::default(),
            ended_here: Mutex::new(HashMap::new()),
            time: time::TimeBase::new(time),
            release: Mutex::new(release),
            attestation: Mutex::new(None),
            live: live::Registry::default(),
            connections: AtomicU64::new(0),
            activity: hosted::Activity::default(),
        });
        runtime.attest(false).await?;
        let tasks = Tasks::spawn(&runtime);
        Ok((runtime, tasks))
    }

    /// A fresh reading of the trusted clock, which also anchors `time.estimate()`.
    pub(crate) async fn now(&self) -> Result<TrustedTime, ServiceError> {
        let time = self.cloud.clock().now().await.map_err(|e| {
            fail(e.code(), format!("clock: {e}")).with(RefusalContext::Unavailable { service: Dependency::Clock })
        })?;
        self.time.record(time);
        Ok(time)
    }

    /// The newest verified state, if it is still fresh at `time`: the enclave fails closed.
    pub(crate) fn snapshot(&self, time: &TrustedTime) -> Result<VerifiedTenant, ServiceError> {
        let tenant = self
            .state
            .get()
            .ok_or_else(|| fail(ErrorCode::Unavailable, "no verified tenant state").with(RefusalContext::NoState))?;
        if time.latest() >= tenant.fresh_until() {
            return Err(fail(ErrorCode::Unavailable, "the tenant state is past its fresh_until")
                .with(RefusalContext::StaleState { fresh_until: Some(tenant.fresh_until()) }));
        }
        Ok(tenant)
    }

    /// Where every operation starts: a fresh clock reading and the snapshot fresh at it, which
    /// must still list this replica (`snapshot`, `serving`).
    pub(crate) async fn serving_now(&self) -> Result<(TrustedTime, VerifiedTenant), ServiceError> {
        let time = self.now().await?;
        let tenant = self.snapshot(&time)?;
        self.serving(&tenant)?;
        Ok((time, tenant))
    }

    /// What this replica serves under `tenant`: `NotAllowed` once the tenant no longer lists
    /// its deployment identity.
    pub(crate) fn serving(&self, tenant: &VerifiedTenant) -> Result<hosted::Serving, ServiceError> {
        hosted::serving(tenant.state(), &self.deployment).ok_or_else(|| {
            fail(ErrorCode::NotAllowed, "the tenant no longer lists this deployment")
                .with(RefusalContext::DeploymentNotListed)
        })
    }

    /// Resolves once this replica has started draining because it is idle (`SealService::idle_exit`).
    pub(crate) async fn idle_exit(&self, idle: Duration) {
        let poll = (idle / 4).clamp(Duration::from_millis(100), self.state_reload);
        // The newest state's word; kept while the tenant lists this deployment no more.
        let mut hosted = false;
        loop {
            tokio::time::sleep(poll).await;
            if let Some(serving) = self.state.get().and_then(|t| hosted::serving(t.state(), &self.deployment)) {
                hosted = serving.hosted;
            }
            if hosted && self.live.all().is_empty() && self.activity.drain_if_idle(idle) {
                return;
            }
        }
    }

    /// One telemetry entry at the current trusted time.
    pub(crate) fn record(
        &self,
        identity: Option<WorkloadIdentity>,
        event: TelemetryEvent,
    ) -> seal_proto::api::TelemetryReceipt {
        self.telemetry.append(TelemetryEntry {
            at: self.time.estimate().now,
            tenant: self.pin.tenant.clone(),
            identity,
            event,
        })
    }

    /// The TLS configuration of the enclave's port (`conn::tls_config`).
    pub(crate) fn tls_config(&self) -> Arc<rustls::ServerConfig> {
        self.tls.clone()
    }

    /// Claims of a token this tenant's enclaves issued, for the pinned tenant and root.
    pub(crate) fn redeem(&self, token: &str) -> Result<SessionClaims, ServiceError> {
        let claims = self.service.token.redeem(token).map_err(|e| match e {
            seal_crypto::CryptoError::Malformed(_) => {
                fail(ErrorCode::BadRequest, "malformed session token").with(RefusalContext::BadSessionToken)
            }
            _ => fail(ErrorCode::NotAllowed, "a session token this tenant's enclaves did not issue")
                .with(RefusalContext::BadSessionToken),
        })?;
        if claims.tenant != self.pin.tenant || claims.blob.header.root_id != self.pin.root_id {
            return Err(fail(ErrorCode::NotAllowed, "a session of another tenant")
                .with(RefusalContext::OtherTenant { tenant: claims.tenant.clone() }));
        }
        Ok(claims)
    }

    /// Attests the current binding at the clock's time. With `reload_release`, first replaces
    /// the release evidence with the store's newest, if that still verifies (the old one is kept
    /// otherwise, and goes stale for clients on its own).
    pub(crate) async fn attest(&self, reload_release: bool) -> Result<(), ServiceError> {
        let time = self.now().await?;
        if reload_release {
            match self.releases.load(self.platform, &self.measurement).await {
                Ok(evidence) => {
                    match check_release(
                        &self.trust,
                        &evidence,
                        self.platform,
                        &self.measurement,
                        self.service_key_version,
                        &time,
                    ) {
                        Ok(()) => *lock(&self.release) = evidence,
                        Err(e) => {
                            tracing::warn!(error = %e, "newer release evidence does not verify; keeping the last")
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "release evidence reload failed"),
            }
        }
        let binding = seal_proto::api::AttestationBinding {
            attested_at: time.now,
            service_key_version: self.service_key_version,
            tls_spki_sha256: self.service.tls_spki_sha256,
            ingest_public_key: self.service.ingest.public_key(),
            telemetry_public_keys: self.service.telemetry_public_keys.clone(),
        };
        let report_data = seal_proto::codec::labeled_digest(seal_proto::api::ATTESTATION_BINDING_LABEL, &binding);
        let evidence =
            self.cloud.attestor().attest(report_data).await.map_err(|e| fail(e.code(), format!("attestation: {e}")))?;
        let response = AttestationResponse {
            evidence,
            binding,
            release: lock(&self.release).clone(),
            certificate: self.service.certificate.clone(),
        };
        *lock(&self.attestation) = Some(response);
        Ok(())
    }
}

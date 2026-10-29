//! Pure decisions over one verified tenant snapshot. Every operation that needs a decision
//! gets a permit (`SealPermit`, `SessionPermit`, `ExtendPermit`, `SignalPermit`), and the
//! enclave acts only by consuming one. Ending a session needs no decision: its token suffices.
//! Sealing needs no caller: anyone may seal, and only the apps a blob names can use it.
//! Expiry checks use `time.latest()`; suspensions use `time.earliest()`.
//!
//! Every decision first requires the snapshot to be fresh (`time.latest() < fresh_until`,
//! `Stale` otherwise), so a state past its freshness never authorizes anything.
//!
//! Caller grants: a caller holds a grant when one of the matchers it was authenticated
//! against (`AuthenticationScope::matched_grants`, which keeps an Azure entry's audience) is,
//! exactly, still in the current grant set and still matches the caller's identity, and the
//! authentication has not expired (`expires_at`, against `time.latest()`).
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::{AuthenticatedRequest, AuthzError};
use seal_proto::telemetry::RefusalContext;
use seal_proto::{
    api::{ExtendRequest, SessionRequest, SignalRequest},
    blob::Blob,
    identity::{AuthenticationScope, IdentityMatcher, WorkloadIdentity},
    integrity::{
        validate_code, EndpointReport, IntegrityAction, IntegritySignal, Severity, SignalSource, CODE_ARTIFACT_MISMATCH,
    },
    session::{ConsumerTier, SessionClaims},
    AppName, ErrorCode, TenantId, TrustedTime, UnixTime,
};
use seal_verify::VerifiedTenant;

/// The severity of the `artifact-mismatch` signal a failed artifact rule produces.
const ARTIFACT_MISMATCH_SEVERITY: Severity = Severity::High;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionDecision {
    pub app: AppName,
    pub tier: ConsumerTier,
    pub reseal: bool,
}

pub struct TenantAuthorizer<'a> {
    tenant: &'a VerifiedTenant,
    /// The connection's source address, for the apps' network rules
    /// (`TenantState::app_networks`): `None` when the call has none to check (a background
    /// recheck of live connections), `Some(None)` when the peer's address is unknown, which no
    /// network admits.
    source: Option<Option<IpAddr>>,
}

/// Whether `scope` (for `identity`) still holds a grant in `grants` at `time`.
fn holds(
    scope: &AuthenticationScope,
    identity: &WorkloadIdentity,
    grants: &BTreeSet<IdentityMatcher>,
    time: &TrustedTime,
) -> bool {
    scope.expires_at.is_none_or(|e| time.latest() < e)
        && scope.matched_grants.iter().any(|m| grants.contains(m) && m.matches(identity))
}

impl<'a> TenantAuthorizer<'a> {
    pub fn new(tenant: &'a VerifiedTenant) -> Self {
        Self { tenant, source: None }
    }

    /// Checks the apps' network rules against `source`, the address the request came from
    /// (`None` if unknown). Session starts, extends and tunnel connections set it; without it
    /// no network rule is checked.
    pub fn with_source(mut self, source: Option<IpAddr>) -> Self {
        self.source = Some(source);
        self
    }

    /// Whether `app`'s network rule admits the request's source (always, when no source was set).
    fn admits_source(&self, app: &AppName) -> bool {
        self.source.is_none_or(|source| self.tenant.state().admits_source(app, source))
    }

    /// Refused for connecting from outside `app`'s networks, with the address the enclave saw.
    fn outside_networks(&self, app: &AppName) -> AuthzError {
        AuthzError::not_allowed("the caller connects from outside its app's networks")
            .with(RefusalContext::OutsideNetworks { app: app.clone(), from: self.source.flatten() })
    }
    fn fresh(&self, time: &TrustedTime) -> Result<(), AuthzError> {
        if time.latest() < self.tenant.fresh_until() {
            Ok(())
        } else {
            Err(AuthzError::Stale)
        }
    }

    fn not_suspended(&self, identity: &WorkloadIdentity, time: &TrustedTime) -> Result<(), AuthzError> {
        match self.suspension(identity, time) {
            None => Ok(()),
            Some(Suspension { code, until }) => {
                Err(AuthzError::denied(ErrorCode::IntegrityFailed, "the caller is suspended")
                    .with(RefusalContext::Suspended { code, until }))
            }
        }
    }

    fn app_grants(&self, app: &AppName) -> Option<&BTreeSet<IdentityMatcher>> {
        self.tenant.state().apps.get(app)
    }

    /// The request's proof context names this snapshot's tenant.
    fn own_tenant(&self, tenant: &TenantId) -> Result<(), AuthzError> {
        if tenant == &self.tenant.state().tenant {
            Ok(())
        } else {
            Err(AuthzError::not_allowed("request for another tenant")
                .with(RefusalContext::OtherTenant { tenant: tenant.clone() }))
        }
    }

    /// A live session's caller, under `scope`, still holds the session's app grant on its blob,
    /// connects from inside the app's networks and is not suspended.
    fn still_holds(
        &self,
        app: &AppName,
        blob: &Blob,
        scope: &AuthenticationScope,
        identity: &WorkloadIdentity,
        time: &TrustedTime,
    ) -> Result<(), AuthzError> {
        let granted =
            blob.policy.apps().contains(app) && self.app_grants(app).is_some_and(|g| holds(scope, identity, g, time));
        if !granted {
            return Err(AuthzError::not_allowed("the caller no longer holds the session's app grant")
                .with(RefusalContext::GrantLost { app: app.clone() }));
        }
        if !self.admits_source(app) {
            return Err(self.outside_networks(app));
        }
        self.not_suspended(identity, time)
    }

    /// Everything about the blob itself: this tenant and root, not expired, a tenant key
    /// version in the accepted window. Returns whether to reseal.
    fn check_blob(&self, blob: &Blob, time: &TrustedTime) -> Result<bool, AuthzError> {
        let state = self.tenant.state();
        let h = &blob.header;
        if h.tenant != state.tenant || &h.root_id != self.tenant.root_id() {
            return Err(AuthzError::not_allowed("blob of another tenant")
                .with(RefusalContext::OtherTenant { tenant: h.tenant.clone() }));
        }
        if let Some(expired_at) = blob.policy.expires_at().filter(|e| time.latest() >= *e) {
            return Err(AuthzError::denied(ErrorCode::Expired, "blob expired")
                .with(RefusalContext::BlobExpired { blob_id: h.blob_id, expired_at }));
        }
        let versions = state.tenant_key_versions;
        if h.tenant_key_version < versions.oldest_accepted {
            return Err(AuthzError::denied(ErrorCode::Expired, "blob tenant key version retired").with(
                RefusalContext::KeyVersionRetired {
                    version: h.tenant_key_version,
                    oldest_accepted: versions.oldest_accepted,
                },
            ));
        }
        if h.tenant_key_version > versions.current {
            // Sealed under a state newer than this snapshot.
            return Err(AuthzError::denied(ErrorCode::Unavailable, "blob sealed under a newer tenant state")
                .with(RefusalContext::NewerState { version: h.tenant_key_version }));
        }
        Ok(h.tenant_key_version < versions.current)
    }

    /// The `artifact-mismatch` refusal for `identity`.
    fn artifact_mismatch(&self, identity: &WorkloadIdentity, blob: &Blob, time: &TrustedTime) -> AuthzError {
        AuthzError::ArtifactMismatch(Box::new(IntegritySignal {
            tenant: self.tenant.state().tenant.clone(),
            identity: identity.clone(),
            source: SignalSource::Sdk,
            code: CODE_ARTIFACT_MISMATCH.into(),
            severity: ARTIFACT_MISMATCH_SEVERITY,
            observed_at: time.now,
            blob_id: Some(blob.header.blob_id),
        }))
    }

    /// The app `scope` is granted on `blob` under, whose artifact rule `report` passes.
    fn choose_app(
        &self,
        scope: &AuthenticationScope,
        identity: &WorkloadIdentity,
        blob: &Blob,
        report: Option<&EndpointReport>,
        time: &TrustedTime,
    ) -> Result<AppName, AuthzError> {
        let granted: Vec<&AppName> = blob
            .policy
            .apps()
            .iter()
            .filter(|app| self.app_grants(app).is_some_and(|g| holds(scope, identity, g, time)))
            .collect();
        if granted.is_empty() {
            return Err(AuthzError::not_allowed("the caller holds no grant for the blob's apps")
                .with(RefusalContext::NoGrant { caller: identity.clone(), apps: blob.policy.apps().clone() }));
        }
        let admitted: Vec<&AppName> = granted.iter().copied().filter(|app| self.admits_source(app)).collect();
        if admitted.is_empty() {
            return Err(self.outside_networks(granted[0]));
        }
        let granted = admitted;
        self.not_suspended(identity, time)?;
        let integrity = &self.tenant.state().integrity;
        granted
            .into_iter()
            .find(|app| integrity.admits(app, report))
            .cloned()
            .ok_or_else(|| self.artifact_mismatch(identity, blob, time))
    }

    /// A fresh snapshot to seal under. Anyone may seal: no grant is checked.
    pub fn seal(&self, time: &TrustedTime) -> Result<SealPermit<'a>, AuthzError> {
        self.fresh(time)?;
        Ok(SealPermit { tenant: self.tenant })
    }

    /// Checks the exact blob in request, current grants, expiry, tenant key version and tier;
    /// that the caller is not suspended; and that the request's `endpoint` report passes the
    /// app's artifact rule (`ArtifactMismatch` otherwise, carrying the `artifact-mismatch`
    /// signal the enclave records for the caller).
    /// Requires the exact authenticated envelope: compare request blob to opened.blob().
    /// Caller matching intersects exact original matchers with current app grants,
    /// checks identity, and caps validity by original authentication expiry.
    /// When the caller is granted under several of the blob's apps, the first (by name) whose
    /// artifact rule the report passes is the session's app.
    pub fn session<'p>(
        &'p self,
        request: &'p AuthenticatedRequest<SessionRequest>,
        opened: &'p seal_crypto::blob::OpenedBlob,
        offered_tier: ConsumerTier,
        time: &TrustedTime,
    ) -> Result<SessionPermit<'p>, AuthzError> {
        self.fresh(time)?;
        let req = request.request();
        let blob =
            Blob::from_str(&req.blob).map_err(|_| AuthzError::denied(ErrorCode::BadRequest, "malformed blob"))?;
        if &blob != opened.blob() {
            return Err(AuthzError::denied(ErrorCode::BadRequest, "the opened blob is not the request's"));
        }
        self.own_tenant(&req.context.tenant)?;
        let reseal = self.check_blob(&blob, time)?;
        let caller = request.caller();
        let app = self.choose_app(caller.scope(), caller.identity(), &blob, req.endpoint.as_ref(), time)?;
        if let Some(required) = req.min_tier.filter(|min| offered_tier < *min) {
            return Err(AuthzError::denied(ErrorCode::TierTooLow, "the session would be below min_tier")
                .with(RefusalContext::TierTooLow { required, offered: offered_tier }));
        }
        // The sealed policy's floor, which nobody can lower after sealing.
        if let Some(required) = blob.policy.min_tier().filter(|min| offered_tier < *min) {
            return Err(AuthzError::denied(ErrorCode::TierTooLow, "the blob requires a higher tier")
                .with(RefusalContext::TierTooLow { required, offered: offered_tier }));
        }
        Ok(SessionPermit {
            request,
            opened,
            decision: SessionDecision { app, tier: offered_tier, reseal },
            tenant: self.tenant,
        })
    }

    /// The session itself: this tenant, not ended early, token not expired.
    fn check_session(&self, claims: &SessionClaims, time: &TrustedTime) -> Result<(), AuthzError> {
        if claims.tenant != self.tenant.state().tenant {
            return Err(AuthzError::not_allowed("session of another tenant")
                .with(RefusalContext::OtherTenant { tenant: claims.tenant.clone() }));
        }
        if let Some(end) = self.tenant.session_end(&claims.session_id) {
            return Err(AuthzError::denied(end.reason, "the session was ended").with(RefusalContext::SessionEnded));
        }
        if time.latest() >= claims.expires_at {
            return Err(AuthzError::denied(ErrorCode::SessionExpired, "session token expired")
                .with(RefusalContext::SessionExpired { expired_at: claims.expires_at }));
        }
        Ok(())
    }

    /// A fresh proof for a live session: `request`'s caller must be `current.caller`, the
    /// session must not have ended early (`SessionEnded`), and it must still pass everything `session` checks (grants with the new proof's
    /// scope, expiry, key version, suspension, endpoint report, and the `min_tier` it started
    /// with, carried in its claims). The permit carries
    /// the new authentication scope; the enclave issues the new token from it.
    pub fn extend<'p>(
        &'p self,
        request: &'p AuthenticatedRequest<ExtendRequest>,
        current: &'p SessionClaims,
        offered_tier: ConsumerTier,
        time: &TrustedTime,
    ) -> Result<ExtendPermit<'p>, AuthzError> {
        self.fresh(time)?;
        let caller = request.caller();
        if caller.identity() != &current.caller {
            return Err(AuthzError::not_allowed("the proof is from another caller")
                .with(RefusalContext::OtherCaller { caller: caller.identity().clone() }));
        }
        self.own_tenant(&request.request().context.tenant)?;
        if self.tenant.session_end(&current.session_id).is_some() {
            return Err(
                AuthzError::denied(ErrorCode::SessionEnded, "the session was ended").with(RefusalContext::SessionEnded)
            );
        }
        self.check_session(current, time)?;
        self.check_blob(&current.blob, time)?;
        self.still_holds(&current.app, &current.blob, caller.scope(), caller.identity(), time)?;
        if !self.tenant.state().integrity.admits(&current.app, request.request().endpoint.as_ref()) {
            return Err(self.artifact_mismatch(caller.identity(), &current.blob, time));
        }
        // Recomputed from the fresh report every extend: a hardened blob stops working
        // within one extend of its endpoint's attestation going silent.
        if let Some(required) = current.min_tier.filter(|min| offered_tier < *min) {
            return Err(AuthzError::denied(ErrorCode::TierTooLow, "the session would be below min_tier")
                .with(RefusalContext::TierTooLow { required, offered: offered_tier }));
        }
        if let Some(required) = current.blob.policy.min_tier().filter(|min| offered_tier < *min) {
            return Err(AuthzError::denied(ErrorCode::TierTooLow, "the blob requires a higher tier")
                .with(RefusalContext::TierTooLow { required, offered: offered_tier }));
        }
        Ok(ExtendPermit { current, scope: caller.scope().clone() })
    }

    /// Uses persisted proof scope, not identity alone, when evaluating current grants.
    /// Also ends the session if it was ended early (with its `SessionEnd::reason`) or the
    /// caller is suspended. Checks the token's expiry, the blob (expiry, tenant key version) and the snapshot's freshness too; the endpoint report is checked only when
    /// one is sent (start and extend).
    pub fn recheck(&self, claims: &SessionClaims, time: &TrustedTime) -> Result<(), AuthzError> {
        self.fresh(time)?;
        self.check_session(claims, time)?;
        self.check_blob(&claims.blob, time)?;
        self.still_holds(&claims.app, &claims.blob, &claims.authentication, &claims.caller, time)
    }

    /// The suspension in force for `identity` at `time`, if any: an uncleared signal about it
    /// (`WorkloadIdentity::same_subject`) whose severity maps to `Suspend`, still within its
    /// duration. Session starts, extends and
    /// live sessions all check this. Of several, the one lasting longest.
    pub(crate) fn suspension(&self, identity: &WorkloadIdentity, time: &TrustedTime) -> Option<Suspension> {
        let state = self.tenant.state();
        let policy = &state.integrity;
        self.tenant
            .signals()
            .iter()
            .filter(|s| s.identity.same_subject(identity) && s.tenant == state.tenant && policy.is_live(s, time))
            .filter_map(|s| match policy.action_for(s.severity) {
                IntegrityAction::Suspend { secs } => Some(Suspension {
                    code: s.code.clone(),
                    until: secs.map(|secs| s.observed_at.saturating_add(secs)),
                }),
                IntegrityAction::LogOnly | IntegrityAction::Deny => None,
            })
            .max_by_key(|s| s.until.map_or(UnixTime::MAX, |u| u.min(UnixTime::MAX - 1)))
    }

    /// The signal a caller raises about itself. It always names the authenticated caller, who must hold
    /// an app grant in the tenant; the enclave signs the permit's signal.
    pub fn signal(
        &self,
        request: &AuthenticatedRequest<SignalRequest>,
        time: &TrustedTime,
    ) -> Result<SignalPermit, AuthzError> {
        self.fresh(time)?;
        let state = self.tenant.state();
        let req = request.request();
        let context = req.context.as_ref().ok_or_else(|| {
            AuthzError::not_allowed("a self-signal carries its proof context")
                .with(RefusalContext::Malformed { what: "a self-signal carries its proof context".into() })
        })?;
        self.own_tenant(&context.tenant)?;
        validate_code(&req.code).map_err(|_| AuthzError::denied(ErrorCode::BadRequest, "malformed signal code"))?;
        let caller = request.caller();
        let granted = state.apps.values().any(|g| holds(caller.scope(), caller.identity(), g, time));
        if !granted {
            return Err(AuthzError::not_allowed("the caller holds no grant in the tenant")
                .with(RefusalContext::NoGrant { caller: caller.identity().clone(), apps: BTreeSet::new() }));
        }
        let signal = IntegritySignal {
            tenant: state.tenant.clone(),
            identity: caller.identity().clone(),
            source: SignalSource::Sdk,
            code: req.code.clone(),
            severity: req.severity,
            observed_at: time.now,
            blob_id: None,
        };
        Ok(SignalPermit { signal })
    }
}

/// An identity suspended under the tenant's integrity policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Suspension {
    /// The opaque code of the signal that caused it.
    pub(crate) code: String,
    /// `None` = until an admin clears the identity.
    pub(crate) until: Option<UnixTime>,
}

/// An approved seal: the fresh snapshot whose platforms and tenant key version the blob is
/// sealed under.
pub struct SealPermit<'a> {
    tenant: &'a VerifiedTenant,
}
impl SealPermit<'_> {
    pub fn tenant(&self) -> &VerifiedTenant {
        self.tenant
    }
}

/// Retains exactly the approved request, decrypted blob, decision and snapshot.
/// Session issuance consumes this permit; it must not take a second blob/secret.
pub struct SessionPermit<'a> {
    request: &'a AuthenticatedRequest<SessionRequest>,
    opened: &'a seal_crypto::blob::OpenedBlob,
    decision: SessionDecision,
    tenant: &'a VerifiedTenant,
}
impl SessionPermit<'_> {
    pub fn request(&self) -> &AuthenticatedRequest<SessionRequest> {
        self.request
    }
    pub fn opened(&self) -> &seal_crypto::blob::OpenedBlob {
        self.opened
    }
    pub fn decision(&self) -> &SessionDecision {
        &self.decision
    }
    pub fn tenant(&self) -> &VerifiedTenant {
        self.tenant
    }
}

/// An approved extension: the live session's claims and the scope of the fresh proof.
pub struct ExtendPermit<'a> {
    current: &'a SessionClaims,
    scope: seal_proto::identity::AuthenticationScope,
}
impl ExtendPermit<'_> {
    pub fn current(&self) -> &SessionClaims {
        self.current
    }
    pub fn scope(&self) -> &seal_proto::identity::AuthenticationScope {
        &self.scope
    }
}

/// An approved self-signal: the signal the enclave will sign, naming the authenticated caller.
pub struct SignalPermit {
    signal: IntegritySignal,
}
impl SignalPermit {
    pub fn signal(&self) -> &IntegritySignal {
        &self.signal
    }
}

#[cfg(test)]
mod tests;

//! Who may read and write a tenant's documents (the read matrix in the library docs).
//!
//! A request names its credential in `Authorization`:
//!
//! - `Bearer sealct_…`: a console control token (`token`), for its tenant and root chain;
//! - `Bearer <write token>`: the deployment's operator;
//! - `SealSigned <base64url(JSON SignedControlRequest)>`: signed by an admin key of the latest
//!   root (admin tools), by a telemetry key of a guardian-certified `ServiceKeyCertificate`
//!   posted for the chain (the tenant's enclaves), or by a freshness signer (`Chain::
//!   freshness_signers`: a tenant-run signer, which reads the state it signs for);
//! - `SealAttested <base64url(JSON AttestedControlRequest)>`: an enclave at boot, before the
//!   guardian released its keys. Its evidence must verify (`seal_attest::verify`), commit to the
//!   request, and come from a release stored here that passes `ReleaseVerifier` under the
//!   configured release trust (with the latest checkpoint) and is an enclave build; its TCB
//!   must meet the release policy. The request names the tenant and root id the enclave is
//!   pinned to. Such an enclave is the tenant's in all but its deployment identity, which it
//!   checks itself before requesting keys: a genuine enclave someone else pins to the tenant
//!   reads the bundle into memory nobody can inspect and stops there.
//!
//! Signed and attested requests name exactly one request (tenant, root id, method, path and
//! query, body digest) and are accepted within `CONTROL_REQUEST_MAX_AGE_SECS` of `issued_at`.
//! A missing or invalid credential is 401; a valid one this route does not admit, or one for
//! another tenant or chain, is 403.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};

use seal_crypto::sign::{admin_key_id, key_id, verify, verify_admin};
use seal_proto::codec::{from_b64url, labeled_digest};
use seal_proto::control::{
    AttestedControlRequest, ControlRequest, SignedControlRequest, ATTESTED_SCHEME, CONTROL_REQUEST_LABEL,
    CONTROL_REQUEST_MAX_AGE_SECS, SIGNED_SCHEME,
};
use seal_proto::release::Component;
use seal_proto::state::TenantRoot;
use seal_proto::{KeyId, TenantId, TenantRootId, TrustedTime};
use seal_verify::ReleaseVerifier;

use super::store::TenantDocs;
use super::token::Scope;
use super::{telemetry_keys, ApiError, ApiResult, App};

/// Who is asking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// A console member, through a control token.
    Console { user: String, scope: Scope },
    /// A request signed by an admin key of the latest root.
    Admin(KeyId),
    /// A request signed by a telemetry key certified for the tenant's chain.
    Enclave,
    /// A request signed by a freshness key of the latest state.
    FreshnessSigner,
    /// A released enclave build pinned to the tenant, holding no keys yet.
    BootingEnclave,
    /// The deployment's write token.
    Operator,
}

/// What a route admits. Admins are admitted everywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// The bundle: console members, the tenant's enclaves (also while booting), its
    /// freshness signers.
    Bundle,
    /// Documents, proposals and telemetry: console members.
    Members,
    /// Creating, signing, withdrawing and submitting proposals: console members with `submit`.
    Propose,
    /// Roots, states and release co-signatures, which carry their own admin signatures:
    /// console members with `submit`, and the write token.
    Submit,
}

impl Rule {
    pub fn admits(self, caller: &Caller) -> bool {
        matches!(
            (self, caller),
            (_, Caller::Admin(_))
                | (Rule::Bundle | Rule::Members, Caller::Console { .. })
                | (Rule::Propose | Rule::Submit, Caller::Console { scope: Scope::Submit, .. })
                | (Rule::Bundle, Caller::Enclave | Caller::BootingEnclave | Caller::FreshnessSigner)
                | (Rule::Submit, Caller::Operator)
        )
    }
}

/// The request as a credential must name it.
pub struct Asked {
    pub method: String,
    /// Path and query as received.
    pub path: String,
    pub authorization: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for Asked {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let authorization = match parts.headers.get(header::AUTHORIZATION) {
            None => None,
            Some(value) => {
                Some(value.to_str().map_err(|_| ApiError::unauthenticated("malformed authorization"))?.to_string())
            }
        };
        Ok(Self {
            method: parts.method.as_str().to_string(),
            path: parts.uri.path_and_query().map_or_else(|| parts.uri.path().to_string(), |p| p.as_str().to_string()),
            authorization,
        })
    }
}

/// The tenant a credential must be for: its chain's root id, the root whose admin keys
/// count (the latest; root version 1 itself while it is being stored), and the freshness
/// signers (the latest state's `freshness_keys`, and for the bundle those of the earlier states
/// it can carry, whose signers vouch for the latest until it is in force).
pub struct Chain<'a> {
    pub tenant: &'a TenantId,
    pub root_id: Option<TenantRootId>,
    pub admins: Option<&'a TenantRoot>,
    pub freshness_signers: Vec<seal_proto::PublicKey>,
}

impl<'a> Chain<'a> {
    pub fn of(tenant: &'a TenantId, docs: &'a TenantDocs) -> Self {
        Self {
            tenant,
            root_id: super::chain_root_id(docs),
            admins: docs.roots.last().map(|link| &link.root.body),
            freshness_signers: docs.state.iter().flat_map(|s| s.body.freshness_keys.iter().copied()).collect(),
        }
    }

    /// Also admits `signers` as freshness signers.
    pub fn with_freshness_signers(mut self, signers: impl IntoIterator<Item = seal_proto::PublicKey>) -> Self {
        self.freshness_signers.extend(signers);
        self
    }
}

fn decode<T: serde::de::DeserializeOwned>(text: &str) -> ApiResult<T> {
    let bytes = from_b64url(text).map_err(|_| ApiError::unauthenticated("credential is not base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::unauthenticated("malformed credential"))
}

impl App {
    /// The caller, if `rule` admits it for this request on `chain`.
    pub(super) async fn authorize(
        &self,
        chain: &Chain<'_>,
        docs: &TenantDocs,
        asked: &Asked,
        body: &[u8],
        rule: Rule,
    ) -> ApiResult<Caller> {
        let caller = self.authenticate(chain, docs, asked, body).await?;
        if rule.admits(&caller) {
            Ok(caller)
        } else {
            Err(ApiError::forbidden("this credential does not admit this request"))
        }
    }

    async fn authenticate(
        &self,
        chain: &Chain<'_>,
        docs: &TenantDocs,
        asked: &Asked,
        body: &[u8],
    ) -> ApiResult<Caller> {
        let authorization = asked
            .authorization
            .as_deref()
            .ok_or_else(|| ApiError::unauthenticated("this request needs a credential"))?;
        let (scheme, value) =
            authorization.split_once(' ').ok_or_else(|| ApiError::unauthenticated("malformed authorization"))?;
        let time = TrustedTime::exact(self.now());
        match scheme {
            "Bearer" if value.starts_with(super::token::PREFIX) => {
                let keys =
                    self.console.as_ref().ok_or_else(|| ApiError::unauthenticated("no console is configured"))?;
                let token = keys.verify(value, &time).map_err(|reason| {
                    tracing::info!(reason, "control token refused");
                    ApiError::unauthenticated("invalid control token")
                })?;
                if token.tenant != *chain.tenant || Some(token.root_id) != chain.root_id {
                    return Err(ApiError::forbidden("the control token is for another tenant or root chain"));
                }
                tracing::info!(tenant = %token.tenant, user = %token.user, scope = ?token.scope, "console request");
                Ok(Caller::Console { user: token.user, scope: token.scope })
            }
            "Bearer" => self.check_write_token(value).map(|()| Caller::Operator),
            SIGNED_SCHEME => {
                let mut signed: SignedControlRequest = decode(value)?;
                check_request(asked, body, &signed.body, &time)?;
                // Each signer's first signature only: a known key id repeated in the header
                // costs one verification per key, not one per copy.
                let mut signers = std::collections::BTreeSet::new();
                signed.signatures.retain(|sig| signers.insert(sig.signer));
                let admin = chain.admins.and_then(|root| {
                    signed.signatures.iter().find(|sig| {
                        let key = root.admin_keys.iter().find(|k| admin_key_id(k) == sig.signer);
                        key.is_some_and(|k| verify_admin(k, CONTROL_REQUEST_LABEL, &signed.body, sig).is_ok())
                    })
                });
                let signed_by = |keys: &[seal_proto::PublicKey]| {
                    signed.signatures.iter().any(|sig| {
                        keys.iter().any(|k| {
                            key_id(k) == sig.signer && verify(k, CONTROL_REQUEST_LABEL, &signed.body, sig).is_ok()
                        })
                    })
                };
                let caller = match admin {
                    Some(sig) => Caller::Admin(sig.signer),
                    None if signed_by(&telemetry_keys(docs, self.release_policy().await.as_ref())) => Caller::Enclave,
                    None if signed_by(&chain.freshness_signers) => Caller::FreshnessSigner,
                    None => {
                        return Err(ApiError::unauthenticated(
                            "not signed by an admin, certified telemetry or freshness key of this tenant",
                        ))
                    }
                };
                check_chain(chain, &signed.body)?;
                Ok(caller)
            }
            ATTESTED_SCHEME => {
                let attested: AttestedControlRequest = decode(value)?;
                check_request(asked, body, &attested.request, &time)?;
                self.check_attested(&attested, &time).await.map_err(|reason| {
                    tracing::info!(tenant = %chain.tenant, %reason, "attested request refused");
                    ApiError::unauthenticated("the attestation does not admit this request")
                })?;
                check_chain(chain, &attested.request)?;
                Ok(Caller::BootingEnclave)
            }
            _ => Err(ApiError::unauthenticated("unknown authorization scheme")),
        }
    }

    /// The evidence is a released enclave build's, committing to the request.
    async fn check_attested(&self, attested: &AttestedControlRequest, time: &TrustedTime) -> Result<(), String> {
        let trust = self.releases.as_ref().ok_or("attested requests are not configured")?;
        let evidence = seal_attest::verify(&attested.evidence, time).map_err(|e| e.to_string())?;
        if evidence.report_data != labeled_digest(CONTROL_REQUEST_LABEL, &attested.request) {
            return Err("the evidence does not commit to the request".into());
        }
        let mut release = self
            .store
            .release(evidence.platform, &evidence.measurement)
            .map_err(|e| e.to_string())?
            .ok_or("no release stored for this measurement")?;
        match self.latest_checkpoint().await {
            Ok(latest) if latest.checkpoint.size >= release.fresh.checkpoint.size => release.fresh = latest,
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e.message, "attested request: using the release's stored checkpoint"),
        }
        let verified = ReleaseVerifier::new(trust.clone()).verify(&release, time).map_err(|e| e.to_string())?;
        let manifest = verified.manifest();
        if manifest.component != Component::Enclave
            || manifest.platform != evidence.platform
            || manifest.measurement != evidence.measurement
        {
            return Err("not an enclave release for this measurement".into());
        }
        ReleaseVerifier::check_tcb(verified.constraints(), evidence.platform, &evidence.tcb).map_err(|e| e.to_string())
    }
}

/// The credential names exactly this request, recently.
fn check_request(asked: &Asked, body: &[u8], request: &ControlRequest, time: &TrustedTime) -> ApiResult<()> {
    let digest: [u8; 32] = Sha256::digest(body).into();
    if request.method != asked.method || request.path != asked.path || request.body_sha256 != digest {
        return Err(ApiError::unauthenticated("the credential is for another request"));
    }
    if request.issued_at.saturating_add(CONTROL_REQUEST_MAX_AGE_SECS) < time.earliest()
        || request.issued_at > time.latest().saturating_add(CONTROL_REQUEST_MAX_AGE_SECS)
    {
        return Err(ApiError::unauthenticated("the request is not recent"));
    }
    Ok(())
}

/// The request is for this tenant and chain.
fn check_chain(chain: &Chain<'_>, request: &ControlRequest) -> ApiResult<()> {
    if request.tenant != *chain.tenant || Some(request.root_id) != chain.root_id {
        return Err(ApiError::forbidden("the request is for another tenant or root chain"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_admit_exactly_the_read_matrix() {
        let read = Caller::Console { user: "u".into(), scope: Scope::Read };
        let submit = Caller::Console { user: "u".into(), scope: Scope::Submit };
        let admin = Caller::Admin(KeyId([1; 32]));
        let callers = [
            &read,
            &submit,
            &admin,
            &Caller::Enclave,
            &Caller::BootingEnclave,
            &Caller::FreshnessSigner,
            &Caller::Operator,
        ];
        let admitted = |rule: Rule| callers.iter().map(|c| rule.admits(c)).collect::<Vec<_>>();
        //                                         read   submit admin  enclave booting fresh  operator
        assert_eq!(admitted(Rule::Bundle), [true, true, true, true, true, true, false]);
        assert_eq!(admitted(Rule::Members), [true, true, true, false, false, false, false]);
        assert_eq!(admitted(Rule::Propose), [false, true, true, false, false, false, false]);
        assert_eq!(admitted(Rule::Submit), [false, true, true, false, false, false, true]);
    }
}

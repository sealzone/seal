//! Identity proofs → verified identities. Call only after `check_context`.

use std::sync::Arc;

use async_trait::async_trait;
use seal_proto::identity::WorkloadIdentity;
use seal_proto::identity::{
    AuthenticationScope, IdentityMatcher, IdentityProof, ProofAssurance, ProofContext, PROOF_CONTEXT_LABEL,
};
use seal_proto::signed::{SigAlg, Signature};
use seal_proto::{codec, TenantId, TrustedTime};

use crate::AuthzError;

mod oidc;
mod sigv4;

#[cfg(test)]
mod tests;

#[async_trait]
pub(crate) trait IdentityVerifier: Send + Sync {
    /// Verifies `proof` against `ctx` at `time` (expiry against `time.latest()`). `candidates` are the tenant's
    /// app matchers: app-key proofs need the matching public key,
    /// Azure proofs take their audience from it, and OIDC issuers outside them are never fetched.
    async fn verify(
        &self,
        proof: &IdentityProof,
        ctx: &ProofContext,
        candidates: &[IdentityMatcher],
        time: &TrustedTime,
    ) -> Result<AuthenticatedCaller, AuthzError>;
}

/// The production verifier.
/// - OIDC: discovery + JWKS over `HttpsClient` (cached 10 min, refetch on unknown `kid`),
///   RS256/ES256 only, `exp`/`nbf` with 60 s skew. Audience: Azure = matcher's `audience`,
///   others = `seal:<tenant>`. Azure issuers `https://login.microsoftonline.com/<tid>/v2.0`
///   or `https://sts.windows.net/<tid>/`; identity = (`tid`, `oid`). GitHub: identity includes
///   `repository_id` and `repository_owner_id`; Kubernetes: `kubernetes.io.serviceaccount.uid`;
///   GCP: `sub`. Token age: GitHub and Kubernetes tokens are refused when `iat` is more than
///   `MAX_OIDC_TOKEN_AGE_SECS` before `time.latest()`, so re-proving every extend means
///   something; Azure and GCP serve cached tokens, so theirs are bounded only by `exp`.
/// - AWS: checks `X-Seal-Binding` is a signed header equal to hex(context digest), host is
///   exactly `sts.amazonaws.com` (or a regional STS host), then replays the request; identity
///   includes the role's unique id from the `UserId` (`AROA…:session`).
/// - App key: Ed25519 over `labeled_digest(PROOF_CONTEXT_LABEL, ctx)`, key from `candidates`.
///
/// The authentication scope it returns holds the candidates the proof matched (for Azure, only
/// those whose `audience` is the token's), its expiry (OIDC: `exp` plus the 60 s skew; none
/// for app keys and SigV4, which are re-proven per request) and its assurance (request-bound
/// for app keys and SigV4, bearer for OIDC). A proof that matches no candidate is refused.
pub(crate) struct ProofVerifier {
    https: Arc<seal_net::HttpsClient>,
    jwks: oidc::JwksCache,
}

impl ProofVerifier {
    pub fn new(https: Arc<seal_net::HttpsClient>) -> Self {
        Self { https, jwks: oidc::JwksCache::default() }
    }

    /// `binding` is the proof context a request proof must be bound to; `None` for a
    /// deployment proof, which has nothing to bind (app-key proofs then do not count).
    async fn verify_proof(
        &self,
        proof: &IdentityProof,
        binding: Option<&ProofContext>,
        tenant: &TenantId,
        candidates: &[IdentityMatcher],
        time: &TrustedTime,
    ) -> Result<AuthenticatedCaller, AuthzError> {
        match proof {
            IdentityProof::AppKey { key_id, signature } => {
                let ctx = binding.ok_or(AuthzError::BadProof("an app key cannot prove a deployment"))?;
                verify_app_key(key_id, signature, ctx, candidates)
            }
            IdentityProof::Oidc { provider, jwt } => {
                oidc::verify(&self.https, &self.jwks, *provider, jwt.expose(), tenant, candidates, time).await
            }
            IdentityProof::AwsSigV4 { method, url, headers, body } => {
                let binding = binding.map(|ctx| codec::labeled_digest(PROOF_CONTEXT_LABEL, ctx));
                let call = sigv4::check(method, url, headers, body, binding.as_ref())?;
                let identity = sigv4::replay(&self.https, &call).await?;
                caller(identity, candidates, None, ProofAssurance::RequestBound, |_| true)
            }
        }
    }
}

#[async_trait]
impl IdentityVerifier for ProofVerifier {
    async fn verify(
        &self,
        proof: &IdentityProof,
        ctx: &ProofContext,
        candidates: &[IdentityMatcher],
        time: &TrustedTime,
    ) -> Result<AuthenticatedCaller, AuthzError> {
        self.verify_proof(proof, Some(ctx), &ctx.tenant, candidates, time).await
    }
}

/// The caller for a verified `identity`: the candidates it matches (and `also` accepts), or
/// `NotAllowed` when there are none.
fn caller(
    identity: WorkloadIdentity,
    candidates: &[IdentityMatcher],
    expires_at: Option<seal_proto::UnixTime>,
    assurance: ProofAssurance,
    also: impl Fn(&IdentityMatcher) -> bool,
) -> Result<AuthenticatedCaller, AuthzError> {
    let mut matched_grants: Vec<IdentityMatcher> =
        candidates.iter().filter(|m| m.matches(&identity) && also(m)).cloned().collect();
    matched_grants.sort();
    matched_grants.dedup();
    if matched_grants.is_empty() {
        return Err(AuthzError::not_allowed("no grant matches the caller"));
    }
    Ok(AuthenticatedCaller { identity, scope: AuthenticationScope { matched_grants, expires_at, assurance } })
}

fn verify_app_key(
    key_id: &seal_proto::KeyId,
    signature: &[u8],
    ctx: &ProofContext,
    candidates: &[IdentityMatcher],
) -> Result<AuthenticatedCaller, AuthzError> {
    let public_key = candidates
        .iter()
        .find_map(|m| match m {
            IdentityMatcher::AppKey { key_id: k, public_key }
                if k == key_id && seal_crypto::sign::key_id(public_key) == *k =>
            {
                Some(*public_key)
            }
            _ => None,
        })
        .ok_or(AuthzError::not_allowed("no grant names this app key"))?;
    let sig = Signature { signer: *key_id, alg: SigAlg::Ed25519 { sig: signature.to_vec() } };
    seal_crypto::sign::verify(&public_key, PROOF_CONTEXT_LABEL, ctx, &sig)
        .map_err(|_| AuthzError::BadProof("app key signature does not verify for this context"))?;
    caller(WorkloadIdentity::AppKey { key_id: *key_id }, candidates, None, ProofAssurance::RequestBound, |_| true)
}

/// GitHub and Kubernetes OIDC tokens older than this are refused. The SDK requests a fresh
/// GitHub token per proof; Kubernetes projected tokens need `expirationSeconds: 600`.
pub const MAX_OIDC_TOKEN_AGE_SECS: u64 = 600;

/// How a deployment shows its identity.
pub enum DeploymentProof {
    /// A proof checked here, OIDC or SigV4 (`X-Seal-Binding` is not required: nothing to bind).
    Proof(IdentityProof),
    /// An identity the enclave's own verified evidence carries
    /// (`seal_attest::VerifiedEvidence::deployment`). Produced by `seal-cloud` from the
    /// enclave's own attestation only, never from anything received.
    Attested(WorkloadIdentity),
}

/// Checks the enclave deployment's own identity before it requests any tenant key; it must
/// match one of `TenantState::deployments`. A genuine enclave someone deployed for a tenant
/// that never authorized it therefore holds none of that tenant's keys, and only its boot
/// path, not its adapters, is exposed before this check. The guardian does not repeat it (it
/// has no network).
pub struct DeploymentVerifier {
    proofs: ProofVerifier,
}

impl DeploymentVerifier {
    pub fn new(https: Arc<seal_net::HttpsClient>) -> Self {
        Self { proofs: ProofVerifier::new(https) }
    }
    /// `NotAllowed` unless `proof` is an OIDC or SigV4 proof valid at `time`, or an attested
    /// identity, and matches a `deployments` entry. OIDC audiences are as for requests: an
    /// Azure entry's `audience`, `seal:<tenant>` otherwise.
    pub async fn verify(
        &self,
        proof: &DeploymentProof,
        tenant: &seal_verify::VerifiedTenant,
        time: &TrustedTime,
    ) -> Result<WorkloadIdentity, AuthzError> {
        let state = tenant.state();
        let deployments: Vec<IdentityMatcher> = state.deployments.iter().cloned().collect();
        match proof {
            DeploymentProof::Attested(identity) => {
                if deployments.iter().any(|m| m.matches(identity)) {
                    Ok(identity.clone())
                } else {
                    Err(AuthzError::not_allowed("deployment identity is not in the tenant's deployments"))
                }
            }
            DeploymentProof::Proof(IdentityProof::AppKey { .. }) => {
                Err(AuthzError::not_allowed("an app key cannot prove a deployment"))
            }
            DeploymentProof::Proof(proof) => {
                let caller = self.proofs.verify_proof(proof, None, &state.tenant, &deployments, time).await?;
                Ok(caller.identity)
            }
        }
    }
}

/// Full proof scope is retained for authorization and later session rechecks.
/// In particular, Azure audience must not be lost when matching grants.
#[derive(Clone, Debug)]
pub struct AuthenticatedCaller {
    pub(crate) identity: WorkloadIdentity,
    pub(crate) scope: seal_proto::identity::AuthenticationScope,
}

impl AuthenticatedCaller {
    pub fn identity(&self) -> &WorkloadIdentity {
        &self.identity
    }
    pub fn scope(&self) -> &seal_proto::identity::AuthenticationScope {
        &self.scope
    }
}

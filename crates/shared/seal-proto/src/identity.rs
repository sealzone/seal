//! Workload identities: who a producer or app is, and how it proves it.

use serde::{Deserialize, Serialize};

use crate::{codec, Bearer, KeyId, PublicKey, TenantId, UnixTime};

/// A verified identity. Produced only by `seal-authz` after checking an
/// `IdentityProof`; never trusted when it arrives over the wire.
/// Every kind carries the provider's immutable id. Names are kept for display only: a deleted
/// role, account or repository can be recreated under the same name by someone else.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkloadIdentity {
    /// Azure managed identity (VM, ACI, App Service, AKS workload identity). `object_id` is immutable.
    Azure { entra_tenant: String, object_id: String },
    /// AWS IAM role, from STS GetCallerIdentity. `role_id` is the role's unique id (`AROA…`,
    /// the `UserId` prefix), which a recreated role does not keep.
    AwsRole { account: String, role_arn: String, role_id: String },
    /// Kubernetes service account, from a projected OIDC token. `service_account_uid` is the
    /// token's `kubernetes.io.serviceaccount.uid`, which a recreated account does not keep.
    Kubernetes { issuer: String, namespace: String, service_account: String, service_account_uid: String },
    /// GCP service account. `unique_id` is the token's `sub`.
    Gcp { email: String, unique_id: String },
    /// GitHub Actions OIDC token. `repository_id` and `repository_owner_id` survive renames and
    /// are never reused.
    GitHub {
        repository: String,
        repository_id: u64,
        repository_owner_id: u64,
        environment: Option<String>,
        git_ref: String,
    },
    /// A `SEAL_APP_KEY` (Ed25519). `key_id` is the hash of its public key.
    AppKey { key_id: KeyId },
    /// A Confidential Space workload, from its verified attestation token (never from a
    /// proof): `submods.gce.project_number`, which GCP never reuses, and the VM's service
    /// account. Used as an enclave deployment identity.
    ConfidentialSpace { project_number: u64, service_account: String },
}

/// A rule in a tenant's signed state that a `WorkloadIdentity` either matches
/// or not. Exact matches only: no wildcards, so a grant never widens by accident. Matching
/// uses the immutable ids; names are what the CLI resolved them from and shows admins.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdentityMatcher {
    /// `audience` is the Entra app ID URI the tenant registered for Seal
    /// (managed identities can only get tokens for registered resources).
    Azure {
        entra_tenant: String,
        object_id: String,
        audience: String,
        /// Set only on the `deployments` entry of Seal's hosted identity for the tenant (the
        /// managed identity of the tenant's ACI groups in Seal's subscription); see `HostedMode`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hosted: Option<HostedMode>,
    },
    AwsRole {
        role_arn: String,
        role_id: String,
    },
    Kubernetes {
        issuer: String,
        namespace: String,
        service_account: String,
        service_account_uid: String,
    },
    Gcp {
        email: String,
        unique_id: String,
    },
    /// Repository alone is never enough: an environment or an exact ref is required.
    GitHub {
        repository: String,
        repository_id: u64,
        repository_owner_id: u64,
        scope: GitHubScope,
    },
    AppKey {
        key_id: KeyId,
        public_key: PublicKey,
    },
    ConfidentialSpace {
        project_number: u64,
        service_account: String,
        /// Set only on the `deployments` entry of Seal's hosted identity for the tenant (Seal's
        /// project and the tenant's own service account there); see `HostedMode`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hosted: Option<HostedMode>,
    },
}

/// The Seal-hosted mark on a `deployments` entry (`hosted` on `IdentityMatcher::Azure` and
/// `IdentityMatcher::ConfidentialSpace`): the tenant's consent to Seal running replicas for it
/// under that identity. A marked replica seals and serves sessions like the tenant's own and
/// exits when idle; an unmarked one never idles out. Signed by the tenant's admins, so neither
/// Seal nor the host can mark a customer's own replica as hosted. One value, written
/// `"sessions"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedMode {
    Sessions,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubScope {
    Environment(String),
    Ref(String),
}

impl IdentityMatcher {
    pub fn matches(&self, id: &WorkloadIdentity) -> bool {
        use IdentityMatcher as M;
        use WorkloadIdentity as W;
        match (self, id) {
            (M::Azure { entra_tenant: t, object_id: o, .. }, W::Azure { entra_tenant, object_id }) => {
                t == entra_tenant && o == object_id
            }
            (M::AwsRole { role_id: r, .. }, W::AwsRole { role_id, .. }) => r == role_id,
            (
                M::Kubernetes { issuer: i, service_account_uid: u, .. },
                W::Kubernetes { issuer, service_account_uid, .. },
            ) => i == issuer && u == service_account_uid,
            (M::Gcp { unique_id: u, .. }, W::Gcp { unique_id, .. }) => u == unique_id,
            (
                M::GitHub { repository_id: r, repository_owner_id: o, scope, .. },
                W::GitHub { repository_id, repository_owner_id, environment, git_ref, .. },
            ) => {
                r == repository_id
                    && o == repository_owner_id
                    && match scope {
                        GitHubScope::Environment(e) => environment.as_deref() == Some(e.as_str()),
                        GitHubScope::Ref(want) => want == git_ref,
                    }
            }
            (M::AppKey { key_id: k, .. }, W::AppKey { key_id }) => k == key_id,
            (
                M::ConfidentialSpace { project_number: p, service_account: s, .. },
                W::ConfidentialSpace { project_number, service_account },
            ) => p == project_number && s == service_account,
            _ => false,
        }
    }

    /// The Seal-hosted mark of a `deployments` entry: `Some` only on Seal's hosted identity.
    pub fn hosted(&self) -> Option<HostedMode> {
        match self {
            IdentityMatcher::Azure { hosted, .. } | IdentityMatcher::ConfidentialSpace { hosted, .. } => *hosted,
            _ => None,
        }
    }
}

/// What every identity proof is bound to, so a proof captured for one call
/// cannot be replayed for another. `labeled_digest(PROOF_CONTEXT_LABEL, ctx)`
/// is what app-key proofs sign and SigV4 proofs carry in `X-Seal-Binding`.
/// OIDC JWTs cannot embed it: they are bound only by arriving over the
/// attested TLS channel, within the JWT's own validity (documented limit).
/// The enclave checks every field with `seal_authz::RequestAuthenticator`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofContext {
    pub tenant: TenantId,
    pub purpose: ProofPurpose,
    /// SHA-256 of the enclave's inbound TLS SubjectPublicKeyInfo DER, as in
    /// `AttestationBinding::tls_spki_sha256`. Shared by the tenant's replicas of a service key version.
    #[serde(with = "codec::array_b64")]
    pub tls_spki_sha256: [u8; 32],
    /// From `POST /v1/tickets`: stateless, MAC'd by the enclave's ticket key, reusable until expiry.
    pub ticket: crate::freshness::ProofTicket,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProofPurpose {
    /// Binds the complete encrypted upload; computed by SealRequest::expected_purpose.
    Seal {
        #[serde(with = "codec::array_b64")]
        request_digest: [u8; 32],
    },
    /// Binds the full blob and options; computed by SessionRequest::expected_purpose.
    Session {
        #[serde(with = "codec::array_b64")]
        request_digest: [u8; 32],
    },
    /// Binds an extension; computed by ExtendRequest::expected_purpose.
    Extend {
        #[serde(with = "codec::array_b64")]
        request_digest: [u8; 32],
    },
    /// Binds a self-signal; computed by SignalRequest::expected_purpose.
    Signal {
        #[serde(with = "codec::array_b64")]
        request_digest: [u8; 32],
    },
}

pub const PROOF_CONTEXT_LABEL: &str = "seal/proof-context/v1";

/// How a caller proves its identity. Verified only inside the enclave.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdentityProof {
    /// An OIDC JWT (Azure managed identity, Kubernetes, GCP, GitHub Actions).
    /// Audience per provider: Azure = the matcher's `audience`; others = `seal:<tenant>`.
    Oidc { provider: OidcProvider, jwt: Bearer },
    /// A presigned STS GetCallerIdentity request whose signed headers include
    /// `X-Seal-Binding: hex(labeled_digest(PROOF_CONTEXT_LABEL, ctx))`.
    /// Replayed by the enclave to `sts.amazonaws.com` only.
    AwsSigV4 { method: String, url: String, headers: Vec<(String, Bearer)>, body: String },
    /// Ed25519 signature by a `SEAL_APP_KEY` over `labeled_digest(PROOF_CONTEXT_LABEL, ctx)`.
    AppKey {
        key_id: KeyId,
        #[serde(with = "codec::bytes_b64")]
        signature: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcProvider {
    Azure,
    Kubernetes,
    Gcp,
    GitHub,
}

/// Persisted inside encrypted session claims. Grant rechecks must match the full
/// originally authenticated matcher (including audience), not just identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationScope {
    pub matched_grants: Vec<IdentityMatcher>,
    pub expires_at: Option<UnixTime>,
    pub assurance: ProofAssurance,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofAssurance {
    RequestBound,
    BearerOverAttestedChannel,
}

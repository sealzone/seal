//! OIDC ID tokens: issuer routing, discovery and JWKS, signature and claims.
//!
//! The issuer is read from the unverified token only to pick keys, and only an issuer the
//! tenant's matchers name is ever fetched: Azure `login.microsoftonline.com/<tid>/v2.0` or
//! `sts.windows.net/<tid>/` for a `tid` some Azure matcher names, GitHub's and Google's
//! issuers when a GitHub or GCP matcher exists, a Kubernetes matcher's exact `issuer`. Azure,
//! GitHub and GCP sign with RS256; a Kubernetes issuer's algorithm is its key's type (RSA →
//! RS256, P-256 → ES256). Discovery (`<issuer>/.well-known/openid-configuration`, for v1 Azure
//! issuers the tenant's `login.microsoftonline.com` document) must name the same issuer.
//! Key sets are cached per issuer for `JWKS_CACHE_SECS` and refetched early when a token names
//! an unknown `kid`, at most once per `JWKS_REFETCH_MIN_SECS`.

use seal_proto::telemetry::{Dependency, RefusalContext};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use seal_crypto::jws::{self, JwkSet, JwsAlg};
use seal_proto::identity::{IdentityMatcher, OidcProvider, ProofAssurance, WorkloadIdentity};
use seal_proto::{TenantId, TrustedTime, UnixTime};
use serde_json::Value;

use super::{caller, AuthenticatedCaller, MAX_OIDC_TOKEN_AGE_SECS};
use crate::AuthzError;

/// How long a fetched key set is used.
pub(crate) const JWKS_CACHE_SECS: u64 = 600;
/// Least time between two fetches of one issuer's keys when a token names an unknown `kid`.
pub(crate) const JWKS_REFETCH_MIN_SECS: u64 = 30;
/// Allowed clock difference to the issuer for `exp`, `nbf` and `iat`.
pub(crate) const OIDC_SKEW_SECS: u64 = 60;

pub(crate) const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub(crate) const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const AZURE_V2_PREFIX: &str = "https://login.microsoftonline.com/";
const AZURE_V1_PREFIX: &str = "https://sts.windows.net/";

struct Cached {
    keys: Arc<JwkSet>,
    fetched_at: UnixTime,
}

/// Key sets by issuer.
#[derive(Default)]
pub(crate) struct JwksCache {
    by_issuer: Mutex<HashMap<String, Cached>>,
}

impl JwksCache {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Cached>> {
        self.by_issuer.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The cached set for `issuer`, if it may still be used for a token naming `kid`.
    fn usable(&self, issuer: &str, kid: Option<&str>, now: UnixTime) -> Option<Arc<JwkSet>> {
        let cache = self.lock();
        let c = cache.get(issuer)?;
        let age = now.checked_sub(c.fetched_at)?;
        if age >= JWKS_CACHE_SECS {
            return None;
        }
        (c.keys.find(kid).is_some() || age < JWKS_REFETCH_MIN_SECS).then(|| c.keys.clone())
    }

    fn store(&self, issuer: &str, keys: Arc<JwkSet>, now: UnixTime) {
        self.lock().insert(issuer.to_string(), Cached { keys, fetched_at: now });
    }
}

/// Where an accepted issuer's keys come from, and its algorithm (`None` = the key's own).
struct Issuer {
    discovery: String,
    alg: Option<JwsAlg>,
}

fn str_claim<'a>(claims: &'a Value, name: &str) -> Option<&'a str> {
    claims.get(name).and_then(Value::as_str)
}

/// A numeric date (RFC 7519): a non-negative number, fractions truncated.
fn time_claim(claims: &Value, name: &str) -> Result<Option<UnixTime>, AuthzError> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_f64().filter(|f| f.is_finite() && *f >= 0.0).map(|f| f as u64))
            .map(Some)
            .ok_or(AuthzError::BadProof("token has a malformed time claim")),
    }
}

/// GitHub writes its numeric ids as strings; accept either form.
fn id_claim(claims: &Value, name: &str) -> Result<u64, AuthzError> {
    let v = claims.get(name).ok_or(AuthzError::BadProof("token lacks a GitHub id claim"))?;
    v.as_u64()
        .or_else(|| {
            v.as_str().filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).and_then(|s| s.parse().ok())
        })
        .ok_or(AuthzError::BadProof("token has a malformed GitHub id claim"))
}

fn audiences(claims: &Value) -> Vec<&str> {
    match claims.get("aud") {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    }
}

/// The Azure tenant id in an Azure issuer.
fn azure_tid(iss: &str) -> Option<&str> {
    let tid = iss
        .strip_prefix(AZURE_V2_PREFIX)
        .and_then(|rest| rest.strip_suffix("/v2.0"))
        .or_else(|| iss.strip_prefix(AZURE_V1_PREFIX).and_then(|rest| rest.strip_suffix('/')))?;
    let ok = !tid.is_empty() && tid.len() <= 64 && tid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    ok.then_some(tid)
}

/// The issuer plan for `iss`, if the tenant's candidates name it for `provider`.
fn issuer(provider: OidcProvider, iss: &str, candidates: &[IdentityMatcher]) -> Option<Issuer> {
    let well_known = |base: &str| format!("{}/.well-known/openid-configuration", base.trim_end_matches('/'));
    match provider {
        OidcProvider::Azure => {
            let tid = azure_tid(iss)?;
            candidates
                .iter()
                .any(|m| matches!(m, IdentityMatcher::Azure { entra_tenant, .. } if entra_tenant == tid))
                .then(|| {
                    let discovery = if iss.starts_with(AZURE_V1_PREFIX) {
                        format!("{AZURE_V2_PREFIX}{tid}/.well-known/openid-configuration")
                    } else {
                        well_known(iss)
                    };
                    Issuer { discovery, alg: Some(JwsAlg::Rs256) }
                })
        }
        OidcProvider::GitHub => (iss == GITHUB_ISSUER
            && candidates.iter().any(|m| matches!(m, IdentityMatcher::GitHub { .. })))
        .then(|| Issuer { discovery: well_known(iss), alg: Some(JwsAlg::Rs256) }),
        OidcProvider::Gcp => (iss == GOOGLE_ISSUER
            && candidates.iter().any(|m| matches!(m, IdentityMatcher::Gcp { .. })))
        .then(|| Issuer { discovery: well_known(iss), alg: Some(JwsAlg::Rs256) }),
        OidcProvider::Kubernetes => (iss.starts_with("https://")
            && candidates.iter().any(|m| matches!(m, IdentityMatcher::Kubernetes { issuer, .. } if issuer == iss)))
        .then(|| Issuer { discovery: well_known(iss), alg: None }),
    }
}

/// Discovery document, then its `jwks_uri`.
async fn fetch(https: &seal_net::HttpsClient, iss: &str, discovery: &str) -> Result<JwkSet, AuthzError> {
    let unavailable = |what: &str| AuthzError::Unavailable(Dependency::Issuer, format!("OIDC issuer {iss}: {what}"));
    let get = |url: String| async move {
        let (status, body) =
            https.get(&url, &[("accept", "application/json")]).await.map_err(|e| unavailable(&e.to_string()))?;
        if status != 200 {
            return Err(unavailable(&format!("HTTP {status}")));
        }
        Ok(body)
    };
    let doc: Value = serde_json::from_slice(&get(discovery.to_string()).await?)
        .map_err(|_| unavailable("discovery document is not JSON"))?;
    if str_claim(&doc, "issuer") != Some(iss) {
        return Err(unavailable("discovery document names another issuer"));
    }
    let jwks_uri = str_claim(&doc, "jwks_uri").ok_or_else(|| unavailable("discovery document has no jwks_uri"))?;
    JwkSet::from_json(&get(jwks_uri.to_string()).await?).map_err(|_| unavailable("jwks_uri is not a JWK set"))
}

async fn keys(
    https: &seal_net::HttpsClient,
    cache: &JwksCache,
    iss: &str,
    plan: &Issuer,
    kid: Option<&str>,
    time: &TrustedTime,
) -> Result<Arc<JwkSet>, AuthzError> {
    if let Some(keys) = cache.usable(iss, kid, time.now) {
        return Ok(keys);
    }
    let keys = Arc::new(fetch(https, iss, &plan.discovery).await?);
    cache.store(iss, keys.clone(), time.now);
    Ok(keys)
}

/// Verifies an OIDC proof; see the module docs and `ProofVerifier`.
pub(crate) async fn verify(
    https: &seal_net::HttpsClient,
    cache: &JwksCache,
    provider: OidcProvider,
    jwt: &str,
    tenant: &TenantId,
    candidates: &[IdentityMatcher],
    time: &TrustedTime,
) -> Result<AuthenticatedCaller, AuthzError> {
    let unverified: Value = jws::peek_payload(jwt)
        .ok()
        .and_then(|p| serde_json::from_slice(&p).ok())
        .ok_or(AuthzError::BadProof("not a JWT"))?;
    let iss = str_claim(&unverified, "iss").ok_or(AuthzError::BadProof("token has no issuer"))?.to_string();
    let plan =
        issuer(provider, &iss, candidates).ok_or(AuthzError::BadProof("token issuer is not one the tenant names"))?;
    let header = jws::peek_header(jwt).map_err(|_| AuthzError::BadProof("not a JWT"))?;
    let keys = keys(https, cache, &iss, &plan, header.kid.as_deref(), time).await?;
    let key = keys.find(header.kid.as_deref()).ok_or(AuthzError::BadProof("token names an unknown key"))?;
    let alg = plan.alg.unwrap_or(key.alg());
    let payload = jws::verify(jwt, key, alg).map_err(|_| AuthzError::BadProof("token signature does not verify"))?;
    let claims: Value =
        serde_json::from_slice(&payload).map_err(|_| AuthzError::BadProof("token claims are not JSON"))?;
    if !claims.is_object() || str_claim(&claims, "iss") != Some(iss.as_str()) {
        return Err(AuthzError::BadProof("token issuer changed"));
    }

    let exp = time_claim(&claims, "exp")?.ok_or(AuthzError::BadProof("token has no expiry"))?;
    let expires_at = exp.saturating_add(OIDC_SKEW_SECS);
    if time.latest() >= expires_at {
        return Err(
            AuthzError::not_allowed("token expired").with(RefusalContext::TokenExpired { expired_at: expires_at })
        );
    }
    let not_before = |name| -> Result<Option<UnixTime>, AuthzError> {
        let t = time_claim(&claims, name)?;
        if t.is_some_and(|t| t > time.earliest().saturating_add(OIDC_SKEW_SECS)) {
            return Err(AuthzError::BadProof("token not valid yet"));
        }
        Ok(t)
    };
    not_before("nbf")?;
    let iat = not_before("iat")?;
    let fresh = || -> Result<(), AuthzError> {
        let iat = iat.ok_or(AuthzError::BadProof("token has no issue time"))?;
        if time.latest() > iat.saturating_add(MAX_OIDC_TOKEN_AGE_SECS) {
            return Err(AuthzError::BadProof("token too old"));
        }
        Ok(())
    };

    let aud = audiences(&claims);
    let seal_audience = format!("seal:{tenant}");
    let bearer = ProofAssurance::BearerOverAttestedChannel;
    let need = |name: &str| {
        str_claim(&claims, name).filter(|s| !s.is_empty()).ok_or(AuthzError::BadProof("token lacks an identity claim"))
    };
    let seal_aud = || {
        if aud.contains(&seal_audience.as_str()) {
            Ok(())
        } else {
            Err(AuthzError::BadProof("token audience is not this tenant"))
        }
    };

    match provider {
        OidcProvider::Azure => {
            let tid = azure_tid(&iss).expect("routed as Azure");
            if need("tid")? != tid {
                return Err(AuthzError::BadProof("token tid disagrees with its issuer"));
            }
            let identity =
                WorkloadIdentity::Azure { entra_tenant: tid.to_string(), object_id: need("oid")?.to_string() };
            // The audience comes from the matched entry: only entries for this audience count.
            caller(
                identity,
                candidates,
                Some(expires_at),
                bearer,
                |m| matches!(m, IdentityMatcher::Azure { audience, .. } if aud.contains(&audience.as_str())),
            )
            .map_err(|e| {
                let denied = AuthzError::not_allowed("no grant matches the caller and token audience");
                match e.context() {
                    Some(context) => denied.with(context),
                    None => denied,
                }
            })
        }
        OidcProvider::GitHub => {
            seal_aud()?;
            fresh()?;
            let environment = match claims.get("environment") {
                None | Some(Value::Null) => None,
                Some(Value::String(e)) => Some(e.clone()),
                Some(_) => return Err(AuthzError::BadProof("token has a malformed environment")),
            };
            let identity = WorkloadIdentity::GitHub {
                repository: need("repository")?.to_string(),
                repository_id: id_claim(&claims, "repository_id")?,
                repository_owner_id: id_claim(&claims, "repository_owner_id")?,
                environment,
                git_ref: need("ref")?.to_string(),
            };
            caller(identity, candidates, Some(expires_at), bearer, |_| true)
        }
        OidcProvider::Kubernetes => {
            seal_aud()?;
            fresh()?;
            let k8s = claims.get("kubernetes.io").ok_or(AuthzError::BadProof("token lacks kubernetes.io claims"))?;
            let sa = k8s.get("serviceaccount");
            let field = |v: Option<&Value>| {
                v.and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .ok_or(AuthzError::BadProof("token lacks a service account claim"))
            };
            let namespace = field(k8s.get("namespace"))?;
            let service_account = field(sa.and_then(|s| s.get("name")))?;
            let service_account_uid = field(sa.and_then(|s| s.get("uid")))?;
            if need("sub")? != format!("system:serviceaccount:{namespace}:{service_account}") {
                return Err(AuthzError::BadProof("token subject disagrees with its service account"));
            }
            let identity =
                WorkloadIdentity::Kubernetes { issuer: iss.clone(), namespace, service_account, service_account_uid };
            caller(identity, candidates, Some(expires_at), bearer, |_| true)
        }
        OidcProvider::Gcp => {
            seal_aud()?;
            if claims.get("email_verified").is_some_and(|v| v != &Value::Bool(true)) {
                return Err(AuthzError::BadProof("token email is not verified"));
            }
            let identity =
                WorkloadIdentity::Gcp { email: need("email")?.to_string(), unique_id: need("sub")?.to_string() };
            caller(identity, candidates, Some(expires_at), bearer, |_| true)
        }
    }
}

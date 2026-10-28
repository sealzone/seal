//! Identity proofs against a local HTTPS server with recorded discovery, JWKS and STS answers.

use std::sync::Arc;

use serde_json::{json, Value};

use super::*;
use crate::request::RequestAuthenticator;
use crate::testing::*;
use seal_proto::api::{ExtendRequest, SealRequest, SessionRequest, SignalRequest};
use seal_proto::codec::b64url;
use seal_proto::identity::{GitHubScope, OidcProvider, ProofPurpose};
use seal_proto::integrity::Severity;
use seal_proto::{Bearer, ErrorCode, ServiceKeyVersion, UnixTime};

// ---- keys and tokens ----

const RSA_N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
const RSA_D: &str = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";
const RSA_P: &str = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc";
const RSA_Q: &str = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";
const EC_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

#[derive(Clone, Copy)]
enum Signer {
    Rsa,
    Ec,
}

fn d(s: &str) -> Vec<u8> {
    seal_proto::codec::from_b64url(s).unwrap()
}

fn ec_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&d(EC_D)).unwrap()
}

/// A JWT over `header` and `claims`, signed with the test RSA or P-256 key.
fn jwt(header: Value, claims: &Value, signer: Signer) -> String {
    use rsa::signature::Signer as _;
    let input = format!("{}.{}", b64url(header.to_string().as_bytes()), b64url(claims.to_string().as_bytes()));
    let sig = match signer {
        Signer::Rsa => {
            let uint = |s: &str| rsa::BoxedUint::from_be_slice(&d(s), 2048).unwrap();
            let key = rsa::RsaPrivateKey::from_components(
                uint(RSA_N),
                uint("AQAB"),
                uint(RSA_D),
                vec![uint(RSA_P), uint(RSA_Q)],
            )
            .unwrap();
            Box::<[u8]>::from(rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key).sign(input.as_bytes())).to_vec()
        }
        Signer::Ec => {
            let s: p256::ecdsa::Signature = ec_key().sign(input.as_bytes());
            s.to_bytes().to_vec()
        }
    };
    format!("{input}.{}", b64url(&sig))
}

fn rs256(kid: &str) -> Value {
    json!({"alg": "RS256", "kid": kid, "typ": "JWT"})
}
fn es256(kid: &str) -> Value {
    json!({"alg": "ES256", "kid": kid})
}

fn jwks(rsa_kid: &str) -> Vec<u8> {
    let point = ec_key().verifying_key().to_sec1_point(false);
    json!({"keys": [
        {"kty": "RSA", "kid": rsa_kid, "use": "sig", "n": RSA_N, "e": "AQAB"},
        {"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": b64url(point.x().unwrap()), "y": b64url(point.y().unwrap())},
    ]})
    .to_string()
    .into_bytes()
}

const TID: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
const K8S_ISSUER: &str = "https://k8s.example.com";

fn azure_v2() -> String {
    format!("https://login.microsoftonline.com/{TID}/v2.0")
}
fn azure_v1() -> String {
    format!("https://sts.windows.net/{TID}/")
}

/// Discovery and JWKS for every issuer the tests use.
async fn issuers() -> Server {
    let s = server().await;
    let r = &s.routes;
    let doc = |iss: &str, jwks_uri: &str| json!({"issuer": iss, "jwks_uri": jwks_uri}).to_string();
    let ms = "login.microsoftonline.com";
    r.set(
        ms,
        &format!("/{TID}/v2.0/.well-known/openid-configuration"),
        200,
        doc(&azure_v2(), &format!("https://{ms}/{TID}/discovery/v2.0/keys")),
    );
    r.set(
        ms,
        &format!("/{TID}/.well-known/openid-configuration"),
        200,
        doc(&azure_v1(), &format!("https://{ms}/{TID}/discovery/keys")),
    );
    r.set(ms, &format!("/{TID}/discovery/v2.0/keys"), 200, jwks("rsa-1"));
    r.set(ms, &format!("/{TID}/discovery/keys"), 200, jwks("rsa-1"));
    let gh = "token.actions.githubusercontent.com";
    r.set(
        gh,
        "/.well-known/openid-configuration",
        200,
        doc(oidc::GITHUB_ISSUER, &format!("https://{gh}/.well-known/jwks")),
    );
    r.set(gh, "/.well-known/jwks", 200, jwks("rsa-1"));
    r.set(
        "accounts.google.com",
        "/.well-known/openid-configuration",
        200,
        doc(oidc::GOOGLE_ISSUER, "https://www.googleapis.com/oauth2/v3/certs"),
    );
    r.set("www.googleapis.com", "/oauth2/v3/certs", 200, jwks("rsa-1"));
    r.set(
        "k8s.example.com",
        "/.well-known/openid-configuration",
        200,
        doc(K8S_ISSUER, &format!("{K8S_ISSUER}/openid/v1/jwks")),
    );
    r.set("k8s.example.com", "/openid/v1/jwks", 200, jwks("rsa-1"));
    s
}

fn ctx() -> ProofContext {
    ProofContext {
        tenant: acme(),
        purpose: ProofPurpose::Session { request_digest: [3; 32] },
        tls_spki_sha256: [4; 32],
        ticket: seal_proto::freshness::ProofTicket { value: [0; 32], expires_at: 0, mac: [0; 32] },
    }
}

fn oidc(provider: OidcProvider, token: String) -> IdentityProof {
    IdentityProof::Oidc { provider, jwt: Bearer::new(token) }
}

async fn check(
    v: &ProofVerifier,
    proof: &IdentityProof,
    candidates: &[IdentityMatcher],
    time: UnixTime,
) -> Result<AuthenticatedCaller, AuthzError> {
    v.verify(proof, &ctx(), candidates, &at(time)).await
}

fn refused(r: Result<AuthenticatedCaller, AuthzError>) -> AuthzError {
    match r {
        Ok(c) => panic!("accepted {:?}", c.identity()),
        Err(e) => e,
    }
}

fn is_bad_proof(e: &AuthzError) -> bool {
    matches!(e, AuthzError::BadProof(_))
}

// ---- app keys ----

#[tokio::test]
async fn app_key_proofs_bind_their_context() {
    let s = server().await;
    let v = ProofVerifier::new(s.https.clone());
    let k = key(42);
    let (m, id) = app_key(42);
    let sign = |ctx: &ProofContext| {
        let SigAlg::Ed25519 { sig } = k.sign(PROOF_CONTEXT_LABEL, ctx).alg else { unreachable!() };
        IdentityProof::AppKey { key_id: k.key_id(), signature: sig }
    };
    let proof = sign(&ctx());
    let c = check(&v, &proof, &[m.clone(), app_key(43).0], T).await.unwrap();
    assert_eq!(c.identity(), &id);
    assert_eq!(c.scope().matched_grants, vec![m.clone()]);
    assert_eq!(c.scope().assurance, ProofAssurance::RequestBound);
    assert_eq!(c.scope().expires_at, None);

    // A proof for another context (another request) is refused.
    let mut other = ctx();
    other.purpose = ProofPurpose::Session { request_digest: [9; 32] };
    assert!(is_bad_proof(&refused(check(&v, &sign(&other), std::slice::from_ref(&m), T).await)));
    // Another key's signature under this key id.
    let SigAlg::Ed25519 { sig } = key(43).sign(PROOF_CONTEXT_LABEL, &ctx()).alg else { unreachable!() };
    let forged = IdentityProof::AppKey { key_id: k.key_id(), signature: sig };
    assert!(is_bad_proof(&refused(check(&v, &forged, std::slice::from_ref(&m), T).await)));
    // No candidate holds the key.
    assert_eq!(refused(check(&v, &proof, &[app_key(43).0], T).await).code(), ErrorCode::NotAllowed);
    // A candidate whose key id does not belong to its public key.
    let liar = IdentityMatcher::AppKey { key_id: k.key_id(), public_key: key(43).public_key() };
    assert_eq!(refused(check(&v, &proof, &[liar], T).await).code(), ErrorCode::NotAllowed);
    assert_eq!(s.requests(), 0);
}

// ---- OIDC ----

fn github_claims(repository_id: Value, iat: UnixTime) -> Value {
    json!({
        "iss": oidc::GITHUB_ISSUER, "aud": "seal:acme", "sub": "repo:acme/api:environment:prod",
        "repository": "acme/api", "repository_id": repository_id, "repository_owner_id": "65",
        "environment": "prod", "ref": "refs/heads/main",
        "iat": iat, "nbf": iat, "exp": iat + 300,
    })
}
fn github_matcher(repository: &str, repository_id: u64, scope: GitHubScope) -> IdentityMatcher {
    IdentityMatcher::GitHub { repository: repository.into(), repository_id, repository_owner_id: 65, scope }
}

#[tokio::test]
async fn github_tokens() {
    let s = issuers().await;
    let v = ProofVerifier::new(s.https.clone());
    let prod = github_matcher("acme/api", 74, GitHubScope::Environment("prod".into()));
    let token = |claims: &Value| oidc(OidcProvider::GitHub, jwt(rs256("rsa-1"), claims, Signer::Rsa));

    let c = check(&v, &token(&github_claims(json!("74"), T - 10)), std::slice::from_ref(&prod), T).await.unwrap();
    assert_eq!(
        c.identity(),
        &WorkloadIdentity::GitHub {
            repository: "acme/api".into(),
            repository_id: 74,
            repository_owner_id: 65,
            environment: Some("prod".into()),
            git_ref: "refs/heads/main".into(),
        }
    );
    assert_eq!(c.scope().assurance, ProofAssurance::BearerOverAttestedChannel);
    assert_eq!(c.scope().expires_at, Some(T - 10 + 300 + oidc::OIDC_SKEW_SECS));
    // Numeric ids work too.
    check(&v, &token(&github_claims(json!(74), T - 10)), std::slice::from_ref(&prod), T).await.unwrap();

    // Renamed repository: same ids, still the grant (the name is display only).
    let mut renamed = github_claims(json!("74"), T - 10);
    renamed["repository"] = json!("acme/api-v2");
    check(&v, &token(&renamed), std::slice::from_ref(&prod), T).await.unwrap();
    // Recreated under the same name: a new id, not the grant.
    let recreated = github_claims(json!("99"), T - 10);
    assert_eq!(
        refused(check(&v, &token(&recreated), std::slice::from_ref(&prod), T).await).code(),
        ErrorCode::NotAllowed
    );
    // Another environment.
    let staging = github_matcher("acme/api", 74, GitHubScope::Environment("staging".into()));
    assert_eq!(
        refused(check(&v, &token(&github_claims(json!("74"), T - 10)), &[staging], T).await).code(),
        ErrorCode::NotAllowed
    );
    // An exact ref.
    let main = github_matcher("acme/api", 74, GitHubScope::Ref("refs/heads/main".into()));
    check(&v, &token(&github_claims(json!("74"), T - 10)), &[main], T).await.unwrap();

    // Wrong audience.
    let mut aud = github_claims(json!("74"), T - 10);
    aud["aud"] = json!("seal:bravo");
    assert!(is_bad_proof(&refused(check(&v, &token(&aud), std::slice::from_ref(&prod), T).await)));
    // Too old: iat more than MAX_OIDC_TOKEN_AGE_SECS before the latest time, though not expired.
    let mut old = github_claims(json!("74"), T - MAX_OIDC_TOKEN_AGE_SECS);
    old["exp"] = json!(T + 3600);
    check(&v, &token(&old), std::slice::from_ref(&prod), T).await.unwrap();
    assert!(is_bad_proof(&refused(check(&v, &token(&old), std::slice::from_ref(&prod), T + 1).await)));
    assert!(is_bad_proof(&refused(
        v.verify(&token(&old), &ctx(), std::slice::from_ref(&prod), &TrustedTime { now: T, radius: 1 }).await
    )));
    let mut no_iat = github_claims(json!("74"), T - 10);
    no_iat.as_object_mut().unwrap().remove("iat");
    assert!(is_bad_proof(&refused(check(&v, &token(&no_iat), &[prod], T).await)));
}

#[tokio::test]
async fn expiry_and_not_before_allow_60_seconds_of_skew() {
    let s = issuers().await;
    let v = ProofVerifier::new(s.https.clone());
    let prod = github_matcher("acme/api", 74, GitHubScope::Environment("prod".into()));
    let claims = github_claims(json!("74"), T); // exp = T + 300
    let proof = oidc(OidcProvider::GitHub, jwt(rs256("rsa-1"), &claims, Signer::Rsa));
    check(&v, &proof, std::slice::from_ref(&prod), T + 359).await.unwrap();
    assert!(is_bad_proof(&refused(check(&v, &proof, std::slice::from_ref(&prod), T + 360).await)));
    assert!(is_bad_proof(&refused(
        v.verify(&proof, &ctx(), std::slice::from_ref(&prod), &TrustedTime { now: T + 355, radius: 5 }).await
    )));
    // nbf (and iat) in the future beyond the skew, against the earliest time.
    check(&v, &proof, std::slice::from_ref(&prod), T - 60).await.unwrap();
    assert!(is_bad_proof(&refused(check(&v, &proof, std::slice::from_ref(&prod), T - 61).await)));
    let mut no_exp = claims.clone();
    no_exp.as_object_mut().unwrap().remove("exp");
    let proof = oidc(OidcProvider::GitHub, jwt(rs256("rsa-1"), &no_exp, Signer::Rsa));
    assert!(is_bad_proof(&refused(check(&v, &proof, &[prod], T).await)));
}

#[tokio::test]
async fn wrong_issuer_alg_kid_and_forgeries_are_refused() {
    let s = issuers().await;
    let v = ProofVerifier::new(s.https.clone());
    let prod = github_matcher("acme/api", 74, GitHubScope::Environment("prod".into()));
    let claims = github_claims(json!("74"), T - 10);

    // GitHub's issuer is RS256: an ES256 token verifies under no key, even the issuer's EC key.
    let es = oidc(OidcProvider::GitHub, jwt(es256("ec-1"), &claims, Signer::Ec));
    assert!(is_bad_proof(&refused(check(&v, &es, std::slice::from_ref(&prod), T).await)));
    // A header claiming RS256 over an EC signature, under the EC key's kid.
    let mixed = oidc(OidcProvider::GitHub, jwt(rs256("ec-1"), &claims, Signer::Ec));
    assert!(is_bad_proof(&refused(check(&v, &mixed, std::slice::from_ref(&prod), T).await)));
    // alg none.
    let none = format!("{}.{}.", b64url(br#"{"alg":"none"}"#), b64url(claims.to_string().as_bytes()));
    assert!(is_bad_proof(&refused(check(&v, &oidc(OidcProvider::GitHub, none), std::slice::from_ref(&prod), T).await)));
    // A type other than JWT.
    let typ =
        oidc(OidcProvider::GitHub, jwt(json!({"alg": "RS256", "kid": "rsa-1", "typ": "at+jwt"}), &claims, Signer::Rsa));
    assert!(is_bad_proof(&refused(check(&v, &typ, std::slice::from_ref(&prod), T).await)));
    // Claims changed after signing.
    let good = jwt(rs256("rsa-1"), &claims, Signer::Rsa);
    let mut parts: Vec<String> = good.split('.').map(String::from).collect();
    let mut changed = claims.clone();
    changed["repository_id"] = json!("75");
    parts[1] = b64url(changed.to_string().as_bytes());
    let forged = oidc(OidcProvider::GitHub, parts.join("."));
    assert!(is_bad_proof(&refused(
        check(&v, &forged, &[github_matcher("acme/api", 75, GitHubScope::Environment("prod".into()))], T).await
    )));
    // Unknown kid.
    let unknown = oidc(OidcProvider::GitHub, jwt(rs256("rsa-9"), &claims, Signer::Rsa));
    assert!(is_bad_proof(&refused(check(&v, &unknown, std::slice::from_ref(&prod), T).await)));

    // An issuer the tenant does not name is never fetched.
    let before = s.requests();
    let mut evil = claims.clone();
    evil["iss"] = json!("https://evil.example.com");
    let evil = oidc(OidcProvider::GitHub, jwt(rs256("rsa-1"), &evil, Signer::Rsa));
    assert!(is_bad_proof(&refused(check(&v, &evil, std::slice::from_ref(&prod), T).await)));
    // GitHub's issuer without any GitHub grant, or under another provider.
    let gh = oidc(OidcProvider::GitHub, jwt(rs256("rsa-1"), &claims, Signer::Rsa));
    assert!(is_bad_proof(&refused(check(&v, &gh, &[app_key(42).0], T).await)));
    let as_k8s = oidc(OidcProvider::Kubernetes, jwt(rs256("rsa-1"), &claims, Signer::Rsa));
    assert!(is_bad_proof(&refused(check(&v, &as_k8s, std::slice::from_ref(&prod), T).await)));
    let as_gcp = oidc(OidcProvider::Gcp, jwt(rs256("rsa-1"), &claims, Signer::Rsa));
    assert!(is_bad_proof(&refused(check(&v, &as_gcp, std::slice::from_ref(&prod), T).await)));
    assert!(is_bad_proof(&refused(check(&v, &oidc(OidcProvider::GitHub, "not.a.jwt".into()), &[prod], T).await)));
    assert_eq!(s.requests(), before);
    assert!(s.seen.lock().unwrap().iter().all(|r| r.host != "evil.example.com"));
}

#[tokio::test]
async fn jwks_cache_and_refetch_on_unknown_kid() {
    let s = issuers().await;
    let v = ProofVerifier::new(s.https.clone());
    let prod = github_matcher("acme/api", 74, GitHubScope::Environment("prod".into()));
    let host = "token.actions.githubusercontent.com";
    let fetches = || s.seen_for(host).iter().filter(|r| r.target == "/.well-known/jwks").count();
    let token =
        |kid: &str, iat| oidc(OidcProvider::GitHub, jwt(rs256(kid), &github_claims(json!("74"), iat), Signer::Rsa));

    check(&v, &token("rsa-1", T), std::slice::from_ref(&prod), T).await.unwrap();
    assert_eq!(fetches(), 1);
    // Cached.
    check(&v, &token("rsa-1", T + 100), std::slice::from_ref(&prod), T + 100).await.unwrap();
    assert_eq!(fetches(), 1);
    // The issuer rotates to rsa-2: an unknown kid refetches at once.
    s.routes.set(host, "/.well-known/jwks", 200, jwks("rsa-2"));
    check(&v, &token("rsa-2", T + 110), std::slice::from_ref(&prod), T + 110).await.unwrap();
    assert_eq!(fetches(), 2);
    // Unknown kids refetch at most once per JWKS_REFETCH_MIN_SECS.
    assert!(is_bad_proof(&refused(check(&v, &token("rsa-9", T + 120), std::slice::from_ref(&prod), T + 120).await)));
    assert_eq!(fetches(), 2);
    assert!(is_bad_proof(&refused(check(&v, &token("rsa-9", T + 140), std::slice::from_ref(&prod), T + 140).await)));
    assert_eq!(fetches(), 3);
    // The rotated-out key no longer verifies once the set is refreshed.
    assert!(is_bad_proof(&refused(check(&v, &token("rsa-1", T + 141), std::slice::from_ref(&prod), T + 141).await)));
    // After JWKS_CACHE_SECS the set is refetched even for a known kid.
    let later = T + 140 + oidc::JWKS_CACHE_SECS;
    check(&v, &token("rsa-2", later), std::slice::from_ref(&prod), later).await.unwrap();
    assert_eq!(fetches(), 4);

    // An unreachable issuer is retryable, not a refusal.
    s.routes.set(host, "/.well-known/jwks", 503, "{}");
    let much_later = later + oidc::JWKS_CACHE_SECS;
    let e = refused(check(&v, &token("rsa-2", much_later), &[prod], much_later).await);
    assert_eq!(e.code(), ErrorCode::Unavailable);
}

#[tokio::test]
async fn discovery_must_name_the_same_issuer() {
    let s = issuers().await;
    s.routes.set(
        "token.actions.githubusercontent.com",
        "/.well-known/openid-configuration",
        200,
        json!({"issuer": "https://evil.example.com", "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks"}).to_string(),
    );
    let v = ProofVerifier::new(s.https.clone());
    let prod = github_matcher("acme/api", 74, GitHubScope::Environment("prod".into()));
    let proof = oidc(OidcProvider::GitHub, jwt(rs256("rsa-1"), &github_claims(json!("74"), T), Signer::Rsa));
    assert_eq!(refused(check(&v, &proof, &[prod], T).await).code(), ErrorCode::Unavailable);
}

fn azure_claims(iss: &str, aud: &str, oid: &str) -> Value {
    json!({"iss": iss, "aud": aud, "tid": TID, "oid": oid, "sub": oid, "iat": T - 3600, "nbf": T - 3600, "exp": T + 3600})
}
fn azure(oid: &str, audience: &str) -> IdentityMatcher {
    IdentityMatcher::Azure { entra_tenant: TID.into(), object_id: oid.into(), audience: audience.into(), hosted: None }
}

#[tokio::test]
async fn azure_tokens_take_their_audience_from_the_grant() {
    let s = issuers().await;
    let v = ProofVerifier::new(s.https.clone());
    let token = |claims: &Value| oidc(OidcProvider::Azure, jwt(rs256("rsa-1"), claims, Signer::Rsa));
    let grants = [azure("oid-1", "api://seal-a"), azure("oid-1", "api://seal-b"), azure("oid-2", "api://seal-a")];

    for iss in [azure_v2(), azure_v1()] {
        let c = check(&v, &token(&azure_claims(&iss, "api://seal-a", "oid-1")), &grants, T).await.unwrap();
        assert_eq!(c.identity(), &WorkloadIdentity::Azure { entra_tenant: TID.into(), object_id: "oid-1".into() });
        // Only the entry for the token's audience is kept: a later recheck cannot widen it.
        assert_eq!(c.scope().matched_grants, vec![azure("oid-1", "api://seal-a")]);
        // Azure tokens are cached by the provider: no age limit, only exp.
        assert_eq!(c.scope().expires_at, Some(T + 3600 + oidc::OIDC_SKEW_SECS));
    }
    // An audience no matching entry names.
    let e = refused(check(&v, &token(&azure_claims(&azure_v2(), "api://other", "oid-1")), &grants, T).await);
    assert_eq!(e.code(), ErrorCode::NotAllowed);
    // `seal:<tenant>` is not an Azure audience.
    let e = refused(check(&v, &token(&azure_claims(&azure_v2(), "seal:acme", "oid-1")), &grants, T).await);
    assert_eq!(e.code(), ErrorCode::NotAllowed);
    // A recreated managed identity has a new object id.
    let e = refused(check(&v, &token(&azure_claims(&azure_v2(), "api://seal-a", "oid-3")), &grants, T).await);
    assert_eq!(e.code(), ErrorCode::NotAllowed);
    // tid must be the issuer's.
    let mut tid = azure_claims(&azure_v2(), "api://seal-a", "oid-1");
    tid["tid"] = json!("00000000-0000-0000-0000-000000000000");
    assert!(is_bad_proof(&refused(check(&v, &token(&tid), &grants, T).await)));

    // Another Entra tenant's issuer is never fetched.
    let before = s.requests();
    let foreign = format!("https://login.microsoftonline.com/{}/v2.0", "11111111-1111-1111-1111-111111111111");
    assert!(is_bad_proof(&refused(
        check(&v, &token(&azure_claims(&foreign, "api://seal-a", "oid-1")), &grants, T).await
    )));
    let lookalike = format!("https://login.microsoftonline.com.evil.com/{TID}/v2.0");
    assert!(is_bad_proof(&refused(
        check(&v, &token(&azure_claims(&lookalike, "api://seal-a", "oid-1")), &grants, T).await
    )));
    assert_eq!(s.requests(), before);
}

fn k8s_claims(uid: &str, iat: UnixTime) -> Value {
    json!({
        "iss": K8S_ISSUER, "aud": ["seal:acme"], "sub": "system:serviceaccount:payments:api",
        "iat": iat, "nbf": iat, "exp": iat + 600,
        "kubernetes.io": {"namespace": "payments", "serviceaccount": {"name": "api", "uid": uid}, "pod": {"name": "api-1", "uid": "p"}},
    })
}
fn k8s(issuer: &str, uid: &str) -> IdentityMatcher {
    IdentityMatcher::Kubernetes {
        issuer: issuer.into(),
        namespace: "payments".into(),
        service_account: "api".into(),
        service_account_uid: uid.into(),
    }
}

#[tokio::test]
async fn kubernetes_tokens() {
    let s = issuers().await;
    let v = ProofVerifier::new(s.https.clone());
    let grant = k8s(K8S_ISSUER, "uid-1");
    // A Kubernetes issuer's algorithm is its key's: ES256 for its P-256 key, RS256 for its RSA key.
    let es = |claims: &Value| oidc(OidcProvider::Kubernetes, jwt(es256("ec-1"), claims, Signer::Ec));
    let rs = |claims: &Value| oidc(OidcProvider::Kubernetes, jwt(rs256("rsa-1"), claims, Signer::Rsa));
    let c = check(&v, &es(&k8s_claims("uid-1", T - 5)), std::slice::from_ref(&grant), T).await.unwrap();
    assert_eq!(
        c.identity(),
        &WorkloadIdentity::Kubernetes {
            issuer: K8S_ISSUER.into(),
            namespace: "payments".into(),
            service_account: "api".into(),
            service_account_uid: "uid-1".into(),
        }
    );
    check(&v, &rs(&k8s_claims("uid-1", T - 5)), std::slice::from_ref(&grant), T).await.unwrap();
    // The EC key's kid with an RS256 header: refused.
    let mixed = oidc(
        OidcProvider::Kubernetes,
        jwt(json!({"alg": "RS256", "kid": "ec-1"}), &k8s_claims("uid-1", T), Signer::Rsa),
    );
    assert!(is_bad_proof(&refused(check(&v, &mixed, std::slice::from_ref(&grant), T).await)));
    // Recreated service account: same names, new uid.
    assert_eq!(
        refused(check(&v, &es(&k8s_claims("uid-2", T - 5)), std::slice::from_ref(&grant), T).await).code(),
        ErrorCode::NotAllowed
    );
    // Too old.
    let old = k8s_claims("uid-1", T - MAX_OIDC_TOKEN_AGE_SECS - 1);
    assert!(is_bad_proof(&refused(check(&v, &es(&old), std::slice::from_ref(&grant), T).await)));
    // Subject must agree with the service account.
    let mut sub = k8s_claims("uid-1", T - 5);
    sub["sub"] = json!("system:serviceaccount:payments:admin");
    assert!(is_bad_proof(&refused(check(&v, &es(&sub), std::slice::from_ref(&grant), T).await)));
    // Wrong audience.
    let mut aud = k8s_claims("uid-1", T - 5);
    aud["aud"] = json!(["https://kubernetes.default.svc"]);
    assert!(is_bad_proof(&refused(check(&v, &es(&aud), std::slice::from_ref(&grant), T).await)));
    // An issuer only another cluster's grant names is not this one.
    let before = s.requests();
    assert!(is_bad_proof(&refused(
        check(&v, &es(&k8s_claims("uid-1", T)), &[k8s("https://k8s.example.com/other", "uid-1")], T).await
    )));
    assert_eq!(s.requests(), before);
}

fn gcp_claims(sub: &str) -> Value {
    json!({
        "iss": oidc::GOOGLE_ISSUER, "aud": "seal:acme", "sub": sub, "azp": sub,
        "email": "api@acme.iam.gserviceaccount.com", "email_verified": true,
        "iat": T - 1800, "exp": T + 1800,
    })
}

#[tokio::test]
async fn gcp_tokens() {
    let s = issuers().await;
    let v = ProofVerifier::new(s.https.clone());
    let grant =
        IdentityMatcher::Gcp { email: "api@acme.iam.gserviceaccount.com".into(), unique_id: "1234567890".into() };
    let token = |claims: &Value| oidc(OidcProvider::Gcp, jwt(rs256("rsa-1"), claims, Signer::Rsa));
    // Cached tokens: no age limit beyond exp.
    let c = check(&v, &token(&gcp_claims("1234567890")), std::slice::from_ref(&grant), T).await.unwrap();
    assert_eq!(
        c.identity(),
        &WorkloadIdentity::Gcp { email: "api@acme.iam.gserviceaccount.com".into(), unique_id: "1234567890".into() }
    );
    // A recreated service account (same email, new unique id).
    assert_eq!(
        refused(check(&v, &token(&gcp_claims("999")), std::slice::from_ref(&grant), T).await).code(),
        ErrorCode::NotAllowed
    );
    let mut aud = gcp_claims("1234567890");
    aud["aud"] = json!("https://example.com");
    assert!(is_bad_proof(&refused(check(&v, &token(&aud), std::slice::from_ref(&grant), T).await)));
    let mut unverified = gcp_claims("1234567890");
    unverified["email_verified"] = json!(false);
    assert!(is_bad_proof(&refused(check(&v, &token(&unverified), &[grant], T).await)));
}

// ---- AWS SigV4 ----

const BINDING_HOST: &str = "sts.amazonaws.com";
const ROLE_ID: &str = "AROA3XFRBF535PLBIFPI4";

fn sts_response(user_id: &str, arn: &str) -> String {
    json!({"GetCallerIdentityResponse": {
        "GetCallerIdentityResult": {"Account": "123456789012", "Arn": arn, "UserId": user_id},
        "ResponseMetadata": {"RequestId": "01234567-89ab-cdef-0123-456789abcdef"},
    }})
    .to_string()
}

fn role_response() -> String {
    sts_response(&format!("{ROLE_ID}:i-0abc"), "arn:aws:sts::123456789012:assumed-role/seal-enclave/i-0abc")
}

fn binding() -> String {
    hex::encode(codec::labeled_digest(PROOF_CONTEXT_LABEL, &ctx()))
}

fn presigned_url(host: &str, signed_headers: &str, extra: &str) -> String {
    format!(
        "https://{host}/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential=ASIAEXAMPLE%2F20300101%2Fus-east-1%2Fsts%2Faws4_request&X-Amz-Date=20300101T000000Z\
         &X-Amz-Expires=60&X-Amz-SignedHeaders={signed_headers}&X-Amz-Security-Token=tok&X-Amz-Signature=abcdef0123{extra}"
    )
}

fn sigv4(method: &str, url: String, headers: &[(&str, &str)], body: &str) -> IdentityProof {
    IdentityProof::AwsSigV4 {
        method: method.into(),
        url,
        headers: headers.iter().map(|(n, v)| (n.to_string(), Bearer::new(v.to_string()))).collect(),
        body: body.into(),
    }
}

fn presigned(host: &str, signed_headers: &str, binding_value: Option<&str>) -> IdentityProof {
    let mut headers = vec![("Host", host)];
    if let Some(b) = binding_value {
        headers.push(("X-Seal-Binding", b));
    }
    sigv4("GET", presigned_url(host, signed_headers, ""), &headers, "")
}

fn role(role_id: &str) -> IdentityMatcher {
    IdentityMatcher::AwsRole { role_arn: "arn:aws:iam::123456789012:role/seal-enclave".into(), role_id: role_id.into() }
}

#[tokio::test]
async fn sigv4_presigned_proof_is_replayed_to_sts() {
    let s = server().await;
    s.routes.set(BINDING_HOST, "/", 200, role_response());
    let v = ProofVerifier::new(s.https.clone());
    let b = binding();
    let c = check(&v, &presigned(BINDING_HOST, "host%3Bx-seal-binding", Some(&b)), &[role(ROLE_ID)], T).await.unwrap();
    assert_eq!(
        c.identity(),
        &WorkloadIdentity::AwsRole {
            account: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/seal-enclave".into(),
            role_id: ROLE_ID.into(),
        }
    );
    assert_eq!(c.scope().assurance, ProofAssurance::RequestBound);
    let seen = s.seen_for(BINDING_HOST);
    assert_eq!(seen.len(), 1);
    let r = &seen[0];
    assert_eq!(r.method, "GET");
    assert!(r.target.starts_with("/?Action=GetCallerIdentity&"));
    let header = |n: &str| r.headers.iter().filter(|(k, _)| k == n).map(|(_, v)| v.as_str()).collect::<Vec<_>>();
    assert_eq!(header("x-seal-binding"), [b.as_str()]);
    assert_eq!(header("accept"), ["application/json"]);
    assert_eq!(header("host"), [BINDING_HOST]);

    // A recreated role of the same name has a new unique id.
    assert_eq!(
        refused(
            check(&v, &presigned(BINDING_HOST, "host%3Bx-seal-binding", Some(&b)), &[role("AROAOTHERROLEID00001")], T)
                .await
        )
        .code(),
        ErrorCode::NotAllowed
    );
}

#[tokio::test]
async fn sigv4_header_signed_post_and_regional_hosts() {
    let s = server().await;
    let regional = "sts.us-east-1.amazonaws.com";
    s.routes.set(regional, "/", 200, role_response());
    let v = ProofVerifier::new(s.https.clone());
    let b = binding();
    let auth = "AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/20300101/us-east-1/sts/aws4_request, \
                SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-seal-binding, Signature=abcdef";
    let proof = sigv4(
        "POST",
        format!("https://{regional}/"),
        &[
            ("host", regional),
            ("authorization", auth),
            ("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
            ("x-amz-date", "20300101T000000Z"),
            ("x-amz-security-token", "tok"),
            ("x-seal-binding", &b),
        ],
        "Action=GetCallerIdentity&Version=2011-06-15",
    );
    check(&v, &proof, &[role(ROLE_ID)], T).await.unwrap();
    let r = &s.seen_for(regional)[0];
    assert_eq!((r.method.as_str(), r.target.as_str()), ("POST", "/"));
    assert_eq!(r.body, b"Action=GetCallerIdentity&Version=2011-06-15");
    assert!(r.headers.iter().any(|(n, v)| n == "content-type" && v.starts_with("application/x-www-form-urlencoded")));
}

#[tokio::test]
async fn sigv4_binding_header_must_be_signed_and_match() {
    let s = server().await;
    s.routes.set(BINDING_HOST, "/", 200, role_response());
    let v = ProofVerifier::new(s.https.clone());
    let b = binding();
    let grants = [role(ROLE_ID)];
    // Present but not signed.
    assert!(is_bad_proof(&refused(check(&v, &presigned(BINDING_HOST, "host", Some(&b)), &grants, T).await)));
    // Signed but absent.
    assert!(is_bad_proof(&refused(
        check(&v, &presigned(BINDING_HOST, "host%3Bx-seal-binding", None), &grants, T).await
    )));
    // For another context.
    let mut other = ctx();
    other.purpose = ProofPurpose::Seal { request_digest: [3; 32] };
    let wrong = hex::encode(codec::labeled_digest(PROOF_CONTEXT_LABEL, &other));
    assert!(is_bad_proof(&refused(
        check(&v, &presigned(BINDING_HOST, "host%3Bx-seal-binding", Some(&wrong)), &grants, T).await
    )));
    // Host not signed.
    assert!(is_bad_proof(&refused(check(&v, &presigned(BINDING_HOST, "x-seal-binding", Some(&b)), &grants, T).await)));
    // Repeated binding header.
    let twice = sigv4(
        "GET",
        presigned_url(BINDING_HOST, "host%3Bx-seal-binding", ""),
        &[("x-seal-binding", &b), ("X-Seal-Binding", &wrong)],
        "",
    );
    assert!(is_bad_proof(&refused(check(&v, &twice, &grants, T).await)));
    assert_eq!(s.requests(), 0);
}

#[tokio::test]
async fn sigv4_goes_only_to_sts_and_only_for_get_caller_identity() {
    let s = server().await;
    let v = ProofVerifier::new(s.https.clone());
    let b = binding();
    let grants = [role(ROLE_ID)];
    let sh = "host%3Bx-seal-binding";
    let (v, grants) = (&v, &grants);
    let refuse =
        |proof: IdentityProof| async move { assert!(is_bad_proof(&refused(check(v, &proof, grants, T).await))) };
    for host in [
        "sts.amazonaws.com.evil.com",
        "evil.com",
        "sts.evil.amazonaws.com",
        "iam.amazonaws.com",
        "sts.us-east-1.amazonaws.com.cn",
    ] {
        refuse(presigned(host, sh, Some(&b))).await;
    }
    for url in [
        presigned_url("sts.amazonaws.com:8443", sh, ""),
        presigned_url("user@sts.amazonaws.com", sh, ""),
        presigned_url(BINDING_HOST, sh, "#frag"),
        presigned_url(BINDING_HOST, sh, "").replacen("https://", "http://", 1),
        presigned_url(BINDING_HOST, sh, "").replacen("/?", "/x?", 1),
        presigned_url(BINDING_HOST, sh, "").replacen("GetCallerIdentity", "AssumeRole", 1),
        presigned_url(BINDING_HOST, sh, "&Action=GetCallerIdentity"),
        presigned_url(BINDING_HOST, sh, "&RoleArn=x"),
        presigned_url(BINDING_HOST, sh, "").replacen("X-Amz-Expires=60", "X-Amz-Expires=3600", 1),
        presigned_url(BINDING_HOST, sh, "").replacen("%2Fsts%2F", "%2Fiam%2F", 1),
    ] {
        refuse(sigv4("GET", url, &[("x-seal-binding", &b)], "")).await;
    }
    // Non-canonical URLs, which another parser could read differently.
    for url in [
        "https://STS.amazonaws.com/?Action=GetCallerIdentity".to_string(),
        "https://sts.amazonaws.com\\@evil.com/?Action=GetCallerIdentity".to_string(),
        "https://sts.amazonaws.com:443/?Action=GetCallerIdentity".to_string(),
    ] {
        refuse(sigv4("GET", url, &[("x-seal-binding", &b)], "")).await;
    }
    refuse(sigv4("GET", presigned_url(BINDING_HOST, sh, ""), &[("x-seal-binding", "a\r\nx-evil: 1")], "")).await;
    // Host header disagreeing with the URL, unknown headers, methods.
    refuse(sigv4("GET", presigned_url(BINDING_HOST, sh, ""), &[("host", "evil.com"), ("x-seal-binding", &b)], ""))
        .await;
    refuse(sigv4("GET", presigned_url(BINDING_HOST, sh, ""), &[("x-forwarded-for", "1"), ("x-seal-binding", &b)], ""))
        .await;
    refuse(sigv4("GET", presigned_url(BINDING_HOST, sh, ""), &[("accept", "text/xml"), ("x-seal-binding", &b)], ""))
        .await;
    refuse(sigv4("PUT", presigned_url(BINDING_HOST, sh, ""), &[("x-seal-binding", &b)], "")).await;
    // Not signed, or signed twice.
    refuse(sigv4("GET", format!("https://{BINDING_HOST}/?Action=GetCallerIdentity"), &[("x-seal-binding", &b)], ""))
        .await;
    let auth = "AWS4-HMAC-SHA256 Credential=A/20300101/us-east-1/sts/aws4_request, SignedHeaders=host;x-seal-binding, Signature=ab";
    refuse(sigv4("GET", presigned_url(BINDING_HOST, sh, ""), &[("authorization", auth), ("x-seal-binding", &b)], ""))
        .await;
    // POST body with another action.
    refuse(sigv4(
        "POST",
        format!("https://{BINDING_HOST}/"),
        &[("authorization", auth), ("content-type", "application/x-www-form-urlencoded"), ("x-seal-binding", &b)],
        "Action=GetSessionToken&Version=2011-06-15",
    ))
    .await;
    assert_eq!(s.requests(), 0);
}

#[tokio::test]
async fn sts_answers() {
    let s = server().await;
    let v = ProofVerifier::new(s.https.clone());
    let b = binding();
    let proof = presigned(BINDING_HOST, "host%3Bx-seal-binding", Some(&b));
    let grants = [role(ROLE_ID)];
    // STS refuses the signature.
    s.routes.set(BINDING_HOST, "/", 403, r#"{"Error":{"Code":"SignatureDoesNotMatch","Type":"Sender"}}"#);
    assert!(is_bad_proof(&refused(check(&v, &proof, &grants, T).await)));
    // STS unavailable.
    s.routes.set(BINDING_HOST, "/", 503, "{}");
    assert_eq!(refused(check(&v, &proof, &grants, T).await).code(), ErrorCode::Unavailable);
    // An IAM user, not a role.
    s.routes.set(BINDING_HOST, "/", 200, sts_response("AIDAEXAMPLEUSERID0001", "arn:aws:iam::123456789012:user/alice"));
    assert!(is_bad_proof(&refused(check(&v, &proof, &grants, T).await)));
    // XML instead of JSON.
    s.routes.set(BINDING_HOST, "/", 200, "<GetCallerIdentityResponse/>");
    assert!(is_bad_proof(&refused(check(&v, &proof, &grants, T).await)));
}

#[test]
fn sts_hosts() {
    for ok in [
        "sts.amazonaws.com",
        "sts.us-east-1.amazonaws.com",
        "sts.eu-central-1.amazonaws.com",
        "sts.us-gov-west-1.amazonaws.com",
        "sts.cn-north-1.amazonaws.com.cn",
    ] {
        assert!(sigv4::is_sts_host(ok), "{ok}");
    }
    for bad in [
        "amazonaws.com",
        "sts.amazonaws.com.",
        "sts..amazonaws.com",
        "sts.us.amazonaws.com",
        "sts.us-east-x.amazonaws.com",
        "sts.us-east-1.amazonaws.com.cn",
        "xsts.amazonaws.com",
        "sts.US-EAST-1.amazonaws.com",
    ] {
        assert!(!sigv4::is_sts_host(bad), "{bad}");
    }
}

#[test]
fn sts_responses() {
    assert_eq!(
        sigv4::parse_response(role_response().as_bytes()).unwrap(),
        WorkloadIdentity::AwsRole {
            account: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/seal-enclave".into(),
            role_id: ROLE_ID.into(),
        }
    );
    let gov = sts_response(&format!("{ROLE_ID}:s"), "arn:aws-us-gov:sts::123456789012:assumed-role/r/s");
    assert!(
        matches!(sigv4::parse_response(gov.as_bytes()).unwrap(), WorkloadIdentity::AwsRole { role_arn, .. } if role_arn == "arn:aws-us-gov:iam::123456789012:role/r")
    );
    for (user_id, arn) in [
        (format!("{ROLE_ID}:s"), "arn:aws:sts::999999999999:assumed-role/r/s".to_string()),
        (format!("{ROLE_ID}:s"), "arn:aws:iam::123456789012:role/r".to_string()),
        (format!("{ROLE_ID}:s"), "arn:evil:sts::123456789012:assumed-role/r/s".to_string()),
        ("123456789012".to_string(), "arn:aws:iam::123456789012:root".to_string()),
        ("AROA:s".to_string(), "arn:aws:sts::123456789012:assumed-role/r/s".to_string()),
    ] {
        assert!(sigv4::parse_response(sts_response(&user_id, &arn).as_bytes()).is_err(), "{user_id} {arn}");
    }
    assert!(sigv4::parse_response(b"{}").is_err());
}

// ---- deployments ----

#[tokio::test]
async fn deployment_identities() {
    let s = issuers().await;
    s.routes.set(BINDING_HOST, "/", 200, role_response());
    let space = WorkloadIdentity::ConfidentialSpace {
        project_number: 42,
        service_account: "enclave@p.iam.gserviceaccount.com".into(),
    };
    let t = verified({
        let mut st = base_state(1);
        st.deployments.insert(role(ROLE_ID));
        st.deployments.insert(azure("oid-dep", "api://seal-deploy"));
        st.deployments.insert(IdentityMatcher::ConfidentialSpace {
            project_number: 42,
            service_account: "enclave@p.iam.gserviceaccount.com".into(),
            hosted: None,
        });
        // Grants are not deployments.
        st.apps.insert(app("checkout"), [azure("oid-app", "api://seal-deploy")].into());
        st
    });
    let dv = DeploymentVerifier::new(s.https.clone());
    let now = at(T);

    // SigV4 needs no binding header for a deployment.
    let proof = presigned(BINDING_HOST, "host", None);
    assert!(matches!(
        dv.verify(&DeploymentProof::Proof(proof), &t, &now).await.unwrap(),
        WorkloadIdentity::AwsRole { .. }
    ));
    // Azure managed identity of the container group.
    let token = |oid: &str| {
        oidc(
            OidcProvider::Azure,
            jwt(rs256("rsa-1"), &azure_claims(&azure_v2(), "api://seal-deploy", oid), Signer::Rsa),
        )
    };
    let id = dv.verify(&DeploymentProof::Proof(token("oid-dep")), &t, &now).await.unwrap();
    assert_eq!(id, WorkloadIdentity::Azure { entra_tenant: TID.into(), object_id: "oid-dep".into() });
    assert_eq!(
        dv.verify(&DeploymentProof::Proof(token("oid-app")), &t, &now).await.unwrap_err().code(),
        ErrorCode::NotAllowed
    );
    // An expired deployment token.
    assert!(dv.verify(&DeploymentProof::Proof(token("oid-dep")), &t, &at(T + 3600 + 60)).await.is_err());
    // Attested identities.
    assert_eq!(dv.verify(&DeploymentProof::Attested(space.clone()), &t, &now).await.unwrap(), space);
    let other = WorkloadIdentity::ConfidentialSpace {
        project_number: 43,
        service_account: "enclave@p.iam.gserviceaccount.com".into(),
    };
    assert_eq!(dv.verify(&DeploymentProof::Attested(other), &t, &now).await.unwrap_err().code(), ErrorCode::NotAllowed);
    // App keys never prove a deployment.
    let k = key(42);
    let SigAlg::Ed25519 { sig } = k.sign(PROOF_CONTEXT_LABEL, &ctx()).alg else { unreachable!() };
    let app_proof = IdentityProof::AppKey { key_id: k.key_id(), signature: sig };
    assert_eq!(
        dv.verify(&DeploymentProof::Proof(app_proof), &t, &now).await.unwrap_err().code(),
        ErrorCode::NotAllowed
    );
    // No deployments: nobody serves.
    let empty = verified(base_state(1));
    assert_eq!(
        dv.verify(&DeploymentProof::Attested(space), &empty, &now).await.unwrap_err().code(),
        ErrorCode::NotAllowed
    );
}

// ---- RequestAuthenticator ----

#[tokio::test]
async fn request_authenticator_computes_the_purpose_itself() {
    let s = server().await;
    let keys = service_keys();
    let spki = keys.tls.spki_sha256();
    let now = at(T);
    let ticket = keys.ticket.issue(&acme(), &now, &mut rng());
    let auth = RequestAuthenticator::new(s.https.clone(), Arc::new(keys.ticket), spki);
    let (m, id) = app_key(42);
    let t = verified({
        let mut st = base_state(1);
        st.producers.insert(m.clone());
        st
    });
    let context = |purpose| ProofContext { tenant: acme(), purpose, tls_spki_sha256: spki, ticket: ticket.clone() };
    let prove = |ctx: &ProofContext| {
        let SigAlg::Ed25519 { sig } = key(42).sign(PROOF_CONTEXT_LABEL, ctx).alg else { unreachable!() };
        IdentityProof::AppKey { key_id: key(42).key_id(), signature: sig }
    };
    let placeholder = || context(ProofPurpose::Seal { request_digest: [0; 32] });
    let seal = |payload: Vec<u8>| {
        let mut r = SealRequest {
            service_key_version: ServiceKeyVersion(1),
            hpke_enc: vec![1; 32],
            sealed_payload: payload,
            context: placeholder(),
            proof: IdentityProof::AppKey { key_id: key(42).key_id(), signature: vec![] },
        };
        r.context = context(r.expected_purpose());
        r.proof = prove(&r.context);
        r
    };
    let ok = auth.seal(seal(vec![7; 64]), &t, &now).await.unwrap();
    assert_eq!(ok.caller().identity(), &id);
    assert_eq!(ok.caller().scope().matched_grants, vec![m.clone()]);

    // The body changed after proving: the purpose the authenticator computes differs.
    let mut changed = seal(vec![7; 64]);
    changed.sealed_payload[0] ^= 1;
    assert_eq!(auth.seal(changed, &t, &now).await.err().unwrap().code(), ErrorCode::NotAllowed);
    // Another enclave's key, an expired ticket, a stranger.
    let mut foreign = seal(vec![7; 64]);
    foreign.context.tls_spki_sha256 = [0; 32];
    foreign.proof = prove(&foreign.context);
    assert_eq!(auth.seal(foreign, &t, &now).await.err().unwrap().code(), ErrorCode::NotAllowed);
    assert_eq!(
        auth.seal(seal(vec![7; 64]), &t, &at(ticket.expires_at)).await.err().unwrap().code(),
        ErrorCode::NotAllowed
    );
    let stranger = verified(base_state(1));
    assert_eq!(auth.seal(seal(vec![7; 64]), &stranger, &now).await.err().unwrap().code(), ErrorCode::NotAllowed);

    // The other request kinds bind their own purpose the same way.
    let mut session = SessionRequest {
        blob: "seal1.x".into(),
        context: placeholder(),
        proof: prove(&placeholder()),
        min_tier: None,
        endpoint: None,
    };
    session.context = context(session.expected_purpose());
    session.proof = prove(&session.context);
    let mut tampered = SessionRequest { blob: "seal1.y".into(), ..session };
    assert_eq!(auth.session(tampered, &t, &now).await.err().unwrap().code(), ErrorCode::NotAllowed);
    tampered = SessionRequest {
        blob: "seal1.x".into(),
        context: placeholder(),
        proof: prove(&placeholder()),
        min_tier: None,
        endpoint: None,
    };
    tampered.context = context(tampered.expected_purpose());
    tampered.proof = prove(&tampered.context);
    auth.session(tampered, &t, &now).await.unwrap();

    let mut extend = ExtendRequest {
        token: Bearer::new("sealtok_a".into()),
        endpoint: None,
        context: placeholder(),
        proof: prove(&placeholder()),
    };
    extend.context = context(extend.expected_purpose());
    extend.proof = prove(&extend.context);
    auth.extend(extend, &t, &now).await.unwrap();

    let mut signal = SignalRequest {
        code: "edr-high".into(),
        severity: Severity::High,
        context: Some(placeholder()),
        proof: Some(prove(&placeholder())),
        identity: None,
        observed_at: None,
        blob_id: None,
        signatures: Vec::new(),
    };
    signal.context = Some(context(signal.expected_purpose()));
    signal.proof = signal.context.as_ref().map(prove);
    let swapped = SignalRequest { severity: Severity::Low, ..signal };
    assert_eq!(auth.signal(swapped, &t, &now).await.err().unwrap().code(), ErrorCode::NotAllowed);
    assert_eq!(s.requests(), 0);
}

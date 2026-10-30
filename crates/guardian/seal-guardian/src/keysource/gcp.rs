//! Cloud KMS through Confidential Space workload identity federation.
//!
//! The root is 32 bytes the guardian generated in its TEE, encrypted under one or more Cloud
//! KMS keys (`GOOGLE_SYMMETRIC_ENCRYPTION`) with `additionalAuthenticatedData` =
//! `seal-guardian/root/v1/<served platform>` (`root_aad`). Unwrapping it, all over
//! `seal_net::HttpsClient` (baked roots), no Google SDK:
//! 1. An OIDC attestation token from the Confidential Space launcher whose `aud` is the
//!    provider's audience, `//iam.googleapis.com/<provider>` (`AttestationTokens`).
//! 2. `POST https://sts.googleapis.com/v1/token`: token exchange (`subjectTokenType` jwt) →
//!    a federated access token for the pool principal.
//! 3. Only with `WorkloadIdentity::service_account`: `POST https://iamcredentials.googleapis.com`
//!    `/v1/projects/-/serviceAccounts/<sa>:generateAccessToken` with the federated token → a
//!    5-minute service account token. Without it the federated token is used directly (Cloud
//!    KMS accepts pool principals in its IAM policies).
//! 4. `POST https://cloudkms.googleapis.com/v1/<key>:decrypt` of each wrapped root in order
//!    until one opens; the plaintext must be exactly 32 bytes.
//!
//! `GcpKms::store` is the root ceremony's half (and a successor's, after
//! `KeySource::Predecessor`): encrypt the root under every listed key, then decrypt each new
//! ciphertext and compare, so a ceremony never records a copy that does not open.
//!
//! The wrapped roots are boot inputs, not part of the measured image: the image that runs
//! the ceremony, or that a predecessor hands its root to, cannot already contain the
//! ciphertext it produces. They are not secret. A substituted ciphertext opens only if made
//! with `cloudkms.cryptoKeyVersions.useToEncrypt` on the same key, and then boots a guardian
//! with another root, whose guardian key no client trusts (`seal_verify::Trust::guardians`):
//! an outage, never a leak. Keep every copy: a lost ciphertext is a lost root.
//!
//! # Setup (gcloud; `<n>` = project number, `<digest>` = the guardian image's `sha256:…`)
//!
//! ```text
//! POOL=projects/<n>/locations/global/workloadIdentityPools/<pool>
//! MAPPING=google.subject=assertion.sub,attribute.image_digest=assertion.submods.container.image_digest
//! gcloud kms keyrings create <ring> --location <loc>
//! gcloud kms keys create <key> --keyring <ring> --location <loc> --purpose encryption \
//!     --protection-level hsm --destroy-scheduled-duration 120d
//! gcloud iam workload-identity-pools create <pool> --location global
//! gcloud iam workload-identity-pools providers create-oidc <provider> --location global \
//!     --workload-identity-pool <pool> --issuer-uri https://confidentialcomputing.googleapis.com/ \
//!     --attribute-mapping "$MAPPING" \
//!     --attribute-condition "assertion.swname == 'CONFIDENTIAL_SPACE'
//!         && 'STABLE' in assertion.submods.confidential_space.support_attributes
//!         && assertion.dbgstat == 'disabled-since-boot'
//!         && assertion.submods.container.image_digest == '<digest>'"
//! gcloud kms keys add-iam-policy-binding <key> --keyring <ring> --location <loc> \
//!     --role roles/cloudkms.cryptoKeyDecrypter \
//!     --member "principalSet://iam.googleapis.com/$POOL/attribute.image_digest/<digest>"
//! ```
//!
//! No `--allowed-audiences`: the provider then accepts only its own name as the audience, so
//! a token minted for it is good for nothing else. The condition admits only the production
//! Confidential Space image (`STABLE`, not debuggable) running exactly this guardian image;
//! the binding repeats the digest, so widening the condition alone grants nothing. For
//! the ceremony, add `roles/cloudkms.cryptoKeyEncrypter` for the same principal set and
//! remove it afterwards. With a service account instead: grant it the KMS roles, grant the
//! principal set `roles/iam.workloadIdentityUser` on it, and set `service_account`. Keep the
//! root under keys in two locations, and no KMS role on the key ring, project, folder or
//! organization (those inherit to the key); a project of their own for the pool, provider and
//! keys keeps that set of administrators small.
//!
//! # What stays degraded
//!
//! All of the above is IAM: whoever administers the project, its folders or the organization
//! can at any time widen or drop the attribute condition, add members to the key's policy,
//! mint service account tokens, re-enable a disabled provider, or disable and destroy key
//! versions (destruction waits out the scheduled duration). Any of those, and then a plain
//! `gcloud kms decrypt` of a wrapped root, yields the root. Google is trusted too: the
//! Confidential Space attestation service signs the tokens STS accepts, and Cloud KMS holds
//! the key. No key source on GCP prevents this; only Azure Key Vault's immutable release
//! policy does.

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use seal_crypto::Key32;
use seal_net::HttpsClient;
use seal_proto::{PlatformId, SecretVec};
use seal_tee::Attestor;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::GuardianError;

const STS_TOKEN: &str = "https://sts.googleapis.com/v1/token";
const IAM_CREDENTIALS: &str = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/";
const CLOUD_KMS: &str = "https://cloudkms.googleapis.com/v1/";
const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// Lifetime asked of an impersonated service account token: enough for one boot or ceremony.
const SERVICE_ACCOUNT_TOKEN_LIFETIME: &str = "300s";
/// Longest error detail from Google kept in a `GuardianError::Root`.
const MAX_DETAIL: usize = 300;

/// Confidential Space attestation tokens for workload identity federation.
#[async_trait]
pub trait AttestationTokens: Send + Sync {
    /// An OIDC attestation token (a JWT signed by `https://confidentialcomputing.googleapis.com`)
    /// whose `aud` is `audience`, for the TEE `attestor` runs in.
    async fn token(&self, attestor: &Attestor, audience: &str) -> Result<String, GuardianError>;
}

/// The Confidential Space launcher's tokens, through `attestor`. `Root` on any other platform.
pub struct LauncherTokens;

#[async_trait]
impl AttestationTokens for LauncherTokens {
    async fn token(&self, attestor: &Attestor, audience: &str) -> Result<String, GuardianError> {
        match attestor {
            Attestor::GcpConfidentialSpace(launcher) => {
                launcher.oidc_token(audience).await.map_err(GuardianError::from)
            }
            other => Err(GuardianError::Root(format!(
                "gcp kms: attestation tokens come from Confidential Space, not {:?}",
                other.platform()
            ))),
        }
    }
}

/// Who the guardian is to Google: a workload identity pool provider, and optionally a service
/// account it impersonates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    /// `projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.
    pub provider: String,
    /// `<name>@<project>.iam.gserviceaccount.com`, or `None` to use the federated token itself.
    #[serde(default)]
    pub service_account: Option<String>,
}

impl WorkloadIdentity {
    /// The audience attestation tokens carry and STS is asked for: `//iam.googleapis.com/<provider>`.
    pub fn audience(&self) -> String {
        format!("//iam.googleapis.com/{}", self.provider)
    }
}

/// One copy of the root: a Cloud KMS key and the root encrypted under it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsWrappedRoot {
    /// `projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>`.
    pub key_name: String,
    /// Cloud KMS ciphertext; standard base64 in JSON, as `gcloud` and the API write it.
    #[serde(with = "standard_b64")]
    pub wrapped_root: Vec<u8>,
}

/// `additionalAuthenticatedData` of every wrapped root for `platform`: a ciphertext made under
/// the same key for anything else, or for another served platform, never opens as this root.
pub fn root_aad(platform: PlatformId) -> String {
    let name = serde_json::to_value(platform).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
    format!("seal-guardian/root/v1/{name}")
}

/// Cloud KMS as one guardian identity: federated tokens, encrypt and decrypt.
pub struct GcpKms {
    platform: PlatformId,
    identity: WorkloadIdentity,
    https: Arc<HttpsClient>,
    tokens: Arc<dyn AttestationTokens>,
}

impl GcpKms {
    /// For a guardian serving `platform` (bound into every wrapped root, `root_aad`), with
    /// tokens from the launcher (`LauncherTokens`). `Root` if `identity` is malformed.
    pub fn new(
        platform: PlatformId,
        identity: WorkloadIdentity,
        https: Arc<HttpsClient>,
    ) -> Result<Self, GuardianError> {
        let provider = ["projects", "#", "locations", "global", "workloadIdentityPools", "*", "providers", "*"];
        if !matches_shape(&identity.provider, &provider) {
            return Err(config_err(format!("not a workload identity provider name: {:?}", identity.provider)));
        }
        if let Some(sa) = &identity.service_account {
            let ok = sa.split_once('@').is_some_and(|(name, domain)| {
                !name.is_empty()
                    && domain.ends_with(".gserviceaccount.com")
                    && sa.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.@_".contains(&b))
            });
            if !ok {
                return Err(config_err(format!("not a service account email: {sa:?}")));
            }
        }
        Ok(Self { platform, identity, https, tokens: Arc::new(LauncherTokens) })
    }

    /// Sim builds only: attestation tokens from `tokens` instead of the launcher (a fake Cloud
    /// KMS's tests).
    #[cfg(feature = "sim")]
    pub fn with_tokens(self, tokens: Arc<dyn AttestationTokens>) -> Self {
        Self { tokens, ..self }
    }

    /// The ceremony: encrypts `root` under each of `key_names` and checks that every new
    /// ciphertext decrypts back to `root`. All or nothing: `Root` if any key fails.
    pub async fn store(
        &self,
        root: &Key32,
        key_names: &[String],
        attestor: &Attestor,
    ) -> Result<Vec<KmsWrappedRoot>, GuardianError> {
        if key_names.is_empty() {
            return Err(config_err("no Cloud KMS key to store the root under".into()));
        }
        for key_name in key_names {
            check_key_name(key_name)?;
        }
        let access = self.access_token(attestor).await?;
        let mut copies = Vec::with_capacity(key_names.len());
        for key_name in key_names {
            let wrapped_root = self.encrypt(&access, key_name, root.expose()).await?;
            let opened = self.decrypt(&access, key_name, &wrapped_root).await?;
            if !seal_proto::secret::ct_eq(opened.expose(), root.expose()) {
                return Err(GuardianError::Root(format!(
                    "gcp kms: {key_name}: the new ciphertext does not open to the root"
                )));
            }
            tracing::info!(key = %key_name, "root stored in Cloud KMS");
            copies.push(KmsWrappedRoot { key_name: key_name.clone(), wrapped_root });
        }
        Ok(copies)
    }

    /// Steps 1-3: an access token for Cloud KMS.
    async fn access_token(&self, attestor: &Attestor) -> Result<String, GuardianError> {
        let audience = self.identity.audience();
        let subject = self.tokens.token(attestor, &audience).await?;
        let request = serde_json::json!({
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": audience,
            "scope": SCOPE,
            "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
            "subjectToken": subject,
            "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
        });
        let sts: StsResponse = self.post("sts", STS_TOKEN, None, &to_body(&request)).await?;
        if !sts.token_type.eq_ignore_ascii_case("bearer") || sts.access_token.is_empty() {
            return Err(GuardianError::Root("gcp kms: sts: no bearer access token in the response".into()));
        }
        let Some(sa) = &self.identity.service_account else { return Ok(sts.access_token) };
        let url = format!("{IAM_CREDENTIALS}{sa}:generateAccessToken");
        let request = serde_json::json!({"scope": [SCOPE], "lifetime": SERVICE_ACCOUNT_TOKEN_LIFETIME});
        let token: GenerateAccessTokenResponse =
            self.post("iamcredentials", &url, Some(&sts.access_token), &to_body(&request)).await?;
        if token.access_token.is_empty() {
            return Err(GuardianError::Root("gcp kms: iamcredentials: empty access token".into()));
        }
        Ok(token.access_token)
    }

    async fn encrypt(&self, access: &str, key_name: &str, plaintext: &[u8]) -> Result<Vec<u8>, GuardianError> {
        let aad = STANDARD.encode(root_aad(self.platform));
        let body = encrypt_body(plaintext, &aad);
        let url = format!("{CLOUD_KMS}{key_name}:encrypt");
        let resp: EncryptResponse = self.post(&format!("{key_name}: encrypt"), &url, Some(access), &body).await?;
        let name_ok = resp.name == key_name || resp.name.starts_with(&format!("{key_name}/cryptoKeyVersions/"));
        if !name_ok || resp.ciphertext.is_empty() {
            return Err(GuardianError::Root(format!("gcp kms: {key_name}: encrypt answered for another key")));
        }
        Ok(resp.ciphertext)
    }

    async fn decrypt(&self, access: &str, key_name: &str, ciphertext: &[u8]) -> Result<SecretVec, GuardianError> {
        let request = serde_json::json!({
            "ciphertext": STANDARD.encode(ciphertext),
            "additionalAuthenticatedData": STANDARD.encode(root_aad(self.platform)),
        });
        let url = format!("{CLOUD_KMS}{key_name}:decrypt");
        let resp: DecryptResponse =
            self.post(&format!("{key_name}: decrypt"), &url, Some(access), &to_body(&request)).await?;
        Ok(resp.plaintext)
    }

    /// POSTs `body` as JSON with an optional bearer token. 200 → the parsed response; anything
    /// else → `Root` naming `step`, the status and Google's error message. Response bodies are
    /// wiped after parsing: a decrypt response holds the root.
    async fn post<T: DeserializeOwned>(
        &self,
        step: &str,
        url: &str,
        bearer: Option<&str>,
        body: &SecretVec,
    ) -> Result<T, GuardianError> {
        let auth = bearer.map(|token| format!("Bearer {token}"));
        let headers: Vec<(&str, &str)> = auth.iter().map(|a| ("authorization", a.as_str())).collect();
        let (status, resp) = self
            .https
            .post(url, &headers, body.expose())
            .await
            .map_err(|e| GuardianError::Root(format!("gcp kms: {step}: {e}")))?;
        let resp = SecretVec::new(resp);
        if status != 200 {
            return Err(GuardianError::Root(format!("gcp kms: {step}: HTTP {status}{}", error_detail(resp.expose()))));
        }
        serde_json::from_slice(resp.expose())
            .map_err(|e| GuardianError::Root(format!("gcp kms: {step}: malformed response: {e}")))
    }
}

/// Cloud KMS decrypt of a wrapped root through workload identity federation (see the module
/// documentation for the flow, the setup and what Google and the project's administrators can
/// still do). The copies are tried in order; boot fails only if none opens.
pub struct GcpKmsKeySource {
    kms: GcpKms,
    roots: Vec<KmsWrappedRoot>,
}

impl GcpKmsKeySource {
    /// `Root` if `roots` is empty or names a malformed key.
    pub fn new(kms: GcpKms, roots: Vec<KmsWrappedRoot>) -> Result<Self, GuardianError> {
        if roots.is_empty() {
            return Err(config_err("no wrapped root".into()));
        }
        for root in &roots {
            check_key_name(&root.key_name)?;
        }
        Ok(Self { kms, roots })
    }

    pub(crate) async fn root_secret(&self, attestor: &Attestor) -> Result<Key32, GuardianError> {
        let access = self.kms.access_token(attestor).await?;
        let mut failures = Vec::new();
        for copy in &self.roots {
            let opened = self.kms.decrypt(&access, &copy.key_name, &copy.wrapped_root).await.and_then(|plaintext| {
                Key32::from_secret_vec(&plaintext).map_err(|_| {
                    GuardianError::Root(format!(
                        "gcp kms: {}: decrypted {} bytes, not a 32-byte root",
                        copy.key_name,
                        plaintext.expose().len()
                    ))
                })
            });
            match opened {
                Ok(root) => return Ok(root),
                Err(e) => {
                    tracing::warn!(key = %copy.key_name, error = %e, "wrapped root did not open");
                    failures.push(e.to_string());
                }
            }
        }
        Err(GuardianError::Root(failures.join("; ")))
    }
}

#[derive(Deserialize)]
struct StsResponse {
    access_token: String,
    token_type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateAccessTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct EncryptResponse {
    name: String,
    #[serde(with = "standard_b64")]
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    #[serde(deserialize_with = "secret_b64")]
    plaintext: SecretVec,
}

fn config_err(reason: String) -> GuardianError {
    GuardianError::Root(format!("gcp kms config: {reason}"))
}

fn check_key_name(name: &str) -> Result<(), GuardianError> {
    let shape = ["projects", "*", "locations", "*", "keyRings", "*", "cryptoKeys", "*"];
    if matches_shape(name, &shape) {
        Ok(())
    } else {
        Err(config_err(format!("not a Cloud KMS key name: {name:?}")))
    }
}

/// `name`'s `/`-separated segments against `shape`: a literal, `*` (one non-empty segment of
/// ASCII letters, digits, `-` and `_`) or `#` (digits). Names are spliced into request URLs,
/// so nothing else (`?`, `%`, `.`, `:`) gets through.
fn matches_shape(name: &str, shape: &[&str]) -> bool {
    let segments: Vec<&str> = name.split('/').collect();
    segments.len() == shape.len()
        && segments.iter().zip(shape).all(|(segment, want)| match *want {
            "*" => !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "#" => !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()),
            literal => *segment == literal,
        })
}

fn to_body(value: &serde_json::Value) -> SecretVec {
    SecretVec::new(serde_json::to_vec(value).expect("a JSON value serializes"))
}

/// The encrypt request, `{"plaintext":"<base64>","additionalAuthenticatedData":"<aad_b64>"}`,
/// built in one allocation, so no unwiped copy of the secret is left behind, and encoded in
/// constant time (`base64ct`).
fn encrypt_body(secret: &[u8], aad_b64: &str) -> SecretVec {
    use base64ct::Encoding as _;
    let head = "{\"plaintext\":\"";
    let tail = format!("\",\"additionalAuthenticatedData\":\"{aad_b64}\"}}");
    let encoded = base64ct::Base64::encoded_len(secret);
    let mut body = Vec::with_capacity(head.len() + encoded + tail.len());
    body.extend_from_slice(head.as_bytes());
    body.resize(head.len() + encoded, 0);
    let written = base64ct::Base64::encode(secret, &mut body[head.len()..]).expect("sized above").len();
    debug_assert_eq!(written, encoded);
    body.extend_from_slice(tail.as_bytes());
    SecretVec::new(body)
}

/// Google's error detail: `error.message` (Google APIs) or `error_description` (STS), cut to
/// `MAX_DETAIL` characters; empty if the body is neither.
fn error_detail(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else { return String::new() };
    let error = &value["error"];
    let detail = match (
        error.as_str(),
        value["error_description"].as_str(),
        error["status"].as_str(),
        error["message"].as_str(),
    ) {
        (Some(code), Some(description), _, _) => format!("{code}: {description}"),
        (Some(code), None, _, _) => code.to_string(),
        (None, _, Some(status), Some(message)) => format!("{status}: {message}"),
        (None, _, None, Some(message)) => message.to_string(),
        _ => return String::new(),
    };
    format!(" ({})", detail.chars().take(MAX_DETAIL).collect::<String>())
}

/// Standard base64 with padding, as Google's JSON APIs write bytes.
mod standard_b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// Standard base64 straight into a `SecretVec`, without an owned copy of the encoded secret,
/// in constant time (`base64ct`): the root's characters pick no table entry and no branch.
fn secret_b64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SecretVec, D::Error> {
    struct V;
    impl serde::de::Visitor<'_> for V {
        type Value = SecretVec;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a standard base64 string")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<SecretVec, E> {
            use base64ct::Encoding as _;
            let mut out = vec![0; v.len().div_ceil(4) * 3];
            let decoded = base64ct::Base64::decode(v, &mut out).map(<[u8]>::len);
            // Truncating keeps the allocation, so the `SecretVec` wipes all of it.
            out.truncate(*decoded.as_ref().unwrap_or(&0));
            let out = SecretVec::new(out);
            decoded.map(|_| out).map_err(|_| E::custom("plaintext is not standard base64"))
        }
    }
    d.deserialize_str(V)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypted_roots_decode_strictly() {
        let plaintext =
            |json: &str| serde_json::from_str::<DecryptResponse>(json).map(|r| r.plaintext.expose().to_vec());
        for len in [0, 1, 2, 3, 31, 32, 33] {
            let root: Vec<u8> = (0..len).map(|i| (i * 53 + 7) as u8).collect();
            let json = format!(r#"{{"plaintext":"{}","usedPrimary":true}}"#, STANDARD.encode(&root));
            assert_eq!(plaintext(&json).unwrap(), root, "{len}");
        }
        // Unpadded, URL-safe, stray trailing bits, a broken group: refused.
        for bad in ["AAA", "AB==", "-_8=", "AA=A", "A===", "AAAA AAAA"] {
            assert!(plaintext(&format!(r#"{{"plaintext":"{bad}"}}"#)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn encrypt_body_is_the_json_request() {
        let root = [0xfbu8; 32];
        let body = encrypt_body(&root, "YWFk");
        let value: serde_json::Value = serde_json::from_slice(body.expose()).unwrap();
        assert_eq!(value["plaintext"], STANDARD.encode(root));
        assert_eq!(value["additionalAuthenticatedData"], "YWFk");
    }
}

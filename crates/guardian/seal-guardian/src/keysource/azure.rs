//! Azure Key Vault Premium through Secure Key Release (SKR), from an ACI confidential group.
//!
//! The root is 32 bytes the guardian generated in its TEE, RSA-OAEP-SHA256-wrapped under an
//! exportable `RSA-HSM` key (label `root_aad(<served platform>)`, as Cloud KMS's AAD), one copy
//! per vault. Opening a copy, all over `seal_net::HttpsClient` (baked roots), no Azure SDK:
//! 1. A fresh RSA-3072 key; runtime data = its JWK set (`key_ops: ["encrypt"]`). An SNP report
//!    whose `report_data[0..32]` = SHA-256(runtime data): the one report not bound to a Seal
//!    binding.
//! 2. `POST <maa>/attest/SevSnpVm` on a Microsoft shared regional endpoint (a customer-owned
//!    attestation provider's owner could change its policy): the report, the VCEK chain (the
//!    VCEK and the baked ASK and ARK) and the UVM endorsement → a token carrying the runtime key.
//! 3. A managed identity token for `https://vault.azure.net` from IMDS (`169.254.169.254`).
//! 4. `POST <vault>/keys/<name>/<version>/release` with the token and `enc =
//!    RSA_AES_KEY_WRAP_256`. The answer is a JWS (RS256, `x5c`) whose certificate chains to a
//!    baked root and names the vault's host (Key Vault signs with its TLS certificate); its
//!    payload names exactly the pinned key version, an exportable RSA key and its immutable
//!    release policy (`check_release_policy`).
//!    `key_hsm` holds RSA-OAEP-SHA256(KEK) ‖ AES-KWP (RFC 5649) of the key (PKCS#8 DER), wrapped
//!    to the ephemeral key.
//! 5. The released key RSA-OAEP-SHA256-unwraps the copy; it must be exactly 32 bytes.
//!
//! `KeyVault::store` is the root ceremony's half (and a successor's, after
//! `KeySource::Predecessor`): for each vault, a release as above of the key's current version
//! (`POST <vault>/keys/<name>/release`, the version read from the answer), refused unless the
//! key is at least 3072 bits and its release policy is immutable and pins this guardian; the
//! root wrapped under its public key, and the new copy opened with the released key. So a
//! ceremony never records a copy that does not open, nor wraps the root under a key whose
//! policy anyone could change, and it needs the same role as a boot.
//!
//! The wrapped roots and key versions are boot inputs, not part of the measured image: the key's
//! policy pins `host_data`, which covers the image, so the image cannot name the key version or
//! contain the copy. They are not secret. A substituted copy, or a key version whose policy does
//! not pin this guardian, boots a guardian with another root, whose guardian key no client
//! trusts (`seal_verify::Trust::guardians`): an outage, never a leak. Keep every copy: a lost
//! copy is a lost root.
//!
//! Managed HSM is designed, not implemented: the guardian imports the root at the ceremony as
//! an exportable 256-bit `oct-HSM` key under the same immutable policy, and a release returns
//! the root itself (no wrapped root). This build refuses such a copy, or a key of any type but
//! `RSA-HSM`, by name.
//!
//! # Setup (az; `<host_data>` = the guardian group's policy hash, from `seal-release aci-policy
//! --component guardian`; `<mi>` = the principal id of the group's user-assigned identity)
//!
//! ```text
//! az keyvault create -n <vault> -g <rg> -l <region> --sku premium \
//!     --enable-rbac-authorization true --enable-purge-protection true --retention-days 90
//! seal-release kv-release-policy --host-data <host_data> > policy.json
//! az keyvault key create --vault-name <vault> -n <key> --kty RSA-HSM --size 3072 \
//!     --exportable true --immutable true --policy @policy.json --ops encrypt
//! az role assignment create --role "Key Vault Crypto Service Release User" \
//!     --assignee-object-id <mi> --assignee-principal-type ServicePrincipal \
//!     --scope "$(az keyvault show -n <vault> --query id -o tsv)/keys/<key>"
//! ```
//!
//! The release role (`keys/release/action` only) is all the guardian needs, for the ceremony
//! and every boot; scope it to the key. An access-policy vault (`--enable-rbac-authorization
//! false`) works the same with `az keyvault set-policy --key-permissions release`, but its
//! access policies are vault-wide and editable by anyone with `Microsoft.KeyVault/vaults/write`:
//! production vaults use RBAC. Key Vault keeps an immutable policy for every later version of
//! the key, so each guardian measurement gets a key (name) of its own, and its build names it.
//!
//! The policy (version 1.0.0) has one branch whose `authority` is the pinned attestation
//! endpoint and whose `allOf` requires `x-ms-attestation-type` = `sevsnpvm`,
//! `x-ms-compliance-status` = `azure-compliant-uvm`, `x-ms-sevsnpvm-hostdata` = the guardian's
//! host_data, `x-ms-sevsnpvm-is-debuggable` = false and `x-ms-sevsnpvm-vmpl` = 0. TCB minimums
//! are the guardian's (`ReleaseConstraints`), never in the policy, so they can rise without a new
//! key. Delete locks on the vault and no other principal with the release role on it keep the
//! administrators who could delete or deny the key few; none of them can read it.
//!
//! # What stays trusted
//!
//! The policy is immutable: no Azure administrator, Seal's included, can release the key to
//! anything but this guardian's measurement on genuine SNP hardware. Microsoft is trusted: its
//! attestation service signs the tokens Key Vault accepts, its UVM endorsement says what the
//! utility VM is, and Key Vault's HSMs hold the key. Administrators can delete the key (purge
//! protection delays that) or withhold the release role: an outage, not a leak. The ceremony
//! operator is trusted once, as on every key source: a root generated outside the TEE and
//! wrapped under the public key would boot too, so publish the guardian key only from a booted
//! guardian's attested identity after a ceremony you watched.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD, URL_SAFE};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::traits::PublicKeyParts as _;
use rsa::{BoxedUint, Oaep, RsaPrivateKey, RsaPublicKey};
use seal_crypto::{Key32, SysRng, UnwrapErr};
use seal_net::HttpsClient;
use seal_proto::{Evidence, PlatformId, SecretVec};
use seal_tee::Attestor;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::gcp::root_aad;
use crate::GuardianError;

/// Key Vault REST API version.
const API_VERSION: &str = "7.4";
/// The managed identity token's resource: Key Vault (not Managed HSM).
const VAULT_RESOURCE: &str = "https://vault.azure.net";
const VAULT_HOST_SUFFIX: &str = ".vault.azure.net";
const MAA_HOST_SUFFIX: &str = ".attest.azure.net";
/// The release's key wrapping: RSA-OAEP-SHA256 of an AES-256 key, then AES-KWP of the key.
const RELEASE_ENC: &str = "RSA_AES_KEY_WRAP_256";
/// The ephemeral key's `kid` in the runtime data.
const RUNTIME_KID: &str = "seal-guardian-release";
const EPHEMERAL_BITS: usize = 3072;
/// Smallest vault key the root is wrapped under.
const MIN_VAULT_KEY_BITS: usize = 3072;
const IMDS_ADDRESS: (&str, u16) = ("169.254.169.254", 80);
const IMDS_TOKEN_PATH: &str = "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=";
const IMDS_TIMEOUT: Duration = Duration::from_secs(10);
/// Token requests. IMDS answers 404, 410, 429 and 5xx while the identity is still being
/// attached; those and failed connections are retried after 1, 2, 4 and 8 s.
const IMDS_ATTEMPTS: u32 = 5;
const MAX_IMDS_ANSWER: usize = 64 * 1024;
/// Longest error detail from Azure kept in a `GuardianError::Root`.
const MAX_DETAIL: usize = 300;

/// Base64url as Azure writes it: with or without padding.
const B64URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// What Key Vault is shown: the guardian's `host_data`, attestation tokens from Microsoft Azure
/// Attestation and the managed identity's tokens.
#[async_trait]
pub trait VaultCredentials: Send + Sync {
    /// The `host_data` of the group `attestor` runs in: what release policies must pin.
    fn host_data(&self, attestor: &Attestor) -> Result<[u8; 32], GuardianError>;
    /// A token from `maa_endpoint` for the TEE `attestor` runs in, whose runtime data
    /// (`x-ms-runtime`) is `runtime_data`.
    async fn maa_token(
        &self,
        attestor: &Attestor,
        maa_endpoint: &str,
        runtime_data: &[u8],
    ) -> Result<String, GuardianError>;
    /// An access token for Key Vault (`https://vault.azure.net`).
    async fn vault_token(&self) -> Result<String, GuardianError>;
}

/// An ACI confidential group's: SNP reports through `attestor`, MAA over `https`, the
/// group's managed identity from IMDS. `Root` on any other platform.
struct AciCredentials {
    https: Arc<HttpsClient>,
    dialer: Arc<dyn seal_net::Dialer>,
}

impl AciCredentials {
    fn new(https: Arc<HttpsClient>, dialer: Arc<dyn seal_net::Dialer>) -> Self {
        Self { https, dialer }
    }

    /// One IMDS `GET` with `Metadata: true`: the status and at most `MAX_IMDS_ANSWER` bytes.
    async fn imds_get(&self, path: &str) -> Result<(u16, SecretVec), String> {
        let (host, port) = IMDS_ADDRESS;
        let request = hyper::Request::get(path)
            .header(hyper::header::HOST, host)
            .header("metadata", "true")
            .body(Empty::<hyper::body::Bytes>::new())
            .map_err(|e| e.to_string())?;
        let exchange = async {
            let stream = self.dialer.dial(host, port).await.map_err(|e| e.to_string())?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| e.to_string())?;
            let conn = tokio::spawn(conn);
            let answer = async {
                let response = sender.send_request(request).await.map_err(|e| e.to_string())?;
                let status = response.status().as_u16();
                let body =
                    Limited::new(response.into_body(), MAX_IMDS_ANSWER).collect().await.map_err(|e| e.to_string())?;
                Ok((status, SecretVec::new(body.to_bytes().to_vec())))
            }
            .await;
            conn.abort();
            answer
        };
        tokio::time::timeout(IMDS_TIMEOUT, exchange).await.map_err(|_| "timed out".to_owned())?
    }
}

#[async_trait]
impl VaultCredentials for AciCredentials {
    fn host_data(&self, attestor: &Attestor) -> Result<[u8; 32], GuardianError> {
        match attestor {
            Attestor::AzureSnpAci(snp) => Ok(snp.host_data()),
            other => Err(GuardianError::Root(format!(
                "key vault: release needs an ACI confidential group, not {:?}",
                other.platform()
            ))),
        }
    }

    async fn maa_token(
        &self,
        attestor: &Attestor,
        maa_endpoint: &str,
        runtime_data: &[u8],
    ) -> Result<String, GuardianError> {
        self.host_data(attestor)?;
        let Evidence::AzureSnpAci { report, vcek_der, uvm_endorsement } =
            attestor.attest(Sha256::digest(runtime_data).into()).await?
        else {
            return Err(GuardianError::Root("key vault: the attestor gave no SNP evidence".into()));
        };
        let chain = seal_attest::azure::amd_chain_pem(&vcek_der)
            .ok_or_else(|| GuardianError::Root("maa: no baked AMD chain certifies the VCEK".into()))?;
        let endorsement = STANDARD
            .decode(uvm_endorsement.trim())
            .map_err(|_| GuardianError::Root("maa: the UVM endorsement is not base64".into()))?;
        let request = maa_request(&report, &pem("CERTIFICATE", &vcek_der), chain, &endorsement, runtime_data);
        let url = format!("{maa_endpoint}/attest/SevSnpVm?api-version=2022-08-01");
        let (status, body) =
            self.https.post(&url, &[], &request).await.map_err(|e| GuardianError::Root(format!("maa: {e}")))?;
        if status != 200 {
            return Err(GuardianError::Root(format!("maa: HTTP {status}{}", error_detail(&body))));
        }
        #[derive(Deserialize)]
        struct Answer {
            token: String,
        }
        let answer: Answer =
            serde_json::from_slice(&body).map_err(|e| GuardianError::Root(format!("maa: malformed response: {e}")))?;
        Ok(answer.token)
    }

    async fn vault_token(&self) -> Result<String, GuardianError> {
        let resource: String = url::form_urlencoded::byte_serialize(VAULT_RESOURCE.as_bytes()).collect();
        let path = format!("{IMDS_TOKEN_PATH}{resource}");
        let mut delay = Duration::from_secs(1);
        for attempt in 1..=IMDS_ATTEMPTS {
            let failure = match self.imds_get(&path).await {
                Ok((200, body)) => {
                    #[derive(Deserialize)]
                    struct Answer {
                        access_token: String,
                    }
                    let answer: Answer = serde_json::from_slice(body.expose())
                        .map_err(|_| GuardianError::Root("imds: answered without an access_token".into()))?;
                    return Ok(answer.access_token);
                }
                Ok((status, _)) if !matches!(status, 404 | 410 | 429 | 500..=599) => {
                    return Err(GuardianError::Root(format!("imds: HTTP {status}")))
                }
                Ok((status, _)) => format!("HTTP {status}"),
                Err(e) => e,
            };
            if attempt == IMDS_ATTEMPTS {
                return Err(GuardianError::Root(format!("imds: {failure}")));
            }
            tracing::debug!(attempt, %failure, "IMDS token request failed; retrying");
            tokio::time::sleep(delay).await;
            delay *= 2;
        }
        unreachable!("the last attempt returns")
    }
}

/// MAA's `SevSnpVm` request: the report, `VcekCertChain` (PEM: VCEK, ASK, ARK) and the UVM
/// endorsement inside a base64url JSON `report`, and the runtime data as JSON.
fn maa_request(report: &[u8], vcek_pem: &str, chain_pem: &str, endorsement: &[u8], runtime_data: &[u8]) -> Vec<u8> {
    let b64 = |bytes: &[u8]| URL_SAFE.encode(bytes);
    let endorsements = serde_json::json!({"Uvm": [b64(endorsement)]});
    let inner = serde_json::json!({
        "SnpReport": b64(report),
        "VcekCertChain": b64(format!("{vcek_pem}{chain_pem}").as_bytes()),
        "Endorsements": b64(endorsements.to_string().as_bytes()),
    });
    let request = serde_json::json!({
        "report": b64(inner.to_string().as_bytes()),
        "runtimeData": {"data": b64(runtime_data), "dataType": "JSON"},
    });
    serde_json::to_vec(&request).expect("a JSON value serializes")
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let lines: Vec<&str> =
        b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).expect("base64 is ASCII")).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// A vault key to store the root under: the ceremony takes its current version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultKeyName {
    /// `https://<vault>.vault.azure.net`.
    pub vault_url: String,
    pub key_name: String,
}

/// One copy of the root: a pinned key version in one vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultKey {
    pub vault_url: String,
    pub key_name: String,
    pub key_version: String,
    /// `RSA-HSM` keys: the root, RSA-OAEP-SHA256-wrapped under the key (label `root_aad`).
    /// `None` for a Managed HSM `oct-HSM` key, whose bytes would be the root (not implemented).
    pub wrapped_root: Option<Vec<u8>>,
}

/// Key Vault as one guardian: Secure Key Release of its keys, and the ceremony's wrap.
pub struct KeyVault {
    platform: PlatformId,
    maa_endpoint: String,
    https: Arc<HttpsClient>,
    credentials: Arc<dyn VaultCredentials>,
    jws_roots: Arc<rustls::RootCertStore>,
}

/// What one boot or ceremony shows every vault: the same token and ephemeral key.
struct Session {
    host_data: [u8; 32],
    access: String,
    ephemeral: RsaPrivateKey,
    maa_token: String,
}

impl KeyVault {
    /// For a guardian serving `platform` (the label of every wrapped root, `root_aad`), with
    /// attestation tokens from `maa_endpoint` (`https://<name>.<region>.attest.azure.net`) and
    /// credentials from the ACI group (`AciCredentials`). `Root` if the endpoint is malformed.
    pub fn new(platform: PlatformId, maa_endpoint: String, https: Arc<HttpsClient>) -> Result<Self, GuardianError> {
        let maa_endpoint = maa_endpoint.trim_end_matches('/').to_owned();
        if !https_host(&maa_endpoint).is_some_and(|h| h.ends_with(MAA_HOST_SUFFIX)) {
            return Err(config_err(format!("not an attestation endpoint: {maa_endpoint:?}")));
        }
        let credentials = Arc::new(AciCredentials::new(https.clone(), Arc::new(seal_net::TcpDialer)));
        Ok(Self { platform, maa_endpoint, https, credentials, jws_roots: Arc::new(seal_net::baked_roots()) })
    }

    /// Sim builds only: host_data, attestation and access tokens from `credentials` instead of
    /// the group (a fake Key Vault's tests).
    #[cfg(feature = "sim")]
    pub fn with_credentials(self, credentials: Arc<dyn VaultCredentials>) -> Self {
        Self { credentials, ..self }
    }

    /// Sim builds only: also trust these PEM roots for the release JWS's certificate.
    #[cfg(feature = "sim")]
    pub fn with_extra_jws_roots(self, pem: &[u8]) -> Result<Self, GuardianError> {
        use rustls::pki_types::pem::PemObject as _;
        let mut roots = (*self.jws_roots).clone();
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|e| config_err(format!("extra JWS roots: {e}")))?;
            roots.add(cert).map_err(|e| config_err(format!("extra JWS roots: {e}")))?;
        }
        Ok(Self { jws_roots: Arc::new(roots), ..self })
    }

    /// The ceremony (module docs): wraps `root` under the current version of each of `keys`
    /// and checks every new copy opens to `root`. All or nothing: `Root` if any key fails.
    pub async fn store(
        &self,
        root: &Key32,
        keys: &[VaultKeyName],
        attestor: &Attestor,
    ) -> Result<Vec<VaultKey>, GuardianError> {
        if keys.is_empty() {
            return Err(config_err("no vault key to store the root under".into()));
        }
        for key in keys {
            check_key_name(&key.vault_url, &key.key_name)?;
        }
        let session = self.session(attestor).await?;
        let mut copies = Vec::with_capacity(keys.len());
        for key in keys {
            let what = format!("{}/keys/{}", key.vault_url, key.key_name);
            let (key_version, released) = self.release(&session, &key.vault_url, &key.key_name, None).await?;
            let public = released.to_public_key();
            if (public.n().bits() as usize) < MIN_VAULT_KEY_BITS {
                return Err(GuardianError::Root(format!(
                    "key vault: {what}: an RSA key of {} bits, below {MIN_VAULT_KEY_BITS}",
                    public.n().bits()
                )));
            }
            let oaep = Oaep::<Sha256>::new_with_label(root_aad(self.platform).into_bytes());
            let wrapped = public
                .encrypt(&mut UnwrapErr(SysRng), oaep, root.expose())
                .map_err(|e| GuardianError::Root(format!("key vault: {what}: wrap: {e}")))?;
            let copy = VaultKey {
                vault_url: key.vault_url.clone(),
                key_name: key.key_name.clone(),
                key_version,
                wrapped_root: Some(wrapped),
            };
            let opened = self.unwrap_root(&released, &copy)?;
            if opened.expose() != root.expose() {
                return Err(GuardianError::Root(format!("key vault: {what}: the new copy does not open to the root")));
            }
            tracing::info!(key = %what, version = %copy.key_version, "root stored in Key Vault");
            copies.push(copy);
        }
        Ok(copies)
    }

    /// Steps 1-3 of the module docs: host_data, the access token, the ephemeral key and the
    /// attestation token carrying it.
    async fn session(&self, attestor: &Attestor) -> Result<Session, GuardianError> {
        let host_data = self.credentials.host_data(attestor)?;
        let access = self.credentials.vault_token().await?;
        let ephemeral = RsaPrivateKey::new(&mut UnwrapErr(SysRng), EPHEMERAL_BITS)
            .map_err(|e| GuardianError::Root(format!("key vault: ephemeral key: {e}")))?;
        let runtime_data = runtime_data(&ephemeral.to_public_key());
        let maa_token = self.credentials.maa_token(attestor, &self.maa_endpoint, &runtime_data).await?;
        Ok(Session { host_data, access, ephemeral, maa_token })
    }

    /// Step 4: the released key of `version` of `key_name`, or of its current version (the
    /// ceremony), with the version it is.
    async fn release(
        &self,
        session: &Session,
        vault_url: &str,
        key_name: &str,
        version: Option<&str>,
    ) -> Result<(String, RsaPrivateKey), GuardianError> {
        let key = format!("{vault_url}/keys/{key_name}");
        let what = match version {
            Some(version) => format!("{key}/{version}"),
            None => key.clone(),
        };
        let url = format!("{what}/release?api-version={API_VERSION}");
        let request = serde_json::json!({"target": session.maa_token, "enc": RELEASE_ENC});
        let body = serde_json::to_vec(&request).expect("a JSON value serializes");
        let answer: ReleaseAnswer = self.post(&format!("{what}: release"), &url, &session.access, &body).await?;
        let fail = |reason: String| GuardianError::Root(format!("key vault: {what}: release: {reason}"));
        let host = https_host(vault_url).expect("checked vault URL");
        let payload = verify_release_jws(&answer.value, host, &self.jws_roots).map_err(fail)?;
        let payload: ReleasePayload =
            serde_json::from_slice(payload.expose()).map_err(|e| fail(format!("malformed payload: {e}")))?;
        let released = payload.response.key;
        let named = released.key.kid.strip_prefix(&format!("{key}/")).filter(|v| is_key_version(v));
        let key_version = match (named, version) {
            (Some(named), Some(pinned)) if named == pinned => named.to_owned(),
            (Some(named), None) => named.to_owned(),
            _ => return Err(fail(format!("the release names {:?}, not the pinned key version", released.key.kid))),
        };
        // Key Vault names a released RSA-HSM key's type `RSA`.
        if released.key.kty != "RSA" && released.key.kty != "RSA-HSM" {
            return Err(fail(not_rsa(&released.key.kty)));
        }
        check_bundle(&released.attributes, released.release_policy.as_ref(), &session.host_data, &self.maa_endpoint)
            .map_err(fail)?;
        let key_hsm = released.key.key_hsm.ok_or_else(|| fail("no key_hsm in the release".into()))?;
        Ok((key_version, unwrap_released(&session.ephemeral, &key_hsm).map_err(fail)?))
    }

    /// Step 5.
    fn unwrap_root(&self, released: &RsaPrivateKey, copy: &VaultKey) -> Result<Key32, GuardianError> {
        let what = format!("{}/keys/{}/{}", copy.vault_url, copy.key_name, copy.key_version);
        let wrapped =
            copy.wrapped_root.as_ref().ok_or_else(|| GuardianError::Root(format!("key vault: {what}: {OCT}")))?;
        let oaep = Oaep::<Sha256>::new_with_label(root_aad(self.platform).into_bytes());
        // One error for every failure: which step failed is not told to whoever chose the copy.
        released
            .decrypt_blinded(&mut UnwrapErr(SysRng), oaep, wrapped)
            .ok()
            .map(SecretVec::new)
            .and_then(|root| Key32::from_secret_vec(&root).ok())
            .ok_or_else(|| GuardianError::Root(format!("key vault: {what}: the wrapped root does not open")))
    }

    /// One Key Vault `POST` of `body` with the access token. 200 → the parsed answer; anything
    /// else → `Root` naming `step`, the status and Azure's message. Answers are wiped after
    /// parsing: a release holds a key.
    async fn post<T: DeserializeOwned>(
        &self,
        step: &str,
        url: &str,
        access: &str,
        body: &[u8],
    ) -> Result<T, GuardianError> {
        let auth = format!("Bearer {access}");
        let headers = [("authorization", auth.as_str())];
        let (status, answer) = self
            .https
            .post(url, &headers, body)
            .await
            .map_err(|e| GuardianError::Root(format!("key vault: {step}: {e}")))?;
        let answer = SecretVec::new(answer);
        if status != 200 {
            return Err(GuardianError::Root(format!(
                "key vault: {step}: HTTP {status}{}",
                error_detail(answer.expose())
            )));
        }
        serde_json::from_slice(answer.expose())
            .map_err(|e| GuardianError::Root(format!("key vault: {step}: malformed response: {e}")))
    }
}

const OCT: &str = "no wrapped root: Managed HSM oct-HSM keys are not implemented by this build";

fn not_rsa(kty: &str) -> String {
    if kty.starts_with("oct") {
        format!("an {kty} key: Managed HSM oct-HSM keys are not implemented by this build")
    } else {
        format!("an {kty} key, not RSA-HSM")
    }
}

/// 32 hex digits.
fn is_key_version(v: &str) -> bool {
    v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Key Vault Secure Key Release of RSA-wrapped roots (see the module documentation for the
/// flow, the setup and what Microsoft is still trusted with). The copies are tried in order;
/// boot fails only if none opens.
pub struct KeyVaultKeySource {
    vault: KeyVault,
    copies: Vec<VaultKey>,
}

impl KeyVaultKeySource {
    /// `Root` if `copies` is empty or names a malformed vault, key or version.
    pub fn new(vault: KeyVault, copies: Vec<VaultKey>) -> Result<Self, GuardianError> {
        if copies.is_empty() {
            return Err(config_err("no wrapped root".into()));
        }
        for copy in &copies {
            check_key_name(&copy.vault_url, &copy.key_name)?;
            if !is_key_version(&copy.key_version) {
                return Err(config_err(format!("not a key version: {:?}", copy.key_version)));
            }
        }
        Ok(Self { vault, copies })
    }

    pub(crate) async fn root_secret(&self, attestor: &Attestor) -> Result<Key32, GuardianError> {
        let session = self.vault.session(attestor).await?;
        let mut failures = Vec::new();
        for copy in &self.copies {
            let opened = match &copy.wrapped_root {
                None => Err(GuardianError::Root(format!(
                    "key vault: {}/keys/{}/{}: {OCT}",
                    copy.vault_url, copy.key_name, copy.key_version
                ))),
                Some(_) => {
                    match self.vault.release(&session, &copy.vault_url, &copy.key_name, Some(&copy.key_version)).await {
                        Ok((_, released)) => self.vault.unwrap_root(&released, copy),
                        Err(e) => Err(e),
                    }
                }
            };
            match opened {
                Ok(root) => return Ok(root),
                Err(e) => {
                    tracing::warn!(vault = %copy.vault_url, key = %copy.key_name, error = %e, "wrapped root did not open");
                    failures.push(match e {
                        GuardianError::Root(reason) => reason,
                        other => other.to_string(),
                    });
                }
            }
        }
        Err(GuardianError::Root(failures.join("; ")))
    }
}

/// The runtime data: a JWK set holding the ephemeral public key, for encryption.
fn runtime_data(public: &RsaPublicKey) -> Vec<u8> {
    let b64 = |n: &BoxedUint| seal_proto::codec::b64url(&n.to_be_bytes_trimmed_vartime());
    let jwks = serde_json::json!({"keys": [{
        "kty": "RSA",
        "kid": RUNTIME_KID,
        "key_ops": ["encrypt"],
        "n": b64(public.n()),
        "e": b64(public.e()),
    }]});
    serde_json::to_vec(&jwks).expect("a JSON value serializes")
}

/// `key_hsm`: base64url JSON whose `ciphertext` is RSA-OAEP-SHA256(KEK) under the ephemeral
/// key, then AES-KWP(KEK, the key's PKCS#8 DER).
fn unwrap_released(ephemeral: &RsaPrivateKey, key_hsm: &str) -> Result<RsaPrivateKey, String> {
    #[derive(Deserialize)]
    struct KeyHsm {
        ciphertext: String,
        #[serde(default)]
        header: Option<KeyHsmHeader>,
    }
    #[derive(Deserialize)]
    struct KeyHsmHeader {
        #[serde(default)]
        kid: Option<String>,
    }
    let json = B64URL.decode(key_hsm).map_err(|_| "key_hsm is not base64url".to_owned())?;
    let key_hsm: KeyHsm = serde_json::from_slice(&json).map_err(|e| format!("key_hsm: {e}"))?;
    if key_hsm.header.and_then(|h| h.kid).is_some_and(|kid| kid != RUNTIME_KID) {
        return Err("key_hsm is wrapped to another key".into());
    }
    let ciphertext =
        B64URL.decode(&key_hsm.ciphertext).map_err(|_| "key_hsm ciphertext is not base64url".to_owned())?;
    let split = ephemeral.size();
    if ciphertext.len() <= split + 8 {
        return Err("key_hsm ciphertext is too short".into());
    }
    let (wrapped_kek, wrapped_key) = ciphertext.split_at(split);
    let kek = ephemeral
        .decrypt_blinded(&mut UnwrapErr(SysRng), Oaep::<Sha256>::new(), wrapped_kek)
        .map(SecretVec::new)
        .map_err(|_| "key_hsm does not open with the ephemeral key".to_owned())?;
    let kek = Key32::from_secret_vec(&kek).map_err(|_| "key_hsm's key encryption key is not AES-256".to_owned())?;
    let kwp = <aes_kw::KwpAes256 as aes_kw::KeyInit>::new(kek.expose().into());
    let mut buf = vec![0; wrapped_key.len()];
    let len = kwp.unwrap_key(wrapped_key, &mut buf).map(<[u8]>::len);
    let der = SecretVec::new(buf);
    let len = len.map_err(|_| "key_hsm does not unwrap (AES-KWP)".to_owned())?;
    let der = &der.expose()[..len];
    RsaPrivateKey::from_pkcs8_der(der)
        .or_else(|_| RsaPrivateKey::from_pkcs1_der(der))
        .map_err(|_| "the released key is not an RSA private key".to_owned())
}

/// An exportable key whose release policy is immutable and pins this guardian.
fn check_bundle(
    attributes: &KeyAttributes,
    policy: Option<&ReleasePolicy>,
    host_data: &[u8; 32],
    maa_endpoint: &str,
) -> Result<(), String> {
    if attributes.exportable != Some(true) {
        return Err("the key is not exportable".into());
    }
    let policy = policy.ok_or("the key has no release policy")?;
    if policy.immutable != Some(true) {
        return Err("the key's release policy is not immutable".into());
    }
    let data = policy.data.as_deref().ok_or("the key's release policy has no data")?;
    let text = B64URL.decode(data).map_err(|_| "the key's release policy is not base64url".to_owned())?;
    check_release_policy(&text, host_data, maa_endpoint).map_err(|e| format!("release policy: {e}"))
}

/// The claims every branch of a release policy must require, with `x-ms-sevsnpvm-hostdata` =
/// the guardian's host_data (lowercase hex).
fn required_claims(host_data: &[u8; 32]) -> [(&'static str, serde_json::Value); 5] {
    let hex: String = host_data.iter().map(|b| format!("{b:02x}")).collect();
    [
        ("x-ms-attestation-type", "sevsnpvm".into()),
        ("x-ms-compliance-status", "azure-compliant-uvm".into()),
        ("x-ms-sevsnpvm-hostdata", hex.into()),
        ("x-ms-sevsnpvm-is-debuggable", false.into()),
        ("x-ms-sevsnpvm-vmpl", 0.into()),
    ]
}

/// A Key Vault release policy (version 1.0.0) that admits only this guardian: at least one
/// branch, each with `authority` = `maa_endpoint` and an `allOf` of plain `{claim, equals}`
/// conditions that includes every one of `required_claims` (more conditions only narrow it).
/// Anything else (another authority, a nested `anyOf`, a missing claim, an unknown member) is
/// refused.
pub fn check_release_policy(policy: &[u8], host_data: &[u8; 32], maa_endpoint: &str) -> Result<(), String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Policy {
        version: String,
        #[serde(rename = "anyOf")]
        any_of: Vec<Branch>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Branch {
        authority: String,
        #[serde(rename = "allOf")]
        all_of: Vec<Condition>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Condition {
        claim: String,
        equals: serde_json::Value,
    }
    let policy: Policy = serde_json::from_slice(policy).map_err(|e| format!("not a plain policy: {e}"))?;
    if policy.version != "1.0.0" {
        return Err(format!("version {:?}, not 1.0.0", policy.version));
    }
    if policy.any_of.is_empty() {
        return Err("no branch".into());
    }
    let required = required_claims(host_data);
    for branch in &policy.any_of {
        if branch.authority.trim_end_matches('/') != maa_endpoint {
            return Err(format!("authority {:?}, not {maa_endpoint}", branch.authority));
        }
        for (claim, value) in &required {
            if !branch.all_of.iter().any(|c| c.claim == *claim && c.equals == *value) {
                return Err(format!("a branch does not require {claim} = {value}"));
            }
        }
    }
    Ok(())
}

/// The release policy `check_release_policy` expects, as the operator creates the key with.
pub fn release_policy(host_data: &[u8; 32], maa_endpoint: &str) -> serde_json::Value {
    let all_of: Vec<serde_json::Value> = required_claims(host_data)
        .into_iter()
        .map(|(claim, equals)| serde_json::json!({"claim": claim, "equals": equals}))
        .collect();
    serde_json::json!({
        "version": "1.0.0",
        "anyOf": [{"authority": maa_endpoint.trim_end_matches('/'), "allOf": all_of}],
    })
}

/// The release's JWS: RS256 under the first `x5c` certificate, which must chain to `roots`
/// and name `host` (as the vault's TLS certificate does). Returns the payload.
fn verify_release_jws(jws: &str, host: &str, roots: &Arc<rustls::RootCertStore>) -> Result<SecretVec, String> {
    use rsa::signature::Verifier as _;
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Deserialize)]
    struct Header {
        alg: String,
        x5c: Vec<String>,
        #[serde(default)]
        crit: Option<serde_json::Value>,
    }
    let mut parts = jws.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a compact JWS".into());
    };
    let header: Header = B64URL
        .decode(header)
        .ok()
        .and_then(|h| serde_json::from_slice(&h).ok())
        .ok_or("the JWS header is malformed")?;
    if header.alg != "RS256" || header.crit.is_some() {
        return Err(format!("JWS algorithm {:?}, not RS256", header.alg));
    }
    let certs: Vec<CertificateDer<'static>> = header
        .x5c
        .iter()
        .map(|c| STANDARD.decode(c).map(CertificateDer::from))
        .collect::<Result<_, _>>()
        .map_err(|_| "the JWS x5c is not base64".to_owned())?;
    let (leaf, intermediates) = certs.split_first().ok_or("the JWS has no x5c")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(roots.clone(), provider)
        .build()
        .map_err(|e| format!("JWS verifier: {e}"))?;
    let name = ServerName::try_from(host.to_owned()).map_err(|_| "the vault host is not a DNS name".to_owned())?;
    verifier
        .verify_server_cert(leaf, intermediates, &name, &[], UnixTime::now())
        .map_err(|e| format!("the JWS certificate does not certify {host}: {e}"))?;
    let spki = leaf_spki(leaf).ok_or("the JWS certificate is malformed")?;
    let key = <RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(&spki)
        .map_err(|_| "the JWS certificate's key is not RSA".to_owned())?;
    let signature = B64URL.decode(signature).map_err(|_| "the JWS signature is not base64url".to_owned())?;
    let signature = rsa::pkcs1v15::Signature::try_from(signature.as_slice()).map_err(|_| "malformed JWS signature")?;
    let signing_input = &jws[..header_payload_len(jws)];
    rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| "the JWS signature does not verify".to_owned())?;
    B64URL.decode(payload).map(SecretVec::new).map_err(|_| "the JWS payload is not base64url".to_owned())
}

fn header_payload_len(jws: &str) -> usize {
    jws.rfind('.').expect("three parts")
}

/// The DER `SubjectPublicKeyInfo` of a certificate.
fn leaf_spki(cert: &[u8]) -> Option<Vec<u8>> {
    use x509_cert::der::{Decode as _, Encode as _};
    let cert = x509_cert::Certificate::from_der(cert).ok()?;
    cert.tbs_certificate().subject_public_key_info().to_der().ok()
}

#[derive(Deserialize)]
struct KeyBundle {
    key: JsonWebKey,
    #[serde(default)]
    attributes: KeyAttributes,
    #[serde(default)]
    release_policy: Option<ReleasePolicy>,
}

#[derive(Deserialize)]
struct JsonWebKey {
    kid: String,
    kty: String,
    #[serde(default)]
    key_hsm: Option<String>,
}

#[derive(Default, Deserialize)]
struct KeyAttributes {
    #[serde(default)]
    exportable: Option<bool>,
}

#[derive(Deserialize)]
struct ReleasePolicy {
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    immutable: Option<bool>,
}

#[derive(Deserialize)]
struct ReleaseAnswer {
    value: String,
}

#[derive(Deserialize)]
struct ReleasePayload {
    response: ReleaseResponse,
}

#[derive(Deserialize)]
struct ReleaseResponse {
    key: KeyBundle,
}

fn config_err(reason: String) -> GuardianError {
    GuardianError::Root(format!("key vault config: {reason}"))
}

/// The host of an `https://<host>` URL with nothing after it, lowercase letters, digits, `-`
/// and `.` only. Names are spliced into request URLs.
fn https_host(url: &str) -> Option<&str> {
    let host = url.strip_prefix("https://")?;
    let ok = !host.is_empty()
        && host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !host.starts_with(['.', '-'])
        && !host.contains("..");
    ok.then_some(host)
}

/// `https://<3-24 of a-z0-9->.vault.azure.net` and a key name of 1-127 of `[A-Za-z0-9-]`.
fn check_key_name(vault_url: &str, key_name: &str) -> Result<(), GuardianError> {
    let vault_ok = https_host(vault_url)
        .and_then(|h| h.strip_suffix(VAULT_HOST_SUFFIX))
        .is_some_and(|name| (3..=24).contains(&name.len()) && !name.contains('.'));
    if !vault_ok {
        return Err(config_err(format!("not a Key Vault URL (https://<name>{VAULT_HOST_SUFFIX}): {vault_url:?}")));
    }
    if key_name.is_empty() || key_name.len() > 127 || !key_name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(config_err(format!("not a Key Vault key name: {key_name:?}")));
    }
    Ok(())
}

/// Azure's error detail, `error.code: error.message`, cut to `MAX_DETAIL` characters; empty
/// if the body is not an Azure error.
fn error_detail(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else { return String::new() };
    let error = &value["error"];
    let detail = match (error["code"].as_str(), error["message"].as_str()) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (None, Some(message)) => message.to_owned(),
        (Some(code), None) => code.to_owned(),
        (None, None) => return String::new(),
    };
    format!(" ({})", detail.chars().take(MAX_DETAIL).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_DATA: [u8; 32] = [0xab; 32];
    const MAA: &str = "https://sharedeus.eus.attest.azure.net";

    #[test]
    fn the_generated_policy_passes_its_own_check() {
        let policy = release_policy(&HOST_DATA, MAA);
        check_release_policy(policy.to_string().as_bytes(), &HOST_DATA, MAA).unwrap();
        assert_eq!(policy["anyOf"][0]["allOf"][2]["equals"], "ab".repeat(32));
        // A trailing slash on the authority is the same endpoint.
        let mut slash = policy.clone();
        slash["anyOf"][0]["authority"] = format!("{MAA}/").into();
        check_release_policy(slash.to_string().as_bytes(), &HOST_DATA, MAA).unwrap();
        // An extra condition only narrows.
        let mut narrower = policy.clone();
        narrower["anyOf"][0]["allOf"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"claim": "x-ms-sevsnpvm-guestsvn", "equals": 3}));
        check_release_policy(narrower.to_string().as_bytes(), &HOST_DATA, MAA).unwrap();
    }

    #[test]
    fn policies_admitting_anyone_else_are_refused() {
        let policy = release_policy(&HOST_DATA, MAA);
        let check = |p: serde_json::Value| check_release_policy(p.to_string().as_bytes(), &HOST_DATA, MAA);
        assert!(check_release_policy(policy.to_string().as_bytes(), &[0xcd; 32], MAA).is_err(), "another host_data");
        let mut other = policy.clone();
        other["anyOf"][0]["authority"] = "https://mine.eus.attest.azure.net".into();
        assert!(check(other).is_err(), "a customer-owned attestation provider");
        let mut wider = policy.clone();
        let mut branch = wider["anyOf"][0].clone();
        branch["allOf"].as_array_mut().unwrap().remove(2);
        wider["anyOf"].as_array_mut().unwrap().push(branch);
        assert!(check(wider).is_err(), "a second branch without host_data");
        for i in 0..5 {
            let mut missing = policy.clone();
            missing["anyOf"][0]["allOf"].as_array_mut().unwrap().remove(i);
            assert!(check(missing).is_err(), "claim {i} missing");
        }
        let mut debuggable = policy.clone();
        debuggable["anyOf"][0]["allOf"][3]["equals"] = true.into();
        assert!(check(debuggable).is_err());
        let mut as_string = policy.clone();
        as_string["anyOf"][0]["allOf"][4]["equals"] = "0".into();
        assert!(check(as_string).is_err(), "types are compared too");
        let mut nested = policy.clone();
        nested["anyOf"][0]["allOf"].as_array_mut().unwrap().push(serde_json::json!({"anyOf": []}));
        assert!(check(nested).is_err(), "a nested condition is not understood");
        let mut empty = policy.clone();
        empty["anyOf"] = serde_json::json!([]);
        assert!(check(empty).is_err());
        let mut version = policy;
        version["version"] = "0.2".into();
        assert!(check(version).is_err());
        assert!(check_release_policy(b"not json", &HOST_DATA, MAA).is_err());
    }

    #[test]
    fn names_are_checked() {
        for (url, key) in [("https://seal-root-1.vault.azure.net", "seal-root"), ("https://abc.vault.azure.net", "k")] {
            check_key_name(url, key).unwrap();
        }
        for (url, key) in [
            ("http://seal.vault.azure.net", "k"),
            ("https://seal.vault.azure.net/", "k"),
            ("https://seal.managedhsm.azure.net", "k"),
            ("https://evil.com/.vault.azure.net", "k"),
            ("https://a.b.vault.azure.net", "k"),
            ("https://ab.vault.azure.net", "k"),
            ("https://seal.vault.azure.net", ""),
            ("https://seal.vault.azure.net", "k/../x"),
            ("https://seal.vault.azure.net", "k?x=1"),
        ] {
            assert!(check_key_name(url, key).is_err(), "{url} {key}");
        }
        let https =
            Arc::new(HttpsClient::new(Arc::new(seal_net::BakedRootsConnector::new(Arc::new(seal_net::TcpDialer)))));
        assert!(KeyVault::new(PlatformId::AzureSnpAci, MAA.into(), https.clone()).is_ok());
        assert_eq!(KeyVault::new(PlatformId::AzureSnpAci, format!("{MAA}/"), https.clone()).unwrap().maa_endpoint, MAA);
        for maa in ["https://example.com", "http://sharedeus.eus.attest.azure.net", "https://x.attest.azure.net/attest"]
        {
            assert!(KeyVault::new(PlatformId::AzureSnpAci, maa.into(), https.clone()).is_err(), "{maa}");
        }
        assert!(is_key_version("0123456789abcdef0123456789abcdef"));
        assert!(!is_key_version("1") && !is_key_version("0123456789abcdef0123456789abcde/"));
    }

    #[test]
    fn maa_request_shape() {
        let body: serde_json::Value =
            serde_json::from_slice(&maa_request(b"report", "VCEK\n", "ASK\nARK\n", b"cose", b"{\"keys\":[]}")).unwrap();
        assert_eq!(body["runtimeData"]["dataType"], "JSON");
        assert_eq!(URL_SAFE.decode(body["runtimeData"]["data"].as_str().unwrap()).unwrap(), b"{\"keys\":[]}");
        let inner: serde_json::Value =
            serde_json::from_slice(&URL_SAFE.decode(body["report"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(URL_SAFE.decode(inner["SnpReport"].as_str().unwrap()).unwrap(), b"report");
        assert_eq!(URL_SAFE.decode(inner["VcekCertChain"].as_str().unwrap()).unwrap(), b"VCEK\nASK\nARK\n");
        let endorsements: serde_json::Value =
            serde_json::from_slice(&URL_SAFE.decode(inner["Endorsements"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(URL_SAFE.decode(endorsements["Uvm"][0].as_str().unwrap()).unwrap(), b"cose");
    }

    #[test]
    fn error_details() {
        let body = br#"{"error":{"code":"Forbidden","message":"Target environment attestation statement cannot be verified.","innererror":{"code":"AccessDenied"}}}"#;
        assert_eq!(error_detail(body), " (Forbidden: Target environment attestation statement cannot be verified.)");
        assert_eq!(error_detail(b"<html>"), "");
    }
}

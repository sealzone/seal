//! GCP Confidential Space. Evidence is an attestation token of type PKI, not OIDC: OIDC
//! tokens are signed with rotating keys that only network can fetch.
//!
//! - Header `alg` `RS256` with an `x5c` of exactly three certificates (leaf, intermediate,
//!   root). The root is byte-identical to the baked Confidential Space Root CA
//!   (`roots/confidential_space_root.pem`, SHA-256 fingerprint
//!   `148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39`, valid 2024-01-19 to
//!   2034-01-16); the root signs the intermediate, which is a CA and signs the leaf, which is
//!   not (RSA PKCS#1 v1.5, SHA-256 in Google's chain). Every certificate is valid for the
//!   whole of `time`.
//! - The JWS signature verifies with the leaf's RSA key (`seal_crypto::jws`, RS256 only).
//! - `iss == "https://confidentialcomputing.googleapis.com"`, `aud` exactly `AUDIENCE`,
//!   `time.latest() < exp`, and `nbf <= time.latest() + 60 s`: Google stamps `nbf` with
//!   its own clock when it issues the token, so a token checked at once can look a second
//!   early to Roughtime, and using a token early gains nothing.
//! - `swname == "CONFIDENTIAL_SPACE"`, `dbgstat == "disabled-since-boot"` (else `DebugMode`:
//!   the debug image is always refused), `secboot == true`, and `hwmodel` is
//!   `GCP_INTEL_TDX` or `GCP_AMD_SEV_SNP`. Plain SEV (`GCP_AMD_SEV`) has no memory integrity and
//!   is refused; both accepted models get the platform's one tier. Google's attestation
//!   service does not yet attest Confidential Space on SEV-SNP (it answers
//!   `UNSUPPORTED_CC_TECHNOLOGY`), so in practice only TDX tokens pass.
//! - Exactly one `eat_nonce` (a string; several nonces are an array): the lowercase hex of
//!   Seal's 32-byte binding (Confidential Space takes nonces of 8 to 88 bytes; 64 hex digits
//!   fit).
//! - `Measurement = SHA-384("gcp-confidential-space" || digest)`, where `digest` is the 32
//!   bytes of `submods.container.image_digest` (`sha256:` and 64 lowercase hex digits).
//! - `tcb`: `cs_version` (the one `swversion`) and `cs_stable` (1 when
//!   `submods.confidential_space.support_attributes` contains `STABLE`, else 0). Requiring a
//!   supported image is a `min_tcb` entry (`cs_stable: 1`), not code. TDX tokens add Intel's
//!   TCB verdict from the `tdx` claim: `tdx_tcb_status` (3 `UpToDate`, 2 `SWHardeningNeeded`,
//!   1 `ConfigurationNeeded` or `ConfigurationAndSWHardeningNeeded`, 0 for anything else:
//!   `OutOfDate*`, `Revoked` and statuses this build does not know) and
//!   `tdx_tcb_evaluation_data_number` (Intel's TCB recovery counter the verdict was made
//!   under). Requiring an up-to-date TDX module is `min_tcb` again (`tdx_tcb_status: 3`, and
//!   a recovery number); a token without the claim has neither component, so such a floor
//!   refuses it.
//! - `deployment` = `ConfidentialSpace { project_number, service_account }` from
//!   `submods.gce.project_number` and the one entry of `google_service_accounts`.
//! - Not checked: the restart policy (a restart runs the same image under the same
//!   measurement) and the env and command overrides, which the production launcher allows
//!   only as the image's launch-policy labels say, and the labels are part of the digest.
//!
//! Claims are read before any signature is checked, cheapest first; nothing unverified is
//! returned.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use base64::Engine;
use der::Decode;
use seal_crypto::jws::{self, JwsAlg};
use seal_proto::identity::WorkloadIdentity;
use seal_proto::release::Tcb;
use seal_proto::{Measurement, PlatformId, TrustedTime};
use serde::Deserialize;
use sha2::{Digest, Sha384};

use crate::x509::{reject, Cert};
use crate::{AttestError, VerifiedEvidence};

/// The `aud` Seal requests and requires. Seal's own name for its attestation, distinct from
/// the `seal:<tenant>` audience of identity proofs.
pub const AUDIENCE: &str = "https://seal.zone/attestation";

/// The only issuer of Confidential Space attestation tokens.
const ISSUER: &str = "https://confidentialcomputing.googleapis.com";

/// Google's Confidential Space Root CA (PKI tokens), byte-identical to
/// `https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt`.
const ROOT_PEM: &[u8] = include_bytes!("../roots/confidential_space_root.pem");

/// Hashed in front of the image digest in `Measurement`.
const MEASUREMENT_LABEL: &[u8] = b"gcp-confidential-space";

/// How far `nbf` may lie after the latest end of the trusted time.
const NBF_SKEW_SECS: u64 = 60;

const HARDWARE_MODELS: [&str; 2] = ["GCP_INTEL_TDX", "GCP_AMD_SEV_SNP"];

pub(crate) fn verify(token: &str, time: &TrustedTime) -> Result<VerifiedEvidence, AttestError> {
    verify_with_root(token, time, &baked_root()?)
}

fn baked_root() -> Result<Cert, AttestError> {
    Cert::parse_pem_chain(ROOT_PEM, "baked Confidential Space root")?
        .pop()
        .ok_or_else(|| reject("baked Confidential Space root is empty"))
}

/// `Measurement` for a container image digest (`sha256:` and 64 lowercase hex digits).
pub fn measurement(image_digest: &str) -> Result<Measurement, AttestError> {
    let hex = image_digest.strip_prefix("sha256:").ok_or_else(|| reject("image digest is not sha256"))?;
    let digest: [u8; 32] = lower_hex(hex).ok_or_else(|| reject("image digest is not 64 lowercase hex digits"))?;
    Ok(Measurement(Sha384::new().chain_update(MEASUREMENT_LABEL).chain_update(digest).finalize().into()))
}

/// Exactly `2 * N` lowercase hex digits.
fn lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let b = s.as_bytes();
    if b.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = digit(b[2 * i])? << 4 | digit(b[2 * i + 1])?;
    }
    Some(out)
}

/// A claim that is a string or an array of strings (`aud`, `eat_nonce`).
#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    /// The single value: a string, or an array of exactly one.
    fn single(&self) -> Option<&str> {
        match self {
            OneOrMany::One(s) => Some(s),
            OneOrMany::Many(v) if v.len() == 1 => Some(&v[0]),
            OneOrMany::Many(_) => None,
        }
    }
}

/// The claims checked. Unknown claims are ignored; a repeated claim is refused by serde.
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: OneOrMany,
    nbf: u64,
    exp: u64,
    eat_nonce: Option<OneOrMany>,
    swname: String,
    swversion: Vec<String>,
    dbgstat: String,
    secboot: bool,
    hwmodel: String,
    submods: Submods,
    #[serde(default)]
    google_service_accounts: Vec<String>,
    #[serde(default)]
    tdx: Option<Tdx>,
}

/// Intel's verdict on the TDX TCB, as Google's attestation service reports it.
#[derive(Deserialize)]
struct Tdx {
    gcp_attester_tcb_status: String,
    tcb_evaluation_data_number: u64,
}

impl Tdx {
    /// `tdx_tcb_status` as the module docs order it: higher is better.
    fn status_rank(&self) -> u64 {
        match self.gcp_attester_tcb_status.as_str() {
            "UpToDate" => 3,
            "SWHardeningNeeded" => 2,
            "ConfigurationNeeded" | "ConfigurationAndSWHardeningNeeded" => 1,
            _ => 0,
        }
    }
}

#[derive(Deserialize)]
struct Submods {
    container: Container,
    gce: Gce,
    #[serde(default)]
    confidential_space: ConfidentialSpace,
}

#[derive(Deserialize)]
struct Container {
    image_digest: String,
}

#[derive(Deserialize)]
struct Gce {
    project_number: String,
}

#[derive(Default, Deserialize)]
struct ConfidentialSpace {
    #[serde(default)]
    support_attributes: Vec<String>,
}

/// The header members read here; `seal_crypto::jws` checks the rest.
#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    x5c: Vec<String>,
}

/// What the claims say, before the chain and signature are checked.
struct Checked {
    measurement: Measurement,
    tcb: Tcb,
    report_data: [u8; 32],
    deployment: WorkloadIdentity,
}

pub(crate) fn verify_with_root(token: &str, time: &TrustedTime, root: &Cert) -> Result<VerifiedEvidence, AttestError> {
    let header_bytes = token
        .split('.')
        .next()
        .and_then(|h| seal_proto::codec::from_b64url(h).ok())
        .ok_or_else(|| reject("token header is not base64url"))?;
    let header: Header = serde_json::from_slice(&header_bytes).map_err(|e| reject(format!("token header: {e}")))?;
    if header.alg != JwsAlg::Rs256.name() {
        return Err(reject(format!("token alg {} is not RS256", header.alg)));
    }
    let payload = jws::peek_payload(token).map_err(|e| reject(format!("token: {e}")))?;
    let checked = check_claims(&payload, time)?;

    let leaf = check_chain(&header.x5c, time, root)?;
    let key = leaf_key(&leaf, jws::peek_header(token).map_err(|e| reject(format!("token: {e}")))?.kid)?;
    let signed = jws::verify(token, &key, JwsAlg::Rs256).map_err(|_| reject("token signature does not verify"))?;
    if signed != payload {
        return Err(reject("token payload changed during verification"));
    }
    Ok(VerifiedEvidence {
        platform: PlatformId::GcpConfidentialSpace,
        measurement: checked.measurement,
        tcb: checked.tcb,
        report_data: checked.report_data,
        deployment: Some(checked.deployment),
    })
}

fn check_claims(payload: &[u8], time: &TrustedTime) -> Result<Checked, AttestError> {
    let c: Claims = serde_json::from_slice(payload).map_err(|e| reject(format!("token claims: {e}")))?;
    if c.iss != ISSUER {
        return Err(reject(format!("token issuer {:?} is not {ISSUER}", c.iss)));
    }
    if c.aud.single() != Some(AUDIENCE) {
        return Err(reject(format!("token audience is not {AUDIENCE}")));
    }
    if c.nbf > time.latest().saturating_add(NBF_SKEW_SECS) || time.latest() >= c.exp {
        return Err(reject(format!(
            "token not valid at {}..{} (valid {}..{})",
            time.earliest(),
            time.latest(),
            c.nbf,
            c.exp
        )));
    }
    if c.swname != "CONFIDENTIAL_SPACE" {
        return Err(reject(format!("swname {:?} is not CONFIDENTIAL_SPACE", c.swname)));
    }
    if c.dbgstat != "disabled-since-boot" {
        return Err(AttestError::DebugMode);
    }
    if !c.secboot {
        return Err(reject("secure boot is off"));
    }
    if !HARDWARE_MODELS.contains(&c.hwmodel.as_str()) {
        return Err(reject(format!("hardware model {:?} is not SEV-SNP or TDX", c.hwmodel)));
    }
    let nonce = match &c.eat_nonce {
        None => return Err(reject("token has no nonce")),
        Some(n) => n.single().ok_or_else(|| reject("token has more than one nonce"))?,
    };
    let report_data: [u8; 32] = lower_hex(nonce).ok_or_else(|| reject("token nonce is not 64 lowercase hex digits"))?;
    let measurement = measurement(&c.submods.container.image_digest)?;
    let cs_version = match c.swversion.as_slice() {
        [v] => decimal(v).ok_or_else(|| reject(format!("swversion {v:?} is not a number")))?,
        _ => return Err(reject("token needs exactly one swversion")),
    };
    let cs_stable = u64::from(c.submods.confidential_space.support_attributes.iter().any(|a| a == "STABLE"));
    let project_number =
        decimal(&c.submods.gce.project_number).ok_or_else(|| reject("submods.gce.project_number is not a number"))?;
    let service_account = match c.google_service_accounts.as_slice() {
        [one] if !one.is_empty() => one.clone(),
        _ => return Err(reject("token needs exactly one service account")),
    };
    let mut tcb = BTreeMap::from([("cs_version".to_owned(), cs_version), ("cs_stable".to_owned(), cs_stable)]);
    if let Some(tdx) = &c.tdx {
        tcb.insert("tdx_tcb_status".to_owned(), tdx.status_rank());
        tcb.insert("tdx_tcb_evaluation_data_number".to_owned(), tdx.tcb_evaluation_data_number);
    }
    Ok(Checked {
        measurement,
        tcb: Tcb(tcb),
        report_data,
        deployment: WorkloadIdentity::ConfidentialSpace { project_number, service_account },
    })
}

/// ASCII digits only, no sign or leading `+`.
fn decimal(s: &str) -> Option<u64> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

/// `[leaf, intermediate, root]`: root identical to `root`, each signing the next, all valid at
/// `time`. Returns the leaf.
fn check_chain(x5c: &[String], time: &TrustedTime, root: &Cert) -> Result<Cert, AttestError> {
    let [leaf, intermediate, sent_root] = x5c else {
        return Err(reject(format!("x5c has {} certificates, not 3", x5c.len())));
    };
    let parse = |b64: &str, what: &str| {
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| reject(format!("x5c {what} is not base64")))?;
        Cert::parse(&der, what)
    };
    let (leaf, intermediate, sent_root) =
        (parse(leaf, "leaf")?, parse(intermediate, "intermediate")?, parse(sent_root, "root")?);
    if sent_root.der != root.der {
        return Err(reject("x5c root is not the Confidential Space root"));
    }
    let (earliest, latest) = (time.earliest(), time.latest());
    root.check_valid(earliest, latest, "Confidential Space root")?;
    intermediate.check_valid(earliest, latest, "intermediate certificate")?;
    leaf.check_valid(earliest, latest, "leaf certificate")?;
    if !intermediate.is_ca()? {
        return Err(reject("intermediate certificate is not a CA"));
    }
    if leaf.is_ca()? {
        return Err(reject("leaf certificate is a CA"));
    }
    root.verify_pkcs1v15(&intermediate)?;
    intermediate.verify_pkcs1v15(&leaf)?;
    Ok(leaf)
}

/// The leaf's RSA key as a JWK under the token's own `kid`: the x5c, not the `kid`, names the key.
fn leaf_key(leaf: &Cert, kid: Option<String>) -> Result<jws::Jwk, AttestError> {
    let key = rsa::pkcs1::RsaPublicKeyRef::from_der(leaf.public_key_bytes())
        .map_err(|e| reject(format!("leaf key is not RSA: {e}")))?;
    jws::Jwk::rsa(kid, key.modulus.as_bytes(), key.public_exponent.as_bytes())
        .map_err(|e| reject(format!("leaf key: {e}")))
}

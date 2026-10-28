//! Microsoft's UVM endorsement (ACI `reference-info-base64`): COSE_Sign1 by a certificate
//! chain pinned with a did:x509, naming the utility VM's SNP launch measurement and its svn.

use base64::Engine;
use ciborium::Value;
use coset::{iana, CborSerializable, CoseSign1, Label, TaggedCborSerializable};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::signature::Verifier;
use sha2::{Digest, Sha256};
use spki::ObjectIdentifier;

use crate::x509::{reject, Cert};
use crate::AttestError;

/// The only issuer accepted: Microsoft Supply Chain RSA Root CA 2022 with the
/// ContainerPlat UVM EKU.
pub(crate) const TRUSTED_ISSUER: &str =
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
/// base64url SHA-256 of the root certificate, as in `TRUSTED_ISSUER`.
const ROOT_SHA256_B64URL: &str = "I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s";
/// The leaf EKU named in `TRUSTED_ISSUER`.
const LEAF_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.76.59.1.2");
pub(crate) const TRUSTED_FEED: &str = "ContainerPlat-AMD-UVM";

// COSE and CWT header labels.
const X5CHAIN: i64 = 33;
const CWT_CLAIMS: i64 = 15;
const PAYLOAD_HASH_ALG: i64 = 258;
const PAYLOAD_PREIMAGE_CONTENT_TYPE: i64 = 259;
const CWT_ISS: i64 = 1;
const CWT_SUB: i64 = 2;
const CWT_IAT: i64 = 6;

const LAUNCH_MEASUREMENT: &str = "x-ms-sevsnpvm-launchmeasurement";
const GUEST_SVN: &str = "x-ms-sevsnpvm-guestsvn";
const GUEST_SVN_INT: &str = "x-ms-sevsnpvm-guestsvn-int";

/// What a verified endorsement says.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Endorsement {
    pub launch_measurement: [u8; 48],
    pub svn: u64,
    /// When it was signed (the time its x5chain was checked at).
    pub signed_at: u64,
}

/// Decodes and verifies the base64 endorsement.
pub(crate) fn verify(endorsement_b64: &str) -> Result<Endorsement, AttestError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(endorsement_b64.trim())
        .map_err(|_| reject("UVM endorsement is not base64"))?;
    verify_bytes(&bytes)
}

fn verify_bytes(bytes: &[u8]) -> Result<Endorsement, AttestError> {
    let sign1 = CoseSign1::from_tagged_slice(bytes)
        .or_else(|_| CoseSign1::from_slice(bytes))
        .map_err(|_| reject("UVM endorsement is not a COSE_Sign1"))?;
    let header = &sign1.protected.header;
    if header.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::PS384)) {
        return Err(reject("UVM endorsement is not signed with PS384"));
    }

    // Claims, in whichever of the two formats.
    let claims = match int_label(&header.rest, CWT_CLAIMS) {
        Some(cwt) => cwt_claims(cwt, header)?,
        None => legacy_claims(header)?,
    };
    if claims.issuer != TRUSTED_ISSUER {
        return Err(reject(format!("UVM endorsement issuer {} is not trusted", claims.issuer)));
    }
    if claims.feed != TRUSTED_FEED {
        return Err(reject(format!("UVM endorsement feed {} is not {TRUSTED_FEED}", claims.feed)));
    }

    // x5chain, leaf first: root pinned by fingerprint, leaf EKU, each signed by the next,
    // all valid when the endorsement was signed.
    let chain = x5chain(&header.rest)?;
    let (leaf, root) = (&chain[0], &chain[chain.len() - 1]);
    let root_sha256 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&root.der));
    if root_sha256 != ROOT_SHA256_B64URL {
        return Err(reject("UVM endorsement x5chain root is not the did:x509 root"));
    }
    if !leaf.has_eku(&LEAF_EKU)? {
        return Err(reject("UVM endorsement signing certificate lacks the did:x509 EKU"));
    }
    for (i, cert) in chain.iter().enumerate() {
        let signer = chain.get(i + 1).unwrap_or(cert);
        if i > 0 && !cert.is_ca()? {
            return Err(reject(format!("UVM endorsement x5chain[{i}] is not a CA")));
        }
        signer.verify_pkcs1v15(cert).map_err(|e| reject(format!("UVM endorsement x5chain[{i}]: {e}")))?;
        cert.check_valid(claims.signed_at, claims.signed_at, &format!("UVM endorsement x5chain[{i}]"))?;
    }

    // The signature, over the protected header as received.
    let payload = sign1.payload.as_deref().ok_or_else(|| reject("UVM endorsement payload is detached"))?;
    let key = rsa::RsaPublicKey::from_pkcs1_der(leaf.public_key_bytes())
        .map_err(|_| reject("UVM endorsement signing key is not RSA"))?;
    let vk = rsa::pss::VerifyingKey::<sha2::Sha384>::new(key);
    sign1.verify_signature(b"", |sig, tbs| {
        let sig = rsa::pss::Signature::try_from(sig).map_err(|_| reject("malformed UVM endorsement signature"))?;
        vk.verify(tbs, &sig).map_err(|_| reject("UVM endorsement signature does not verify"))
    })?;

    let (launch_measurement, svn) = match claims.svn {
        Some(svn) => {
            let m = payload.try_into().map_err(|_| reject("UVM endorsement payload is not a 48-byte measurement"))?;
            (m, svn)
        }
        None => legacy_payload(payload)?,
    };
    Ok(Endorsement { launch_measurement, svn, signed_at: claims.signed_at })
}

struct Claims {
    issuer: String,
    feed: String,
    signed_at: u64,
    /// CWT format: the svn claim. Legacy: `None`, the svn is in the payload.
    svn: Option<u64>,
}

/// CWT format (UVM 0.2.10 and later): claims under label 15, payload is the raw measurement
/// (COSE hash envelope, SHA-384).
fn cwt_claims(cwt: &Value, header: &coset::Header) -> Result<Claims, AttestError> {
    let get = |key: Value| {
        cwt.as_map()
            .and_then(|m| m.iter().find(|(k, _)| *k == key))
            .map(|(_, v)| v)
            .ok_or_else(|| reject("UVM endorsement CWT claims incomplete"))
    };
    let text =
        |v: &Value| v.as_text().map(str::to_owned).ok_or_else(|| reject("UVM endorsement CWT claim is not text"));
    let hash_alg = int_label(&header.rest, PAYLOAD_HASH_ALG).and_then(int);
    if hash_alg != Some(i128::from(iana::Algorithm::SHA_384 as i64)) {
        return Err(reject("UVM endorsement payload hash is not SHA-384"));
    }
    if int_label(&header.rest, PAYLOAD_PREIMAGE_CONTENT_TYPE).and_then(Value::as_text)
        != Some("application/octet-stream")
    {
        return Err(reject("UVM endorsement payload content type is not application/octet-stream"));
    }
    Ok(Claims {
        issuer: text(get(Value::from(CWT_ISS))?)?,
        feed: text(get(Value::from(CWT_SUB))?)?,
        signed_at: epoch(get(Value::from(CWT_IAT))?)?,
        svn: Some(
            uint(get(Value::from("svn"))?).ok_or_else(|| reject("UVM endorsement svn is not an unsigned integer"))?,
        ),
    })
}

/// Legacy format (UVM up to 0.2.9): text labels in the protected header, JSON payload.
fn legacy_claims(header: &coset::Header) -> Result<Claims, AttestError> {
    if header.content_type != Some(coset::ContentType::Text("application/json".into())) {
        return Err(reject("UVM endorsement content type is not application/json"));
    }
    let get = |key: &str| {
        header
            .rest
            .iter()
            .find(|(l, _)| *l == Label::Text(key.into()))
            .map(|(_, v)| v)
            .ok_or_else(|| reject(format!("UVM endorsement has no {key}")))
    };
    let text = |v: &Value| v.as_text().map(str::to_owned).ok_or_else(|| reject("UVM endorsement header is not text"));
    Ok(Claims {
        issuer: text(get("iss")?)?,
        feed: text(get("feed")?)?,
        signed_at: epoch(get("signingtime")?)?,
        svn: None,
    })
}

fn legacy_payload(payload: &[u8]) -> Result<([u8; 48], u64), AttestError> {
    let json: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| reject("UVM endorsement payload is not JSON"))?;
    let hex_m = json[LAUNCH_MEASUREMENT].as_str().ok_or_else(|| reject("UVM endorsement has no launch measurement"))?;
    let measurement =
        decode_hex48(hex_m).ok_or_else(|| reject("UVM endorsement launch measurement is not 48 bytes of hex"))?;
    let svn = match &json[GUEST_SVN] {
        serde_json::Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse::<u64>().map_err(|_| reject("UVM endorsement guestsvn out of range"))?
        }
        serde_json::Value::Number(n) => {
            n.as_u64().ok_or_else(|| reject("UVM endorsement guestsvn is not an unsigned integer"))?
        }
        _ => return Err(reject("UVM endorsement has no valid guestsvn")),
    };
    if let Some(int) = json.get(GUEST_SVN_INT) {
        if int.as_u64() != Some(svn) {
            return Err(reject("UVM endorsement guestsvn and guestsvn-int disagree"));
        }
    }
    Ok((measurement, svn))
}

fn x5chain(rest: &[(Label, Value)]) -> Result<Vec<Cert>, AttestError> {
    let entries = match int_label(rest, X5CHAIN) {
        Some(Value::Array(a)) if a.len() >= 2 => a,
        _ => return Err(reject("UVM endorsement x5chain is not a certificate chain")),
    };
    entries
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let der = v.as_bytes().ok_or_else(|| reject("UVM endorsement x5chain entry is not bytes"))?;
            Cert::parse(der, &format!("UVM endorsement x5chain[{i}]"))
        })
        .collect()
}

fn int_label(rest: &[(Label, Value)], label: i64) -> Option<&Value> {
    rest.iter().find(|(l, _)| *l == Label::Int(label)).map(|(_, v)| v)
}

fn int(v: &Value) -> Option<i128> {
    v.as_integer().map(i128::from)
}

fn uint(v: &Value) -> Option<u64> {
    int(v).and_then(|i| u64::try_from(i).ok())
}

/// Epoch seconds, tagged as a CBOR date (tag 1) or bare.
fn epoch(v: &Value) -> Result<u64, AttestError> {
    let inner = match v {
        Value::Tag(1, inner) => inner.as_ref(),
        other => other,
    };
    uint(inner).ok_or_else(|| reject("UVM endorsement signing time is not an epoch time"))
}

fn decode_hex48(s: &str) -> Option<[u8; 48]> {
    let s = s.as_bytes();
    if s.len() != 96 {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 48];
    for (i, pair) in s.chunks(2).enumerate() {
        out[i] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

#[cfg(test)]
pub(crate) fn verify_raw(bytes: &[u8]) -> Result<Endorsement, AttestError> {
    verify_bytes(bytes)
}

//! AWS Nitro attestation documents, from a Nitro Enclave (NSM) or an EC2 instance's NitroTPM.
//! Both are the same COSE_Sign1 (ES384) over CBOR, with `module_id`, `digest`, `timestamp`,
//! the PCRs (`pcrs` for an enclave, `nitrotpm_pcrs` for a NitroTPM), `certificate`,
//! `cabundle`, and the optional `public_key`, `user_data` and `nonce`.
//!
//! - `cabundle` is root first: `cabundle[0]` is byte-identical to the baked AWS Nitro root
//!   (G1, `roots/aws_nitro_root_g1.pem`), each entry signs the next, the last signs
//!   `certificate`, and the COSE signature verifies with `certificate`. Every signature is
//!   ECDSA P-384 over SHA-384; every bundle entry is a CA, `certificate` is not; all are valid
//!   for the whole of `time`. AWS issues the leaf for three hours.
//! - `digest` is `SHA384`, and every PCR is 48 bytes. `public_key`, `user_data` and `nonce`
//!   are byte strings of at most 1024 bytes, or absent (CBOR null counts as absent).
//!
//! An enclave document (`verify`):
//! - PCR0, PCR1 and PCR2 are present and none is all zero (all zero = debug mode or an
//!   attached console, refused). Other PCRs (parent role and instance, signing certificate,
//!   app extensions) are ignored.
//! - `Measurement = SHA-384("aws-nitro" || PCR0 || PCR1 || PCR2)`.
//! - `user_data` = Seal's 32-byte binding; `nonce` and `public_key` unused.
//! - `tcb` is empty: the document carries no hypervisor version.
//!
//! A NitroTPM document (`verify_tpm`) proves that an EC2 instance, not an enclave, made it:
//! - `module_id` is `<instance id>-tpm<16 lowercase hex digits>`, and `certificate`'s one
//!   common name is `<module_id>.<region>.aws`. The instance id and region are returned.
//! - Every PCR from 0 to 23 is present and returned as is. Which boot they show (PCR4, PCR7,
//!   PCR12 for an Attestable AMI) is the caller's to compare; no value is refused here.
//! - `nonce` must be present; `user_data` and `public_key` are returned untouched.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use ciborium::Value;
use coset::{iana, CborSerializable, CoseSign1, TaggedCborSerializable};
use p384::ecdsa::signature::Verifier;
use seal_proto::release::Tcb;
use seal_proto::{Measurement, PlatformId, TrustedTime};
use sha2::{Digest, Sha384};

use crate::x509::{reject, Cert};
use crate::{AttestError, VerifiedEvidence};

/// AWS's Nitro attestation root (G1), byte-identical to `root.pem` in
/// `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`.
const ROOT_PEM: &[u8] = include_bytes!("../roots/aws_nitro_root_g1.pem");

/// Hashed in front of PCR0..2 in `Measurement`.
const MEASUREMENT_LABEL: &[u8] = b"aws-nitro";

/// The largest `public_key`, `user_data` or `nonce` the NSM accepts.
const MAX_USER_BYTES: usize = 1024;

const PCR_LEN: usize = 48;

/// A verified NitroTPM document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmDocument {
    /// `i-` and 8 or 17 lowercase hex digits.
    pub instance_id: String,
    /// The region the issuing hypervisor is in, e.g. `us-east-1`.
    pub region: String,
    pub module_id: String,
    /// When the hypervisor made the document, in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// PCR0 to PCR23.
    pub pcrs: BTreeMap<u8, [u8; PCR_LEN]>,
    pub nonce: Vec<u8>,
    pub user_data: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
}

pub(crate) fn verify(document: &[u8], time: &TrustedTime) -> Result<VerifiedEvidence, AttestError> {
    verify_enclave_with_root(document, time, &baked_root()?)
}

/// Verifies a NitroTPM document against the baked root.
pub fn verify_tpm(document: &[u8], time: &TrustedTime) -> Result<TpmDocument, AttestError> {
    verify_tpm_with_root(document, time, &baked_root()?)
}

/// `Measurement` for an enclave image's PCRs.
pub fn measurement(pcr0: &[u8; 48], pcr1: &[u8; 48], pcr2: &[u8; 48]) -> Measurement {
    Measurement(
        Sha384::new()
            .chain_update(MEASUREMENT_LABEL)
            .chain_update(pcr0)
            .chain_update(pcr1)
            .chain_update(pcr2)
            .finalize()
            .into(),
    )
}

fn baked_root() -> Result<Cert, AttestError> {
    Cert::parse_pem_chain(ROOT_PEM, "baked AWS Nitro root")?
        .pop()
        .ok_or_else(|| reject("baked AWS Nitro root is empty"))
}

fn verify_enclave_with_root(document: &[u8], time: &TrustedTime, root: &Cert) -> Result<VerifiedEvidence, AttestError> {
    let doc = verify_document(document, time, root, "pcrs")?;
    let pcr = |i: u8| -> Result<&[u8; PCR_LEN], AttestError> {
        let value = doc.pcrs.get(&i).ok_or_else(|| reject(format!("document has no PCR{i}")))?;
        if value.iter().all(|b| *b == 0) {
            return Err(AttestError::DebugMode);
        }
        Ok(value)
    };
    let measurement = measurement(pcr(0)?, pcr(1)?, pcr(2)?);
    let report_data: [u8; 32] = doc
        .user_data
        .as_deref()
        .ok_or_else(|| reject("document has no user_data"))?
        .try_into()
        .map_err(|_| reject("user_data is not 32 bytes"))?;
    Ok(VerifiedEvidence {
        platform: PlatformId::AwsNitro,
        measurement,
        tcb: Tcb::default(),
        report_data,
        deployment: None,
    })
}

fn verify_tpm_with_root(document: &[u8], time: &TrustedTime, root: &Cert) -> Result<TpmDocument, AttestError> {
    let doc = verify_document(document, time, root, "nitrotpm_pcrs")?;
    let instance_id = instance_of(&doc.module_id)
        .ok_or_else(|| reject(format!("module_id {:?} is not <instance id>-tpm<16 hex digits>", doc.module_id)))?
        .to_owned();
    let cn = doc.leaf.common_name()?;
    let region = cn
        .strip_prefix(doc.module_id.as_str())
        .and_then(|rest| rest.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix(".aws"))
        .filter(|region| is_region(region))
        .ok_or_else(|| reject(format!("certificate {cn:?} is not <module_id>.<region>.aws")))?
        .to_owned();
    if let Some(i) = (0..24).find(|i| !doc.pcrs.contains_key(i)) {
        return Err(reject(format!("document has no PCR{i}")));
    }
    let nonce = doc.nonce.ok_or_else(|| reject("document has no nonce"))?;
    Ok(TpmDocument {
        instance_id,
        region,
        module_id: doc.module_id,
        timestamp_ms: doc.timestamp_ms,
        pcrs: doc.pcrs,
        nonce,
        user_data: doc.user_data,
        public_key: doc.public_key,
    })
}

/// A document whose chain and signature verified.
struct Document {
    module_id: String,
    timestamp_ms: u64,
    pcrs: BTreeMap<u8, [u8; PCR_LEN]>,
    leaf: Cert,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

/// The checks both kinds share. `pcrs_key` names the PCR map: `pcrs` or `nitrotpm_pcrs`.
fn verify_document(document: &[u8], time: &TrustedTime, root: &Cert, pcrs_key: &str) -> Result<Document, AttestError> {
    let sign1 = CoseSign1::from_tagged_slice(document)
        .or_else(|_| CoseSign1::from_slice(document))
        .map_err(|_| reject("attestation document is not a COSE_Sign1"))?;
    if sign1.protected.header.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::ES384)) {
        return Err(reject("attestation document is not signed with ES384"));
    }
    let payload = sign1.payload.as_deref().ok_or_else(|| reject("attestation document payload is detached"))?;

    // Fields, cheapest first, before any signature.
    let Value::Map(entries) =
        ciborium::from_reader::<Value, _>(payload).map_err(|_| reject("attestation document payload is not CBOR"))?
    else {
        return Err(reject("attestation document payload is not a map"));
    };
    let mut fields = BTreeMap::new();
    for (key, value) in entries {
        let Value::Text(key) = key else {
            return Err(reject("attestation document has a key that is not text"));
        };
        if fields.insert(key.clone(), value).is_some() {
            return Err(reject(format!("attestation document repeats {key}")));
        }
    }
    let field = |name: &str| fields.get(name).ok_or_else(|| reject(format!("attestation document has no {name}")));
    let bytes = |name: &str| match field(name)? {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(reject(format!("{name} is not a byte string"))),
    };
    let optional = |name: &str| match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bytes(b)) if b.len() <= MAX_USER_BYTES => Ok(Some(b.clone())),
        Some(_) => Err(reject(format!("{name} is not a byte string of at most {MAX_USER_BYTES} bytes"))),
    };

    let Value::Text(module_id) = field("module_id")? else {
        return Err(reject("module_id is not text"));
    };
    if field("digest")? != &Value::Text("SHA384".into()) {
        return Err(reject("digest is not SHA384"));
    }
    let timestamp_ms = match field("timestamp")? {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| reject("timestamp is not a u64"))?,
        _ => return Err(reject("timestamp is not an integer")),
    };
    let Value::Map(pcr_entries) = field(pcrs_key)? else {
        return Err(reject(format!("{pcrs_key} is not a map")));
    };
    let mut pcrs = BTreeMap::new();
    for (index, value) in pcr_entries {
        let index = match index {
            Value::Integer(i) => u8::try_from(*i).ok().filter(|i| *i < 32),
            _ => None,
        }
        .ok_or_else(|| reject(format!("{pcrs_key} has an index that is not 0..32")))?;
        let value: [u8; PCR_LEN] = match value {
            Value::Bytes(b) => b.as_slice().try_into().ok(),
            _ => None,
        }
        .ok_or_else(|| reject(format!("PCR{index} is not {PCR_LEN} bytes")))?;
        if pcrs.insert(index, value).is_some() {
            return Err(reject(format!("{pcrs_key} repeats PCR{index}")));
        }
    }
    let leaf = Cert::parse(&bytes("certificate")?, "certificate")?;
    let Value::Array(bundle) = field("cabundle")? else {
        return Err(reject("cabundle is not an array"));
    };
    let bundle = bundle
        .iter()
        .enumerate()
        .map(|(i, cert)| match cert {
            Value::Bytes(der) => Cert::parse(der, &format!("cabundle[{i}]")),
            _ => Err(reject(format!("cabundle[{i}] is not a byte string"))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (public_key, user_data, nonce) = (optional("public_key")?, optional("user_data")?, optional("nonce")?);

    check_chain(&bundle, &leaf, time, root)?;

    // The signature, over the protected header as received.
    let key = leaf.p384_public_key()?;
    sign1.verify_signature(b"", |sig, tbs| {
        let sig = p384::ecdsa::Signature::from_slice(sig).map_err(|_| reject("malformed document signature"))?;
        key.verify(tbs, &sig).map_err(|_| reject("document signature does not verify"))
    })?;

    Ok(Document { module_id: module_id.clone(), timestamp_ms, pcrs, leaf, public_key, user_data, nonce })
}

/// `[root, intermediates..]` then `leaf`: the first identical to `root`, each signing the
/// next, all valid at `time`.
fn check_chain(bundle: &[Cert], leaf: &Cert, time: &TrustedTime, root: &Cert) -> Result<(), AttestError> {
    let Some(first) = bundle.first() else {
        return Err(reject("cabundle is empty"));
    };
    if first.der != root.der {
        return Err(reject("cabundle does not start with the AWS Nitro root"));
    }
    let (earliest, latest) = (time.earliest(), time.latest());
    for (i, cert) in bundle.iter().enumerate() {
        let what = format!("cabundle[{i}]");
        cert.check_valid(earliest, latest, &what)?;
        if !cert.is_ca()? {
            return Err(reject(format!("{what} is not a CA")));
        }
        if i > 0 {
            bundle[i - 1].verify_ecdsa_p384(cert).map_err(|e| reject(format!("{what}: {e}")))?;
        }
    }
    leaf.check_valid(earliest, latest, "certificate")?;
    if leaf.is_ca()? {
        return Err(reject("certificate is a CA"));
    }
    bundle[bundle.len() - 1].verify_ecdsa_p384(leaf).map_err(|e| reject(format!("certificate: {e}")))
}

/// The instance id of a NitroTPM `module_id`.
fn instance_of(module_id: &str) -> Option<&str> {
    let (instance, tpm) = module_id.split_once("-tpm")?;
    let hex = |s: &str| s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let id = instance.strip_prefix("i-")?;
    ((id.len() == 8 || id.len() == 17) && hex(id) && tpm.len() == 16 && hex(tpm)).then_some(instance)
}

/// `us-east-1`, `ap-southeast-2`, `us-gov-west-1`: lowercase words and a number, by dashes.
fn is_region(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    let Some((number, words)) = parts.split_last() else {
        return false;
    };
    words.len() >= 2
        && words.iter().all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()))
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
}

//! The NSM device: `/dev/nsm`, one ioctl, CBOR in and out.
//!
//! The driver (Linux `drivers/misc/nsm.c`, and AWS's `nsm.ko` in the Nitro boot blobs) takes
//! one command, `NSM_IOCTL_RAW`, with the request (at most `MAX_REQUEST` bytes) and room for
//! the response (`MAX_RESPONSE` bytes). The ioctl itself is `seal_tee_nsm_sys::exchange`, kept
//! in a crate of its own so this one has no `unsafe`.
//!
//! Requests and responses are CBOR in the encoding AWS's `aws-nitro-enclaves-nsm-api` gives its
//! serde enums (externally tagged): an attestation request is
//! `{"Attestation": {"user_data": bytes / null, "nonce": bytes / null, "public_key": null}}`,
//! answered by `{"Attestation": {"document": bytes}}` or `{"Error": "<code>"}`. That crate is
//! not used: it pulls `serde_cbor` (unmaintained, refused in `deny.toml`) and `nix`.

use std::fs::File;

use ciborium::Value;

use crate::TeeError;

pub(crate) const DEVICE: &str = "/dev/nsm";
/// Largest request the driver takes.
pub(crate) const MAX_REQUEST: usize = 0x1000;
/// Largest response the driver writes. A document is about 4.5 KiB.
pub(crate) const MAX_RESPONSE: usize = 0x3000;

/// The NSM: one CBOR request in, one CBOR response out. A trait so tests can stand in for it.
pub(crate) trait Nsm: Send + Sync + 'static {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, TeeError>;
}

fn unavailable(msg: impl std::fmt::Display) -> TeeError {
    TeeError::Unavailable(format!("nitro: NSM: {msg}"))
}

/// An attestation document with these fields (`None` = absent), from `nsm`.
pub(crate) fn attestation(
    nsm: &dyn Nsm,
    user_data: Option<&[u8; 32]>,
    nonce: Option<&[u8; 32]>,
) -> Result<Vec<u8>, TeeError> {
    let response = nsm.exchange(&attestation_request(user_data, nonce))?;
    attestation_document(&response)
}

/// The CBOR of an `Attestation` request (module docs).
pub(crate) fn attestation_request(user_data: Option<&[u8; 32]>, nonce: Option<&[u8; 32]>) -> Vec<u8> {
    let field = |value: Option<&[u8; 32]>| value.map_or(Value::Null, |v| Value::Bytes(v.to_vec()));
    let request = Value::Map(vec![(
        Value::Text("Attestation".into()),
        Value::Map(vec![
            (Value::Text("user_data".into()), field(user_data)),
            (Value::Text("nonce".into()), field(nonce)),
            (Value::Text("public_key".into()), Value::Null),
        ]),
    )]);
    let mut out = Vec::new();
    ciborium::into_writer(&request, &mut out).expect("CBOR into a Vec");
    out
}

/// The document of an `Attestation` response, or `Unavailable` naming the NSM's error code.
pub(crate) fn attestation_document(response: &[u8]) -> Result<Vec<u8>, TeeError> {
    let value: Value = ciborium::from_reader(response).map_err(|_| unavailable("response is not CBOR"))?;
    let Value::Map(mut entries) = value else {
        return Err(unavailable("response is not a map"));
    };
    if entries.len() != 1 {
        return Err(unavailable("response is not one variant"));
    }
    match entries.remove(0) {
        (Value::Text(variant), Value::Map(fields)) if variant == "Attestation" => {
            let mut documents = fields.into_iter().filter(|(k, _)| *k == Value::Text("document".into()));
            match (documents.next(), documents.next()) {
                (Some((_, Value::Bytes(document))), None) if !document.is_empty() => Ok(document),
                _ => Err(unavailable("attestation response has no document")),
            }
        }
        (Value::Text(variant), Value::Text(code)) if variant == "Error" => {
            let code: String = code.chars().filter(char::is_ascii_alphanumeric).take(64).collect();
            Err(unavailable(format!("error {code}")))
        }
        (Value::Text(variant), _) => {
            let variant: String = variant.chars().filter(char::is_ascii_alphanumeric).take(64).collect();
            Err(unavailable(format!("unexpected {variant} response")))
        }
        _ => Err(unavailable("response is not one variant")),
    }
}

/// `/dev/nsm`, open for the process's lifetime.
pub(crate) struct NsmDevice(File);

impl NsmDevice {
    pub(crate) fn open() -> Result<Self, TeeError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEVICE)
            .map_err(|e| unavailable(format!("{DEVICE}: {e}")))?;
        Ok(Self(file))
    }
}

impl Nsm for NsmDevice {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, TeeError> {
        if request.len() > MAX_REQUEST {
            return Err(unavailable("request too large"));
        }
        let mut response = vec![0u8; MAX_RESPONSE];
        let len = seal_tee_nsm_sys::exchange(&self.0, request, &mut response)
            .map_err(|e| unavailable(format!("ioctl: {e}")))?;
        response.truncate(len);
        Ok(response)
    }
}

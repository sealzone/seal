//! The NSM device: `/dev/nsm`, one ioctl, CBOR in and out.
//!
//! The driver (Linux `drivers/misc/nsm.c`, and AWS's `nsm.ko` in the Nitro boot blobs) takes
//! one command, `NSM_IOCTL_RAW = _IOWR(0x0A, 0, struct nsm_raw)`, whose argument is two
//! `{u64 addr; u64 len}` buffers: the request, at most `MAX_REQUEST` bytes, and room for the
//! response, `MAX_RESPONSE` bytes. The driver writes the response's length back into the second
//! `len`. The ioctl is this crate's only `unsafe` code (`ioctl`).
//!
//! Requests and responses are CBOR in the encoding AWS's `aws-nitro-enclaves-nsm-api` gives its
//! serde enums (externally tagged): an attestation request is
//! `{"Attestation": {"user_data": bytes / null, "nonce": bytes / null, "public_key": null}}`,
//! answered by `{"Attestation": {"document": bytes}}` or `{"Error": "<code>"}`. That crate is
//! not used: it pulls `serde_cbor` (unmaintained, refused in `deny.toml`) and `nix`.

use std::fs::File;
use std::os::fd::AsRawFd;

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
        let len = raw::exchange(&self.0, request, &mut response).map_err(|e| unavailable(format!("ioctl: {e}")))?;
        response.truncate(len);
        Ok(response)
    }
}

/// The ioctl itself.
pub(crate) mod raw {
    use super::*;

    /// `struct nsm_iovec` (`include/uapi/linux/nsm.h`).
    #[repr(C)]
    struct Iovec {
        addr: u64,
        len: u64,
    }

    /// `struct nsm_raw`.
    #[repr(C)]
    struct Raw {
        request: Iovec,
        response: Iovec,
    }

    /// `_IOWR(type, nr, size)` as Linux encodes it on x86_64 and arm64: direction (read and
    /// write = 3) in bits 30..32, the argument's size in bits 16..30, the type in 8..16, the
    /// number in 0..8.
    pub(crate) const fn iowr(ty: u8, nr: u8, size: usize) -> u64 {
        (3 << 30) | ((size as u64) << 16) | ((ty as u64) << 8) | nr as u64
    }

    /// `NSM_IOCTL_RAW`: `_IOWR(0x0A, 0, struct nsm_raw)` = `0xC0200A00`.
    pub(crate) const NSM_IOCTL_RAW: u64 = iowr(0x0A, 0, std::mem::size_of::<Raw>());

    /// Sends `request` and writes the response into `response`; its length.
    pub(super) fn exchange(device: &File, request: &[u8], response: &mut [u8]) -> std::io::Result<usize> {
        let mut raw = Raw {
            request: Iovec { addr: request.as_ptr() as u64, len: request.len() as u64 },
            response: Iovec { addr: response.as_mut_ptr() as u64, len: response.len() as u64 },
        };
        ioctl(device, &mut raw)?;
        let len = usize::try_from(raw.response.len).unwrap_or(usize::MAX);
        if len > response.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "response longer than its buffer"));
        }
        Ok(len)
    }

    #[allow(unsafe_code)]
    fn ioctl(device: &File, raw: &mut Raw) -> std::io::Result<()> {
        // SAFETY: `device` is an open file for the call's duration. `raw` is a valid,
        // exclusively borrowed `struct nsm_raw` whose size is the one the command encodes. Its
        // request buffer is a live shared slice the driver only reads; its response buffer is a
        // live exclusive slice of exactly the length given, which the driver writes at most
        // that much of. Neither outlives `exchange`, which holds both borrows across the call.
        let status = unsafe { libc::ioctl(device.as_raw_fd(), NSM_IOCTL_RAW as _, raw as *mut Raw) };
        if status < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

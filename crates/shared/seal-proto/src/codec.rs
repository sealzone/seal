//! Canonical encodings shared by every component.

use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

use crate::ProtoError;

/// Deterministic CBOR. The bytes behind every hash, signature and AEAD AAD.
pub fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

pub fn from_canonical<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
    ciborium::from_reader(bytes).map_err(|e| ProtoError::Malformed(format!("cbor: {e}")))
}

/// SHA-256 over the canonical encoding.
pub fn digest<T: Serialize>(value: &T) -> [u8; 32] {
    Sha256::digest(canonical(value)).into()
}

/// SHA-256 over a domain-separation label and the canonical encoding.
/// Every signature in Seal signs `labeled_digest(LABEL, msg)`, never raw bytes.
pub fn labeled_digest<T: Serialize>(label: &str, value: &T) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((label.len() as u32).to_be_bytes());
    h.update(label.as_bytes());
    h.update(canonical(value));
    h.finalize().into()
}

pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn from_b64url(s: &str) -> Result<Vec<u8>, ProtoError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| ProtoError::Malformed(format!("base64url: {e}")))
}

/// Serde helper: byte fields as base64url strings in JSON, bytes in CBOR.
pub mod bytes_b64 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&super::b64url(v))
        } else {
            s.serialize_bytes(v)
        }
    }

    /// Accepts a base64url string or raw bytes in BOTH modes: serde buffers
    /// internally-tagged enums through a "human readable" content deserializer
    /// even inside CBOR, so the mode flag cannot be trusted here.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use serde::de::Visitor;
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes or a base64url string")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                super::from_b64url(v).map_err(E::custom)
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
        }
        d.deserialize_any(V)
    }
}

/// Fixed-size byte arrays with the same JSON/CBOR behavior as `bytes_b64`.
pub mod array_b64 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        super::bytes_b64::serialize(v, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        let v = super::bytes_b64::deserialize(d)?;
        v.try_into().map_err(|v: Vec<u8>| serde::de::Error::custom(format!("expected {N} bytes, got {}", v.len())))
    }
}

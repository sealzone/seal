//! Canonical encodings shared by every component.

use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ProtoError;

/// Deterministic CBOR. The bytes behind every hash, signature and AEAD AAD.
pub fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

/// `canonical` for values that carry secrets (seal payloads, released keys): sized first,
/// then encoded into a buffer of exactly that capacity, so the encoding is never copied by
/// a reallocation and leaves no freed copy behind; zeroized when dropped. Decoding cannot
/// promise the same: ciborium reads through its own scratch buffer.
pub fn canonical_secret<T: Serialize>(value: &T) -> Zeroizing<Vec<u8>> {
    struct Size(usize);
    impl std::io::Write for Size {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut size = Size(0);
    ciborium::into_writer(value, &mut size).expect("CBOR encoding into a counter cannot fail");
    let mut out = Zeroizing::new(Vec::with_capacity(size.0));
    let mut writer = Bounded(&mut out);
    ciborium::into_writer(value, &mut writer).expect("a value encodes to the same size twice");
    out
}

/// Writes into a `Vec` only within its capacity, so it never reallocates.
struct Bounded<'a>(&'a mut Vec<u8>);
impl std::io::Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.0.capacity() - self.0.len() {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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

/// Unpadded base64url. Constant time (`base64ct`): no table lookup or branch depends on the
/// bytes, since secrets travel this way (`SecretVec` in JSON, session tokens).
pub fn b64url(bytes: &[u8]) -> String {
    use base64ct::Encoding as _;
    base64ct::Base64UrlUnpadded::encode_string(bytes)
}

/// Strict unpadded base64url (no padding, no stray trailing bits), in constant time like
/// `b64url`. The error never says where decoding failed: that would locate a byte of a secret
/// in messages that reach callers and logs.
pub fn from_b64url(s: &str) -> Result<Vec<u8>, ProtoError> {
    use base64ct::Encoding as _;
    base64ct::Base64UrlUnpadded::decode_vec(s).map_err(|_| ProtoError::Malformed("base64url: not canonical".into()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretVec;

    /// The constant-time codec accepts and produces exactly what the `base64` crate's strict
    /// unpadded URL-safe engine does: no padding, no stray trailing bits, no other alphabet.
    #[test]
    fn b64url_matches_the_strict_table_codec() {
        use base64::Engine as _;
        let table = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        for len in 0..70 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + len * 11) as u8).collect();
            let text = b64url(&bytes);
            assert_eq!(text, table.encode(&bytes), "{len}");
            assert_eq!(from_b64url(&text).unwrap(), bytes, "{len}");
        }
        for text in ["", "AA", "AB", "AAA", "AAB", "AAAA", "A", "AAAAA", "AA==", "A+", "A/", "_-", "-_8", "AA A"] {
            assert_eq!(from_b64url(text).ok(), table.decode(text).ok(), "{text:?}");
        }
    }

    proptest::proptest! {
        #[test]
        fn b64url_decodes_like_the_table_codec(text in "[A-Za-z0-9_-]{0,23}[A-Za-z0-9_+/= -]?") {
            use base64::Engine as _;
            let table = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&text).ok();
            proptest::prop_assert_eq!(from_b64url(&text).ok(), table);
        }
    }

    #[test]
    fn canonical_secret_is_canonical_in_an_exact_buffer() {
        for len in [0, 1, 23, 24, 255, 256, 70_000] {
            let value = (SecretVec::new(vec![7; len]), "policy", [1u32, 2, 3]);
            let encoded = canonical_secret(&value);
            assert_eq!(&encoded[..], &canonical(&value)[..], "{len}");
            assert_eq!(encoded.capacity(), encoded.len(), "{len}: sized once, never grown");
        }
    }
}

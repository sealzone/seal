//! Console control tokens: what lets a browser reach one tenant's documents. The console
//! issues them; this module checks them. The format is this text and the test vector below,
//! shared with the console as a contract, not as code:
//!
//! ```text
//! token     = "sealct_" base64url(payload) "." base64url(signature)     (no padding)
//! payload   = UTF-8 JSON object: v, kid, tenant, root_id, user, scope, iat, exp
//! signature = Ed25519(console key, "seal/console-control-token/v1\n" || payload bytes)
//! ```
//!
//! `v` is `VERSION`; `kid` names the console key (`kid`); `root_id` is the tenant's chain, 64
//! lowercase hex digits; `user` is the console user, for logs only; `scope` is `read` or
//! `submit`; `iat` and `exp` are Unix seconds, with `0 < exp - iat <= CONTROL_TOKEN_SECS`,
//! `iat` at most `ISSUED_AHEAD_SECS` ahead and `exp` not yet reached. No other member is
//! allowed.
//!
//! The signature is checked over the payload bytes as received, with the configured console
//! key `kid` names, before the payload is parsed as a token; no canonical encoding is involved.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use seal_proto::codec::from_b64url;
use seal_proto::{PublicKey, TenantId, TenantRootId, TrustedTime, UnixTime};

pub const PREFIX: &str = "sealct_";
pub const LABEL: &[u8] = b"seal/console-control-token/v1\n";
pub const VERSION: u64 = 1;
/// The longest life a token may have (`exp - iat`).
pub const CONTROL_TOKEN_SECS: u64 = 300;
/// How far the console's clock may run ahead: a token issued later than this is refused, so
/// none is good for longer than `CONTROL_TOKEN_SECS` plus this from now.
pub const ISSUED_AHEAD_SECS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Bundles, documents, proposals and telemetry.
    Read,
    /// Also: proposals, and submitting documents (which still need their admin signatures).
    Submit,
}

/// A verified token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlToken {
    pub tenant: TenantId,
    pub root_id: TenantRootId,
    /// The console user, for logs only.
    pub user: String,
    pub scope: Scope,
    pub exp: UnixTime,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    v: u64,
    /// Read before the signature is checked (`KeyName`).
    #[serde(rename = "kid")]
    _kid: String,
    tenant: TenantId,
    root_id: String,
    user: String,
    scope: Scope,
    iat: UnixTime,
    exp: UnixTime,
}

/// Only what selects the key, read before the signature is checked.
#[derive(Deserialize)]
struct KeyName {
    kid: String,
}

/// Lowercase hex of the first 8 bytes of SHA-256 of the console public key.
pub fn kid(key: &PublicKey) -> String {
    Sha256::digest(key.0)[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// The console's public keys, by `kid`.
pub struct ConsoleKeys(Vec<(String, ed25519_dalek::VerifyingKey)>);

impl ConsoleKeys {
    /// Refuses a key that is not a valid Ed25519 point.
    pub fn new(keys: &[PublicKey]) -> Result<Self, String> {
        keys.iter()
            .map(|k| {
                let key = ed25519_dalek::VerifyingKey::from_bytes(&k.0)
                    .map_err(|_| format!("console key {k} is not an Ed25519 public key"))?;
                Ok((kid(k), key))
            })
            .collect::<Result<_, String>>()
            .map(Self)
    }

    /// The token, if it verifies and has not expired at `time.latest()`. The reason for a
    /// refusal is for logs.
    pub fn verify(&self, token: &str, time: &TrustedTime) -> Result<ControlToken, &'static str> {
        let (payload, signature) =
            token.strip_prefix(PREFIX).and_then(|t| t.split_once('.')).ok_or("not a control token")?;
        let payload = from_b64url(payload).map_err(|_| "payload is not base64url")?;
        let signature = from_b64url(signature).map_err(|_| "signature is not base64url")?;
        let signature = ed25519_dalek::Signature::from_slice(&signature).map_err(|_| "not an Ed25519 signature")?;
        let name: KeyName = serde_json::from_slice(&payload).map_err(|_| "payload names no kid")?;
        let (_, key) = self.0.iter().find(|(kid, _)| *kid == name.kid).ok_or("unknown console key")?;
        key.verify_strict(&[LABEL, &payload].concat(), &signature).map_err(|_| "bad signature")?;

        let p: Payload = serde_json::from_slice(&payload).map_err(|_| "malformed payload")?;
        if p.v != VERSION {
            return Err("unknown version");
        }
        let lowercase_hex =
            p.root_id.len() == 64 && p.root_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !lowercase_hex {
            return Err("root_id is not 64 lowercase hex digits");
        }
        let root_id: TenantRootId = p.root_id.parse().map_err(|_| "malformed root_id")?;
        if p.exp <= p.iat || p.exp - p.iat > CONTROL_TOKEN_SECS {
            return Err("lifetime out of range");
        }
        if p.iat > time.latest().saturating_add(ISSUED_AHEAD_SECS) {
            return Err("issued in the future");
        }
        if time.latest() >= p.exp {
            return Err("expired");
        }
        Ok(ControlToken { tenant: p.tenant, root_id, user: p.user, scope: p.scope, exp: p.exp })
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;
    use seal_proto::codec::b64url;

    use super::*;

    /// The contract's test vector; the console's own tests repeat it byte for byte.
    const VECTOR: &str = "sealct_eyJ2IjoxLCJraWQiOiIzNDc1MGY5OGJkNTlmY2ZjIiwidGVuYW50IjoiYWNtZSIsInJvb3RfaWQiOiIwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3IiwidXNlciI6IjAxOTJmMWEwLTAwMDAtNzAwMC04MDAwLTAwMDAwMDAwMDAwMSIsInNjb3BlIjoic3VibWl0IiwiaWF0IjoxODAwMDAwMDAwLCJleHAiOjE4MDAwMDAzMDB9.gUFIBeT6vHJCSnyf-4V5czOMdfOFvVlFjawzfwBf1KuHoWxzIC7BaMB9DLFOsKgLmznzYam-zwxR0kkytrQTDQ";
    const PAYLOAD: &str = r#"{"v":1,"kid":"34750f98bd59fcfc","tenant":"acme","root_id":"0707070707070707070707070707070707070707070707070707070707070707","user":"0192f1a0-0000-7000-8000-000000000001","scope":"submit","iat":1800000000,"exp":1800000300}"#;

    fn console(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }
    fn public(key: &ed25519_dalek::SigningKey) -> PublicKey {
        PublicKey(key.verifying_key().to_bytes())
    }
    fn keys(seeds: &[u8]) -> ConsoleKeys {
        ConsoleKeys::new(&seeds.iter().map(|&s| public(&console(s))).collect::<Vec<_>>()).unwrap()
    }
    fn issue(key: &ed25519_dalek::SigningKey, payload: &str) -> String {
        let sig = key.sign(&[LABEL, payload.as_bytes()].concat());
        format!("{PREFIX}{}.{}", b64url(payload.as_bytes()), b64url(&sig.to_bytes()))
    }
    fn at(t: UnixTime) -> TrustedTime {
        TrustedTime::exact(t)
    }

    #[test]
    fn the_contract_vector_verifies() {
        assert_eq!(kid(&public(&console(1))), "34750f98bd59fcfc");
        assert_eq!(issue(&console(1), PAYLOAD), VECTOR, "the same bytes as the console signs");
        let token = keys(&[2, 1]).verify(VECTOR, &at(1_800_000_299)).unwrap();
        assert_eq!(token.tenant, TenantId::new("acme").unwrap());
        assert_eq!(token.root_id, TenantRootId([7; 32]));
        assert_eq!(token.user, "0192f1a0-0000-7000-8000-000000000001");
        assert_eq!(token.scope, Scope::Submit);
        assert_eq!(keys(&[1]).verify(VECTOR, &at(1_800_000_300)), Err("expired"));
        assert_eq!(
            keys(&[1]).verify(VECTOR, &TrustedTime { now: 1_800_000_295, radius: 5 }),
            Err("expired"),
            "against the latest end of the interval"
        );
        assert_eq!(keys(&[2]).verify(VECTOR, &at(1_800_000_000)), Err("unknown console key"), "a rotated-out key");
        assert_eq!(keys(&[1]).verify(VECTOR, &at(1_800_000_000 - ISSUED_AHEAD_SECS)).unwrap().scope, Scope::Submit);
        assert_eq!(
            keys(&[1]).verify(VECTOR, &at(1_800_000_000 - ISSUED_AHEAD_SECS - 1)),
            Err("issued in the future"),
            "a token minted ahead would outlive CONTROL_TOKEN_SECS"
        );
    }

    #[test]
    fn the_signature_covers_the_bytes_as_received() {
        // Same JSON value, other bytes: whitespace changes the signed payload.
        let spaced = PAYLOAD.replace(",\"kid\"", ", \"kid\"");
        let (_, sig) = VECTOR.split_once('.').unwrap();
        let swapped = format!("{PREFIX}{}.{sig}", b64url(spaced.as_bytes()));
        assert_eq!(keys(&[1]).verify(&swapped, &at(1_800_000_000)), Err("bad signature"));
        // Signed as sent, the spaced form is a valid token.
        assert!(keys(&[1]).verify(&issue(&console(1), &spaced), &at(1_800_000_000)).is_ok());

        let victim = PAYLOAD.replace("acme", "victim");
        let edited = format!("{PREFIX}{}.{sig}", b64url(victim.as_bytes()));
        assert_eq!(keys(&[1]).verify(&edited, &at(1_800_000_000)), Err("bad signature"));
        // Another key claiming this key's kid.
        assert_eq!(keys(&[1]).verify(&issue(&console(2), PAYLOAD), &at(1_800_000_000)), Err("bad signature"));
    }

    #[test]
    fn malformed_tokens_are_refused() {
        let k = keys(&[1]);
        let refused = |payload: &str| k.verify(&issue(&console(1), payload), &at(1_800_000_000)).unwrap_err();
        assert_eq!(refused(&PAYLOAD.replace(r#""v":1"#, r#""v":2"#)), "unknown version");
        assert_eq!(
            refused(&PAYLOAD.replace(r#""exp":1800000300"#, r#""exp":1800000300,"admin":true"#)),
            "malformed payload"
        );
        assert_eq!(refused(&PAYLOAD.replace(r#""scope":"submit""#, r#""scope":"admin""#)), "malformed payload");
        assert_eq!(
            refused(&PAYLOAD.replace(r#","user":"0192f1a0-0000-7000-8000-000000000001""#, "")),
            "malformed payload"
        );
        assert_eq!(refused(&PAYLOAD.replace("07070707", "0707070A")), "root_id is not 64 lowercase hex digits");
        assert_eq!(refused(&PAYLOAD.replace("1800000300", "1800000301")), "lifetime out of range");
        assert_eq!(refused(&PAYLOAD.replace(r#""tenant":"acme""#, r#""tenant":"Acme""#)), "malformed payload");
        let duplicate = PAYLOAD.replace(r#""scope":"submit""#, r#""scope":"read","scope":"submit""#);
        assert_eq!(refused(&duplicate), "malformed payload");

        assert_eq!(k.verify(&format!("{VECTOR}="), &at(1_800_000_000)), Err("signature is not base64url"), "padding");
        assert_eq!(k.verify(&VECTOR.replacen("sealct_", "sealxx_", 1), &at(1_800_000_000)), Err("not a control token"));
        assert_eq!(k.verify(VECTOR.split_once('.').unwrap().0, &at(1_800_000_000)), Err("not a control token"));
        assert_eq!(k.verify(&format!("{VECTOR}.x"), &at(1_800_000_000)), Err("signature is not base64url"));
    }
}

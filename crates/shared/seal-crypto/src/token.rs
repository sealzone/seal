//! Token encryption authenticates claims; the session resolver authorizes their use.
//!
//! Format (`seal_proto::session::SessionClaims`): `TOKEN_PREFIX + base64url(version:u8 ||
//! service_key_version:u32-BE || salt:32 || nonce:12 || AES-256-GCM(k, canonical(claims)))`,
//! `k = HKDF-SHA256(salt = salt, ikm = token seed, info = TOKEN_PER_TOKEN)`. The AEAD's
//! associated data is the 49-byte header before the ciphertext, so the version and service key
//! version are authenticated too. Redeeming also requires the claims' `service_key_version` to
//! equal the header's.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use crate::{kdf, CryptoError, TokenKey};
use seal_proto::codec::{b64url, canonical, from_b64url, from_canonical};
use seal_proto::session::{SessionClaims, TOKEN_PREFIX};
use seal_proto::ServiceKeyVersion;

/// The token format version.
pub const TOKEN_VERSION: u8 = 1;
const HEADER_LEN: usize = 1 + 4 + 32 + 12;
const TAG_LEN: usize = 16;

/// The parsed, still unauthenticated header and the ciphertext.
struct Parts {
    service_key_version: ServiceKeyVersion,
    header: [u8; HEADER_LEN],
    ciphertext: Vec<u8>,
}

fn parse(token: &str) -> Result<Parts, CryptoError> {
    let body = token.strip_prefix(TOKEN_PREFIX).ok_or_else(|| CryptoError::Malformed("session token prefix".into()))?;
    let raw = from_b64url(body).map_err(|_| CryptoError::Malformed("session token encoding".into()))?;
    if raw.len() < HEADER_LEN + TAG_LEN {
        return Err(CryptoError::Malformed("session token too short".into()));
    }
    if raw[0] != TOKEN_VERSION {
        return Err(CryptoError::Malformed(format!("session token version {}", raw[0])));
    }
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&raw[..HEADER_LEN]);
    let service_key_version = ServiceKeyVersion(u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]));
    Ok(Parts { service_key_version, header, ciphertext: raw[HEADER_LEN..].to_vec() })
}

fn nonce(header: &[u8; HEADER_LEN]) -> Nonce<aes_gcm::aead::consts::U12> {
    let n: [u8; 12] = header[37..].try_into().expect("12-byte nonce");
    Nonce::from(n)
}

impl TokenKey {
    fn aead(&self, salt: &[u8]) -> Aes256Gcm {
        let mut key = Zeroizing::new([0u8; 32]);
        kdf::expand_into(Some(salt), self.seed.expose(), &kdf::info(kdf::TOKEN_PER_TOKEN, &[]), key.as_mut());
        Aes256Gcm::new((&*key).into())
    }

    /// The token for `claims`, under this key's service key version (whatever `claims` says;
    /// `redeem` refuses a mismatch).
    pub fn issue(&self, claims: &SessionClaims, rng: &mut impl rand::CryptoRng) -> seal_proto::Bearer {
        let mut header = [0u8; HEADER_LEN];
        header[0] = TOKEN_VERSION;
        header[1..5].copy_from_slice(&self.service_key_version.0.to_be_bytes());
        rng.fill_bytes(&mut header[5..]);
        let (salt, nonce) = (&header[5..37], nonce(&header));
        let plaintext = Zeroizing::new(canonical(claims));
        let ciphertext = self
            .aead(salt)
            .encrypt(&nonce, Payload { msg: &plaintext, aad: &header })
            .expect("AES-GCM encryption of a bounded message cannot fail");
        let raw = [&header[..], &ciphertext].concat();
        seal_proto::Bearer::new(format!("{TOKEN_PREFIX}{}", b64url(&raw)))
    }
    /// `Malformed` for a token that does not parse, `Decrypt` for one this key did not issue
    /// (another service key version, another key, any change).
    pub fn redeem(&self, token: &str) -> Result<SessionClaims, CryptoError> {
        let parts = parse(token)?;
        if parts.service_key_version != self.service_key_version {
            return Err(CryptoError::Decrypt);
        }
        let (salt, nonce) = (&parts.header[5..37], nonce(&parts.header));
        let plaintext = Zeroizing::new(
            self.aead(salt)
                .decrypt(&nonce, Payload { msg: &parts.ciphertext, aad: &parts.header })
                .map_err(|_| CryptoError::Decrypt)?,
        );
        let claims: SessionClaims =
            from_canonical(&plaintext).map_err(|_| CryptoError::Malformed("session claims".into()))?;
        if claims.service_key_version != self.service_key_version {
            return Err(CryptoError::Malformed("session claims name another service key version".into()));
        }
        Ok(claims)
    }
}

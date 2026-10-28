//! The SDK tunnel: how apps reach the enclave's data plane.
//!
//! The app talks plaintext to a loopback listener inside its own process, using `s.key` = a
//! local key (`LOCAL_KEY_PREFIX…`). For each app connection the tunnel makes a TLS connection
//! to the enclave's one port (the API's), pinned to the attested key, with ALPN [`ALPN`]
//! instead of the API's `http/1.1`, and before any protocol bytes sends:
//!
//! ```text
//! MAGIC (8 bytes) || u32 big-endian length || canonical(TunnelPreamble)
//! ```
//!
//! then forwards the app's bytes untouched; the session's blob says which protocol they are.
//! After the SDK extends a session, the tunnel makes a short connection to each replica
//! holding one of its connections and sends an `Extend` preamble with the new token; the
//! replica moves the expiry of every live connection of that `session_id` (same caller) and
//! answers `EXTEND_OK` or closes. The adapter finds the local key by prefix
//! (`find_local_key`) in its protocol's credential slot; the resolver accepts a local key
//! only if `SHA-256(local key) == local_key_sha256`. The token never leaves the SDK, and
//! `s.key` is worthless without the tunnel's connection.

use serde::{Deserialize, Serialize};

use crate::{codec, Bearer};

/// The TLS ALPN protocol of tunnel connections.
pub const ALPN: &[u8] = b"seal-tunnel/1";
pub const MAGIC: &[u8; 8] = b"SEALTUN1";
pub const MAX_PREAMBLE_LEN: u32 = 64 * 1024;
/// Prefix of local tunnel keys (`s.key`).
pub const LOCAL_KEY_PREFIX: &str = "seallk_";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TunnelPreamble {
    /// Start of an app connection; the protocol's bytes follow.
    Connect(TunnelConnect),
    /// Apply an extension to this replica's live connections of the token's session;
    /// nothing follows.
    Extend { token: Bearer },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelConnect {
    pub token: Bearer,
    #[serde(with = "codec::array_b64")]
    pub local_key_sha256: [u8; 32],
}

/// The enclave's one-byte answer to an accepted `Extend`.
pub const EXTEND_OK: u8 = 0x00;

pub fn encode(p: &TunnelPreamble) -> Vec<u8> {
    let body = codec::canonical(p);
    let mut out = Vec::with_capacity(12 + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Finds a local key in a credential value, e.g. after `Bearer ` or inside a `user:password`
/// pair. Returns the first match.
pub fn find_local_key(value: &str) -> Option<&str> {
    let rest = &value[value.find(LOCAL_KEY_PREFIX)?..];
    let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')).unwrap_or(rest.len());
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_local_keys() {
        assert_eq!(find_local_key("Bearer seallk_abc-DEF_1"), Some("seallk_abc-DEF_1"));
        assert_eq!(find_local_key("user:seallk_x9 rest"), Some("seallk_x9"));
        assert_eq!(find_local_key("Bearer sealtok_a"), None, "session tokens never reach the app");
        assert_eq!(find_local_key("sk-proj-123"), None);
    }
}

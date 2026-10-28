//! Secret-carrying wire values. Zeroized on drop, redacted in `Debug`, no
//! `Display`, no `Clone`. Use `expose()` only at the point of use.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// Secret bytes on the wire (an upstream secret, released key material).
#[derive(PartialEq, Eq)]
pub struct SecretVec(Zeroizing<Vec<u8>>);

impl SecretVec {
    pub fn new(v: Vec<u8>) -> Self {
        Self(Zeroizing::new(v))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    /// Explicit copy. Named so every duplication of a secret is greppable.
    pub fn duplicate(&self) -> Self {
        Self::new(self.0.to_vec())
    }
}

impl std::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SecretVec(<{} bytes redacted>)", self.0.len())
    }
}

impl Serialize for SecretVec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        crate::codec::bytes_b64::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for SecretVec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        crate::codec::bytes_b64::deserialize(d).map(Self::new)
    }
}

/// A bearer credential string: session tokens, OIDC JWTs, local tunnel keys.
/// Anyone holding one can use it, so it is treated like a secret.
#[derive(PartialEq, Eq)]
pub struct Bearer(Zeroizing<String>);

impl Bearer {
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn duplicate(&self) -> Self {
        Self::new(self.0.to_string())
    }
}

impl std::fmt::Debug for Bearer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let prefix: String = self.0.chars().take_while(|c| *c != '_').take(8).collect();
        write!(f, "Bearer({prefix}_<redacted>)")
    }
}

impl Serialize for Bearer {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bearer {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

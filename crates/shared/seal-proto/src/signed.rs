//! Signatures: every signed document in Seal is a `Signed<T>`.

use serde::{Deserialize, Serialize};

use crate::{codec, KeyId};

/// A signature over the 32-byte message `labeled_digest(label, msg)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub signer: KeyId,
    pub alg: SigAlg,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alg", rename_all = "snake_case")]
pub enum SigAlg {
    /// Ed25519 directly over the 32-byte message.
    Ed25519 {
        #[serde(with = "codec::bytes_b64")]
        sig: Vec<u8>,
    },
    /// A passkey (WebAuthn assertion, ES256). The message is the WebAuthn
    /// challenge: `clientDataJSON.challenge == base64url(message)`,
    /// `type == "webauthn.get"`, origin's RP ID == the key's `rp_id`, UP and UV flags set;
    /// the P-256 signature covers `authenticator_data || SHA-256(client_data_json)`.
    WebAuthnEs256 {
        #[serde(with = "codec::bytes_b64")]
        authenticator_data: Vec<u8>,
        #[serde(with = "codec::bytes_b64")]
        client_data_json: Vec<u8>,
        /// DER ECDSA signature.
        #[serde(with = "codec::bytes_b64")]
        sig: Vec<u8>,
    },
}

/// A message plus the signatures over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    pub body: T,
    pub signatures: Vec<Signature>,
}

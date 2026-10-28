//! Client for the guardian's HTTP surface, used by the enclave. HTTPS through
//! `seal_net::HttpsClient` (baked roots), so a `KeyRequest`, whose tenant bundle names the
//! tenant's grants and identities, is not readable on the network. TLS is terminated in
//! front of the guardian by an ordinary, untrusted proxy: security still rests on the
//! request's evidence and on keys HPKE-sealed to a key only the attested requester holds,
//! so the guardian's frozen code holds no TLS certificate to renew.
//! A denial comes back as `GuardianError::Refused`, without detail; network failures, and
//! any response that is malformed or not signed by the guardian for exactly this request, as
//! `GuardianError::Unavailable`.

use std::sync::Arc;

use seal_crypto::hpke::KEY_RELEASE_INFO;
use seal_crypto::EphemeralKey;
use seal_proto::codec::{canonical, from_canonical, labeled_digest};
use seal_proto::freshness::GuardianChallenge;
use seal_proto::release::{
    KeyRequest, KeyRequestBinding, KeyResponse, ReleasedKeys, KEY_REQUEST_BINDING_LABEL, KEY_RESPONSE_LABEL,
};
use seal_proto::PublicKey;

use crate::GuardianError;

pub struct GuardianClient {
    base: url::Url,
    https: Arc<seal_net::HttpsClient>,
    guardian_key: PublicKey,
}

impl GuardianClient {
    /// `base` must be `https://` (`HttpsClient` refuses anything else, so requests to another
    /// scheme fail as `Unavailable`). `guardian_key` is the guardian's key from
    /// `Trust::guardians`: `keys` refuses any response it did not sign.
    pub fn new(base: url::Url, https: Arc<seal_net::HttpsClient>, guardian_key: PublicKey) -> Self {
        Self { base, https, guardian_key }
    }

    /// `base` + `path`, whether or not `base` ends in `/`.
    fn url(&self, path: &str) -> String {
        format!("{}/{path}", self.base.as_str().trim_end_matches('/'))
    }

    pub async fn challenge(&self) -> Result<GuardianChallenge, GuardianError> {
        let (status, body) = self.https.get(&self.url("v1/challenge"), &[]).await.map_err(unavailable)?;
        parse(status, &body)
    }

    /// `POST /v1/keys`. The response is returned only if `verify_response` accepts it for
    /// `req.binding` under the configured guardian key; open it with `open_response`.
    pub async fn keys(&self, req: &KeyRequest) -> Result<KeyResponse, GuardianError> {
        let body = serde_json::to_vec(req).map_err(|e| GuardianError::Unavailable(format!("encode request: {e}")))?;
        let (status, body) = self.https.post(&self.url("v1/keys"), &[], &body).await.map_err(unavailable)?;
        let resp: KeyResponse = parse(status, &body)?;
        verify_response(&self.guardian_key, &req.binding, &resp)?;
        Ok(resp)
    }
}

/// `resp.signature` is `guardian_key`'s over
/// `labeled_digest(KEY_RESPONSE_LABEL, (labeled_digest(KEY_REQUEST_BINDING_LABEL, binding), hpke_enc, ciphertext))`.
/// `Unavailable` otherwise: something on the path answered instead of the guardian.
pub fn verify_response(
    guardian_key: &PublicKey,
    binding: &KeyRequestBinding,
    resp: &KeyResponse,
) -> Result<(), GuardianError> {
    let message = (labeled_digest(KEY_REQUEST_BINDING_LABEL, binding), resp.hpke_enc.clone(), resp.ciphertext.clone());
    seal_crypto::sign::verify(guardian_key, KEY_RESPONSE_LABEL, &message, &resp.signature).map_err(|_| {
        tracing::warn!("key response not signed by the guardian key for this request");
        GuardianError::Unavailable("response not signed by the guardian for this request".into())
    })
}

/// Opens a verified response with the requester's ephemeral key: HPKE with
/// `info = KEY_RELEASE_INFO`, `aad = canonical(binding)`, plaintext `canonical(ReleasedKeys)`.
pub fn open_response(
    ephemeral: &EphemeralKey,
    binding: &KeyRequestBinding,
    resp: &KeyResponse,
) -> Result<ReleasedKeys, GuardianError> {
    let opened = seal_crypto::hpke::open_ephemeral(
        ephemeral,
        &resp.hpke_enc,
        &resp.ciphertext,
        KEY_RELEASE_INFO,
        &canonical(binding),
    )
    .map_err(|_| GuardianError::Unavailable("cannot open the released keys".into()))?;
    from_canonical(opened.expose()).map_err(|_| GuardianError::Unavailable("malformed released keys".into()))
}

fn unavailable(e: seal_net::NetError) -> GuardianError {
    GuardianError::Unavailable(e.to_string())
}

/// 200 → the JSON body; 403 → `Refused`; anything else → `Unavailable`.
fn parse<T: serde::de::DeserializeOwned>(status: u16, body: &[u8]) -> Result<T, GuardianError> {
    match status {
        200 => serde_json::from_slice(body).map_err(|e| GuardianError::Unavailable(format!("malformed response: {e}"))),
        403 => Err(GuardianError::Refused),
        other => Err(GuardianError::Unavailable(format!("guardian answered HTTP {other}"))),
    }
}

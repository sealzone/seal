//! `seal changes sign --passkey`: an admin passkey on a security key, over USB (CTAP2 over HID,
//! `ctap-hid-fido2`). The CLI makes the assertion a browser would for the console: its
//! `clientDataJSON` names the challenge (the document's labeled digest) and the origin
//! `https://<rp_id>`, and the key signs SHA-256 of it with its authenticator data. The passkey is
//! discoverable (the console registers it so), so no credential id is needed; a key with a PIN
//! is unlocked with it, which also sets the UV flag the verifier requires.

use anyhow::{anyhow, bail, Context as _};
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::{FidoKeyHidFactory, LibCfg};
use serde::Serialize;

use seal_crypto::sign::{admin_key_id, verify_admin};
use seal_proto::codec::{b64url, labeled_digest};
use seal_proto::signed::{SigAlg, Signature, Signed};
use seal_proto::state::{AdminKey, TenantRoot};

/// Authenticator data and DER signature, one pair per credential the key offers.
type Assertions = Vec<(Vec<u8>, Vec<u8>)>;

/// Adds the security key's signature to `signed`: one that verifies under a passkey admin key
/// of `root`, replacing any signature already naming that key.
pub async fn cosign<T: Serialize>(root: &TenantRoot, label: &str, signed: &mut Signed<T>) -> anyhow::Result<()> {
    cosign_with(root, label, signed, |rp_id, client_data_json| assert(&rp_id, &client_data_json)).await
}

/// `cosign` with the authenticator given: the security key, or a test's software key.
async fn cosign_with<T: Serialize>(
    root: &TenantRoot,
    label: &str,
    signed: &mut Signed<T>,
    authenticator: impl FnOnce(String, Vec<u8>) -> anyhow::Result<Assertions> + Send + 'static,
) -> anyhow::Result<()> {
    let passkeys: Vec<(&AdminKey, &str)> = root
        .admin_keys
        .iter()
        .filter_map(|k| match k {
            AdminKey::WebAuthnEs256 { rp_id, .. } => Some((k, rp_id.as_str())),
            AdminKey::Ed25519 { .. } => None,
        })
        .collect();
    let Some(&(_, rp_id)) = passkeys.first() else {
        bail!("root version {} has no passkey admin key: sign with --key-file", root.version);
    };
    let rp_id = rp_id.to_owned();
    let client_data_json = serde_json::to_vec(&serde_json::json!({
        "type": "webauthn.get",
        "challenge": b64url(&labeled_digest(label, &signed.body)),
        "origin": format!("https://{rp_id}"),
        "crossOrigin": false,
    }))?;
    // The key blocks until touched: off the async runtime.
    let assertions = {
        let (rp_id, client_data_json) = (rp_id.clone(), client_data_json.clone());
        tokio::task::spawn_blocking(move || authenticator(rp_id, client_data_json)).await??
    };
    for (authenticator_data, sig) in assertions {
        for &(key, _) in passkeys.iter().filter(|(_, r)| *r == rp_id) {
            let signature = Signature {
                signer: admin_key_id(key),
                alg: SigAlg::WebAuthnEs256 {
                    authenticator_data: authenticator_data.clone(),
                    client_data_json: client_data_json.clone(),
                    sig: sig.clone(),
                },
            };
            if verify_admin(key, label, &signed.body, &signature).is_ok() {
                signed.signatures.retain(|s| s.signer != signature.signer);
                signed.signatures.push(signature);
                return Ok(());
            }
        }
    }
    bail!("the security key holds no passkey that is an admin key of root version {}", root.version)
}

/// The key's assertions for `rp_id` over `client_data_json` (the library hashes what it is given
/// as the challenge, which is WebAuthn's clientDataHash): authenticator data and DER signature.
fn assert(rp_id: &str, client_data_json: &[u8]) -> anyhow::Result<Assertions> {
    let mut cfg = LibCfg::init().with_keep_alive_msg_to_stderr(true);
    cfg.keep_alive_msg = "Touch your security key to sign".into();
    let device = FidoKeyHidFactory::create(&cfg).map_err(|e| anyhow!("{e}: plug in one security key"))?;
    let has_pin = device.enable_info_option(&InfoOption::ClientPin).map_err(|e| anyhow!("{e}"))? == Some(true);
    let pin =
        if has_pin { Some(rpassword::prompt_password("Security key PIN: ").context("reading the PIN")?) } else { None };
    let mut args = GetAssertionArgsBuilder::new(rp_id, client_data_json);
    if let Some(pin) = &pin {
        args = args.pin(pin);
    }
    let assertions = device.get_assertion_with_args(&args.build()).map_err(|e| anyhow!("security key: {e}"))?;
    Ok(assertions.into_iter().map(|a| (a.auth_data, a.signature)).collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use p256::ecdsa::signature::Signer as _;
    use sha2::{Digest, Sha256};

    use super::*;

    const LABEL: &str = "seal/test/v1";

    // A software authenticator: signs authenticator data (RP ID hash, UP and UV set, a counter)
    // and the clientDataHash, as a security key does.
    fn authenticator(
        key: p256::ecdsa::SigningKey,
        flags: u8,
    ) -> impl FnOnce(String, Vec<u8>) -> anyhow::Result<Assertions> {
        move |rp_id, client_data_json| {
            let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
            data.push(flags);
            data.extend_from_slice(&7u32.to_be_bytes());
            let signed = [&data[..], &Sha256::digest(&client_data_json)[..]].concat();
            let sig: p256::ecdsa::Signature = key.sign(&signed);
            Ok(vec![(data, sig.to_der().as_bytes().to_vec())])
        }
    }

    fn root(keys: &[&p256::ecdsa::SigningKey]) -> TenantRoot {
        let admin_keys: BTreeSet<AdminKey> = keys
            .iter()
            .map(|k| AdminKey::WebAuthnEs256 {
                sec1: k.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
                rp_id: "seal.zone".into(),
            })
            .collect();
        TenantRoot { tenant: "acme".parse().unwrap(), version: 2, admin_keys, threshold: 1, cosign_releases: false }
    }

    fn key(seed: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    #[tokio::test]
    async fn the_assertion_verifies_as_the_admin_passkey() {
        let (mine, other) = (key(1), key(2));
        let root = root(&[&other, &mine]);
        let mut signed = Signed { body: "state".to_string(), signatures: vec![] };
        cosign_with(&root, LABEL, &mut signed, authenticator(mine.clone(), 0x05)).await.unwrap();
        assert_eq!(signed.signatures.len(), 1);
        let admin = root.admin_keys.iter().find(|k| admin_key_id(k) == signed.signatures[0].signer).unwrap();
        verify_admin(admin, LABEL, &signed.body, &signed.signatures[0]).unwrap();
        // Signing again replaces the signature instead of adding a second.
        cosign_with(&root, LABEL, &mut signed, authenticator(mine, 0x05)).await.unwrap();
        assert_eq!(signed.signatures.len(), 1);
    }

    #[tokio::test]
    async fn a_key_that_is_no_admin_or_skips_verification_is_refused() {
        let root = root(&[&key(1)]);
        let mut signed = Signed { body: "state".to_string(), signatures: vec![] };
        assert!(cosign_with(&root, LABEL, &mut signed, authenticator(key(3), 0x05)).await.is_err());
        // User presence without user verification (no PIN, no biometric) does not count.
        assert!(cosign_with(&root, LABEL, &mut signed, authenticator(key(1), 0x01)).await.is_err());
        assert!(signed.signatures.is_empty());
    }
}

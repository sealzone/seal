//! Named blobs in the browser API: the version the console signs, and what it shows of one.

use serde_json::Value;

use seal_crypto::sign::SigningKey;
use seal_proto::blob::{Blob, BlobHeader, DekWrap, BLOB_VERSION, POLICY_LABEL};
use seal_proto::codec::labeled_digest;
use seal_proto::named::{NamedBlobVersion, NAMED_BLOB_LABEL};
use seal_proto::policy::SecretPolicy;
use seal_proto::state::{AdminKey, TenantRoot};
use seal_proto::{AppName, BlobId, PlatformId, TenantId, TenantKeyVersion, TenantRootId};
use seal_verify_wasm::api;

const ROOT_ID: TenantRootId = TenantRootId([6; 32]);

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

fn root(threshold: u8) -> TenantRoot {
    TenantRoot {
        tenant: TenantId::new("acme").unwrap(),
        version: 1,
        admin_keys: [1, 2].map(|n| AdminKey::Ed25519 { public_key: key(n).public_key() }).into(),
        threshold,
        cosign_releases: false,
    }
}

fn blob(root_id: TenantRootId) -> String {
    let policy = SecretPolicy::new("https://api.openai.com/v1", [AppName::new("checkout").unwrap()]).unwrap();
    Blob {
        header: BlobHeader {
            version: BLOB_VERSION,
            tenant: TenantId::new("acme").unwrap(),
            root_id,
            tenant_key_version: TenantKeyVersion(1),
            blob_id: BlobId([1; 8]),
            policy_digest: labeled_digest(POLICY_LABEL, &policy),
            created_at: 1,
        },
        policy,
        wraps: vec![DekWrap::Hpke { platform: PlatformId::Sim, enc: vec![1; 32], wrapped_dek: vec![2; 48] }],
        nonce: [3; 12],
        ciphertext: vec![4; 40],
    }
    .to_string()
}

fn describe(version: &NamedBlobVersion, threshold: u8) -> Value {
    let root = serde_json::to_string(&root(threshold)).unwrap();
    let version = serde_json::to_string(version).unwrap();
    serde_json::from_str(&api::describe_named_blob("acme", &ROOT_ID.to_string(), &root, &version).unwrap()).unwrap()
}

#[test]
fn the_console_drafts_signs_and_describes_a_version() {
    let text = blob(ROOT_ID);
    let draft = api::named_blob("acme", &ROOT_ID.to_string(), "openai", 1, &text, 100).unwrap();
    let mut version: NamedBlobVersion = serde_json::from_str(&draft).unwrap();
    assert!(version.entry.signatures.is_empty());
    assert_eq!(version.blob.as_deref(), Some(text.as_str()));

    let body = serde_json::to_string(&version.entry.body).unwrap();
    assert_eq!(
        api::labeled_digest_of(NAMED_BLOB_LABEL, &body).unwrap(),
        labeled_digest(NAMED_BLOB_LABEL, &version.entry.body)
    );

    let unsigned = describe(&version, 1);
    assert_eq!(unsigned["signed"], false);
    assert_eq!(unsigned["blob"]["destination"], "https://api.openai.com:443/v1");
    assert_eq!(unsigned["blob"]["apps"], serde_json::json!(["checkout"]));

    key(1).cosign(NAMED_BLOB_LABEL, &mut version.entry);
    let signed = describe(&version, 1);
    assert_eq!((signed["signed"].clone(), signed["problem"].clone()), (Value::Bool(true), Value::Null));
    assert_eq!(signed["signers"].as_array().unwrap().len(), 1);
    assert_eq!(describe(&version, 2)["signed"], false, "below a threshold of 2");

    let mut swapped = version.clone();
    swapped.blob = Some(blob(TenantRootId([7; 32])));
    assert_eq!(describe(&swapped, 1)["signed"], false, "another blob");
}

#[test]
fn drafts_refuse_what_no_enclave_would_take() {
    let root_id = ROOT_ID.to_string();
    assert!(api::named_blob("acme", &root_id, "open.ai", 1, &blob(ROOT_ID), 1).is_err(), "not a name");
    assert!(api::named_blob("acme", &root_id, "openai", 0, &blob(ROOT_ID), 1).is_err(), "version 0");
    assert!(api::named_blob("acme", &root_id, "openai", 1, &blob(TenantRootId([7; 32])), 1).is_err(), "another chain");
    let deletion: NamedBlobVersion =
        serde_json::from_str(&api::named_blob("acme", &root_id, "openai", 3, "", 1).unwrap()).unwrap();
    assert!(deletion.blob.is_none() && deletion.entry.body.blob.is_none());
}

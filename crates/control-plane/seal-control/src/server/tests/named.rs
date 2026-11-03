//! Named blobs: who may read and publish them, and what a version must carry.

use super::*;
use seal_proto::blob::{Blob, BlobHeader, DekWrap, BLOB_VERSION, POLICY_LABEL};
use seal_proto::named::{BlobRef, NamedBlob, NamedBlobVersion, NAMED_BLOB_LABEL, NAMED_BLOB_VERSIONS_KEPT};
use seal_proto::policy::SecretPolicy;
use seal_proto::{AppName, BlobId, BlobName};

fn blob_text(root_id: TenantRootId, id: u8) -> String {
    let policy = SecretPolicy::new("https://api.example.com/v1", [AppName::new("checkout").unwrap()]).unwrap();
    Blob {
        header: BlobHeader {
            version: BLOB_VERSION,
            tenant: acme(),
            root_id,
            tenant_key_version: TenantKeyVersion(1),
            blob_id: BlobId([id; 8]),
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

fn openai() -> BlobName {
    BlobName::new("openai").unwrap()
}

/// Version `version` of `name`, pointing at `text` (none: a deletion), signed by `admins`.
fn version(
    root_id: TenantRootId,
    name: BlobName,
    version: u64,
    text: Option<String>,
    admins: &[u8],
) -> NamedBlobVersion {
    let body = NamedBlob {
        tenant: acme(),
        root_id,
        name,
        version,
        blob: text.as_deref().map(|t| BlobRef::of(t).unwrap()),
        published_at: 1,
    };
    NamedBlobVersion { entry: signed(NAMED_BLOB_LABEL, body, admins), blob: text }
}

#[tokio::test]
async fn publishing_needs_the_latest_roots_threshold_and_the_next_version() {
    let env = Env::new().await;
    let root_id = env.root_id();
    let path = "/v1/tenants/acme/blobs/openai";
    let first = version(root_id, openai(), 1, Some(blob_text(root_id, 1)), &V1_ADMINS);
    let admin = || Auth::Key(V1_ADMINS[0]);
    assert_eq!(env.call("PUT", path, admin(), Some(&first)).await.0, 401, "no chain to sign for");
    env.ready().await;

    assert_eq!(env.call("PUT", path, Auth::None, Some(&first)).await.0, 401);
    let weak = version(root_id, openai(), 1, Some(blob_text(root_id, 1)), &V1_ADMINS[..1]);
    assert_eq!(env.call("PUT", path, admin(), Some(&weak)).await.0, 400, "below the threshold");
    let mut swapped = first.clone();
    swapped.blob = Some(blob_text(root_id, 2));
    assert_eq!(env.call("PUT", path, admin(), Some(&swapped)).await.0, 400, "not the blob signed for");
    let elsewhere = version(TenantRootId([9; 32]), openai(), 1, Some(blob_text(TenantRootId([9; 32]), 1)), &V1_ADMINS);
    assert_eq!(env.call("PUT", path, admin(), Some(&elsewhere)).await.0, 400, "another chain");
    let renamed = "/v1/tenants/acme/blobs/stripe";
    assert_eq!(env.call("PUT", renamed, admin(), Some(&first)).await.0, 400, "another name");
    let skipped = version(root_id, openai(), 2, Some(blob_text(root_id, 1)), &V1_ADMINS);
    assert_eq!(env.call("PUT", path, admin(), Some(&skipped)).await.0, 409);
    let nothing = version(root_id, openai(), 1, None, &V1_ADMINS);
    assert_eq!(env.call("PUT", path, admin(), Some(&nothing)).await.0, 409, "nothing to delete");

    assert_eq!(env.call("PUT", path, admin(), Some(&first)).await.0, 204);
    assert_eq!(env.call("PUT", path, admin(), Some(&first)).await.0, 409, "version 1 is taken");
    let got: NamedBlobVersion = env.get_json(path).await;
    assert_eq!(got, first);
    let listed: Vec<NamedBlobVersion> = env.get_json("/v1/tenants/acme/blobs").await;
    assert_eq!(listed, vec![first.clone()]);

    let second = version(root_id, openai(), 2, Some(blob_text(root_id, 2)), &V1_ADMINS);
    assert_eq!(env.call("PUT", path, admin(), Some(&second)).await.0, 204);
    let gone = version(root_id, openai(), 3, None, &V1_ADMINS);
    assert_eq!(env.call("PUT", path, admin(), Some(&gone)).await.0, 204);
    let got: NamedBlobVersion = env.get_json(path).await;
    assert_eq!(got, gone, "the newest version is served, a deletion included");
    let listed: Vec<NamedBlobVersion> = env.get_json("/v1/tenants/acme/blobs").await;
    assert!(listed.is_empty(), "deleted names are not listed");
    let versions: Vec<NamedBlobVersion> = env.get_json("/v1/tenants/acme/blobs/openai/versions").await;
    assert_eq!(versions, vec![gone, second, first]);
    assert_eq!(env.get("/v1/tenants/acme/blobs/stripe").await.0, 404);
    assert_eq!(env.get("/v1/tenants/acme/blobs/Open.AI").await.0, 400);
}

#[tokio::test]
async fn enclaves_read_a_name_and_members_read_them_all() {
    let env = Env::new().await;
    env.ready().await;
    let root_id = env.root_id();
    let path = "/v1/tenants/acme/blobs/openai";
    let first = version(root_id, openai(), 1, Some(blob_text(root_id, 1)), &V1_ADMINS);
    assert_eq!(env.call("PUT", path, Auth::Key(V1_ADMINS[0]), Some(&first)).await.0, 204);

    let enclave = |method: &str, path: &str| {
        Auth::Header(signed_header(env.telemetry_signer(), root_id, method, path, b"", env.now()))
    };
    assert_eq!(env.get_as(path, enclave("GET", path)).await.0, 200);
    let list = "/v1/tenants/acme/blobs";
    assert_eq!(env.get_as(list, enclave("GET", list)).await.0, 403, "enclaves look up one name");
    let second = version(root_id, openai(), 2, Some(blob_text(root_id, 2)), &V1_ADMINS);
    let body = serde_json::to_vec(&second).unwrap();
    let as_enclave = signed_header(env.telemetry_signer(), root_id, "PUT", path, &body, env.now());
    assert_eq!(env.send("PUT", path, Auth::Header(as_enclave), &[], body).await.0, 403, "enclaves never publish");
    assert_eq!(env.get_as(path, Auth::None).await.0, 401);
    assert_eq!(env.get_as(path, Auth::Key(STRANGER)).await.0, 401);

    let read = control_token(&console_key(), "acme", root_id, "read", env.now());
    let submit = control_token(&console_key(), "acme", root_id, "submit", env.now());
    assert_eq!(env.get_as(list, Auth::Header(read.clone())).await.0, 200);
    let (status, _) = env.call("PUT", path, Auth::Header(read.clone()), Some(&second)).await;
    assert_eq!(status, 403, "read members don't publish");
    let (status, _) = env.call("PUT", path, Auth::Header(submit.clone()), Some(&second)).await;
    assert_eq!(status, 204);
}

#[tokio::test]
async fn only_the_newest_versions_are_kept() {
    let env = Env::new().await;
    env.ready().await;
    let root_id = env.root_id();
    let path = "/v1/tenants/acme/blobs/openai";
    let total = NAMED_BLOB_VERSIONS_KEPT as u64 + 3;
    for v in 1..=total {
        let next = version(root_id, openai(), v, Some(blob_text(root_id, v as u8)), &V1_ADMINS);
        assert_eq!(env.call("PUT", path, Auth::Key(V1_ADMINS[0]), Some(&next)).await.0, 204);
    }
    let versions: Vec<NamedBlobVersion> = env.get_json("/v1/tenants/acme/blobs/openai/versions").await;
    let numbers: Vec<u64> = versions.iter().map(|v| v.entry.body.version).collect();
    assert_eq!(numbers, (4..=total).rev().collect::<Vec<_>>());
}

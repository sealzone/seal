//! Named secrets: what a lookup returns, to whom, and from which version.

use super::*;
use seal_proto::api::ResolveRequest;
use seal_proto::named::{BlobRef, NamedSecret, NamedSecretVersion, NAMED_SECRET_LABEL};
use seal_proto::telemetry::Operation;
use seal_proto::SecretName;

fn openai() -> SecretName {
    SecretName::new("openai").unwrap()
}

impl Harness {
    /// Stores `version` of `name` as the control plane would serve it, pointing at `blob` (none:
    /// a deletion), signed by `signers`.
    fn publish_named(&self, name: &SecretName, version: u64, blob: Option<&str>, signers: &[u8]) {
        let body = NamedSecret {
            tenant: acme(),
            root_id: self.world.root_id,
            name: name.clone(),
            version,
            blob: blob.map(|b| BlobRef::of(b).unwrap()),
            published_at: wall(),
        };
        let stored =
            NamedSecretVersion { entry: signed(NAMED_SECRET_LABEL, body, signers), blob: blob.map(Into::into) };
        self.stores.named.lock().unwrap().insert(name.to_string(), stored);
    }

    async fn resolve(&self, consumer: u8, name: &str) -> Result<(String, u64), ServiceError> {
        let placeholder = ProofPurpose::Resolve { request_digest: [0; 32] };
        let mut request = ResolveRequest {
            name: SecretName::new(name).unwrap(),
            context: self.context(placeholder).await,
            proof: IdentityProof::AppKey { key_id: key(consumer).key_id(), signature: vec![] },
        };
        request.context.purpose = request.expected_purpose();
        request.proof = proof(consumer, &request.context);
        self.service.resolve(request).await.map(|r| (r.blob, r.version))
    }

    /// Makes every named secret held here due for a fetch.
    fn age_named(&self) {
        for (at, _) in crate::lock(&self.service.runtime.named).values_mut() {
            *at = 0;
        }
    }
}

#[tokio::test]
async fn granted_apps_get_the_blob_a_name_points_at() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let blob = h.seal().await.unwrap().blob;
    h.publish_named(&openai(), 1, Some(&blob), &[ADMIN]);

    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap(), (blob.clone(), 1));
    let session = h.start(CONSUMER, &blob, None).await.unwrap();
    assert_eq!(session.info.app, checkout());

    assert_eq!(h.resolve(STRANGER, "openai").await.unwrap_err().code, ErrorCode::NotAllowed);
    assert_eq!(h.resolve(CONSUMER, "stripe").await.unwrap_err().code, ErrorCode::NotAllowed);
    let refusals = h
        .events()
        .into_iter()
        .filter(|e| matches!(e, TelemetryEvent::Refused { operation: Operation::Resolve, .. }))
        .count();
    assert_eq!(refusals, 2);
}

#[tokio::test]
async fn versions_the_root_did_not_sign_or_that_swap_the_blob_are_refused() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let blob = h.seal().await.unwrap().blob;
    let other = h.seal().await.unwrap().blob;

    h.publish_named(&openai(), 1, Some(&blob), &[STRANGER]);
    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap_err().code, ErrorCode::NotAllowed, "not an admin");

    h.publish_named(&openai(), 1, Some(&blob), &[ADMIN]);
    h.stores.named.lock().unwrap().get_mut("openai").unwrap().blob = Some(other);
    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap_err().code, ErrorCode::NotAllowed, "another blob");

    let stripe = SecretName::new("stripe").unwrap();
    h.publish_named(&stripe, 1, Some(&blob), &[ADMIN]);
    let served_as_openai = h.stores.named.lock().unwrap()["stripe"].clone();
    h.stores.named.lock().unwrap().insert("openai".into(), served_as_openai);
    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap_err().code, ErrorCode::NotAllowed, "another name");
}

#[tokio::test]
async fn new_versions_arrive_once_fetched_and_versions_never_go_back() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let first = h.seal().await.unwrap().blob;
    let second = h.seal().await.unwrap().blob;
    h.publish_named(&openai(), 1, Some(&first), &[ADMIN]);
    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap().1, 1);

    h.publish_named(&openai(), 2, Some(&second), &[ADMIN]);
    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap().1, 1, "held until due");
    h.age_named();
    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap(), (second.clone(), 2));

    h.publish_named(&openai(), 1, Some(&first), &[ADMIN]);
    h.age_named();
    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap().1, 2, "an older version served is ignored");

    h.stores.named_down.store(true, std::sync::atomic::Ordering::SeqCst);
    h.age_named();
    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap().1, 2, "held while the control plane is down");
    h.stores.named_down.store(false, std::sync::atomic::Ordering::SeqCst);

    h.publish_named(&openai(), 3, None, &[ADMIN]);
    h.age_named();
    assert_eq!(h.resolve(CONSUMER, "openai").await.unwrap_err().code, ErrorCode::NotAllowed, "deleted");
}

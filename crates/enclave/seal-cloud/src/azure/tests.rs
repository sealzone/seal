use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// A fake IMDS answering each connection with the next `(status, body)`, recording each request head.
struct FakeImds {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl FakeImds {
    async fn start(answers: Vec<(u16, String)>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        tokio::spawn(async move {
            for (status, body) in answers {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap();
                    head.extend_from_slice(&buf[..n]);
                }
                seen.lock().unwrap().push(String::from_utf8(head).unwrap());
                let length = body.len();
                let answer =
                    format!("HTTP/1.1 {status} X\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n{body}");
                s.write_all(answer.as_bytes()).await.unwrap();
            }
        });
        Self { port, requests }
    }

    fn identity(&self) -> ManagedIdentity {
        ManagedIdentity::at(Arc::new(seal_net::TcpDialer), "127.0.0.1", self.port)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

/// An unsigned token with these claims, shaped like the managed-identity tokens ACI's IMDS issues (header
/// `typ`, `alg` RS256, `x5t`, `kid`; claims `aud`, `iss` `https://sts.windows.net/<tid>/`, `iat`, `nbf`, `exp`,
/// `oid`, `sub`, `tid`, `idtyp` `app`, `xms_mirid` naming the identity's resource).
fn jwt(tid: &str, oid: &str, aud: &str) -> String {
    let b64 = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let header = serde_json::json!({ "typ": "JWT", "alg": "RS256", "x5t": "k1", "kid": "k1" });
    let claims = serde_json::json!({
        "aud": aud,
        "iss": format!("https://sts.windows.net/{tid}/"),
        "iat": 1_793_078_456u64,
        "nbf": 1_793_078_456u64,
        "exp": 1_793_165_156u64,
        "idtyp": "app",
        "oid": oid,
        "sub": oid,
        "tid": tid,
        "xms_mirid": "/subscriptions/s/resourcegroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi",
    });
    format!("{}.{}.c2ln", b64(header), b64(claims))
}

/// IMDS's answer around `token`.
fn answer(token: &str, resource: &str) -> String {
    serde_json::json!({
        "access_token": token,
        "refresh_token": "",
        "expires_in": "86398",
        "expires_on": "1793165155",
        "not_before": "1793078696",
        "resource": resource,
        "token_type": "Bearer",
    })
    .to_string()
}

fn azure(tid: &str, oid: &str, audience: &str) -> IdentityMatcher {
    IdentityMatcher::Azure { entra_tenant: tid.into(), object_id: oid.into(), audience: audience.into(), hosted: None }
}

fn jwt_of(proof: DeploymentProof) -> String {
    match proof {
        DeploymentProof::Proof(IdentityProof::Oidc { provider: OidcProvider::Azure, jwt }) => jwt.expose().to_owned(),
        _ => panic!("not an Azure OIDC proof"),
    }
}

#[tokio::test]
async fn token_request_names_the_audience_and_sends_metadata() {
    let token = jwt("t1", "o1", "api://seal-acme");
    let imds = FakeImds::start(vec![(200, answer(&token, "api://seal-acme"))]).await;
    assert_eq!(imds.identity().token("api://seal-acme").await.unwrap().expose(), token);
    let request = imds.requests().remove(0).to_ascii_lowercase();
    assert!(
        request.starts_with(
            "get /metadata/identity/oauth2/token?api-version=2018-02-01&resource=api%3a%2f%2fseal-acme http/1.1\r\n"
        ),
        "{request}"
    );
    assert!(request.contains("\r\nmetadata: true\r\n"), "{request}");
    assert!(!request.contains("client_id"), "{request}");
}

#[tokio::test]
async fn token_retries_while_the_identity_is_attached() {
    let token = jwt("t1", "o1", "aud");
    let imds = FakeImds::start(vec![(404, "{}".into()), (200, answer(&token, "aud"))]).await;
    assert_eq!(imds.identity().token("aud").await.unwrap().expose(), token);
    assert_eq!(imds.requests().len(), 2);
}

#[tokio::test]
async fn token_refusals() {
    let error = r#"{"error":"invalid_resource","error_description":"AADSTS500011: resource principal not found"}"#;
    let imds = FakeImds::start(vec![(400, error.into())]).await;
    let e = imds.identity().token("api://unregistered").await.unwrap_err();
    assert!(matches!(&e, CloudError::Deployment(m) if m.contains("HTTP 400")), "{e}");
    assert_eq!(imds.requests().len(), 1, "a client error is not retried");

    let imds = FakeImds::start(vec![(200, r#"{"token_type":"Bearer"}"#.into())]).await;
    assert!(matches!(imds.identity().token("aud").await, Err(CloudError::Deployment(m)) if m.contains("access_token")));

    let closed = ManagedIdentity::at(Arc::new(seal_net::TcpDialer), "127.0.0.1", 1);
    let start = tokio::time::Instant::now();
    tokio::time::pause();
    assert!(matches!(closed.token("aud").await, Err(CloudError::Deployment(_))));
    assert!(start.elapsed() >= Duration::from_secs(15), "four waits of 1, 2, 4 and 8 s");
}

#[tokio::test]
async fn proof_uses_the_tenants_azure_audience() {
    let token = jwt("t1", "o1", "api://seal-acme");
    let imds = FakeImds::start(vec![(200, answer(&token, "api://seal-acme"))]).await;
    let deployments = BTreeSet::from([
        azure("t1", "o1", "api://seal-acme"),
        IdentityMatcher::AwsRole { role_arn: "arn:aws:iam::1:role/r".into(), role_id: "AROA1".into() },
    ]);
    assert_eq!(jwt_of(imds.identity().proof(&deployments).await.unwrap()), token);
    assert!(imds.requests()[0].contains("resource=api%3A%2F%2Fseal-acme "));
}

#[tokio::test]
async fn proof_picks_the_audience_whose_entry_names_this_identity() {
    let (other, mine) = (jwt("t1", "o1", "api://a"), jwt("t1", "o1", "api://b"));
    let imds = FakeImds::start(vec![(200, answer(&other, "api://a")), (200, answer(&mine, "api://b"))]).await;
    let deployments = BTreeSet::from([azure("t1", "o2", "api://a"), azure("t1", "o1", "api://b")]);
    assert_eq!(jwt_of(imds.identity().proof(&deployments).await.unwrap()), mine);

    // No entry names it: the first audience's token, for the verifier to refuse.
    let imds = FakeImds::start(vec![(200, answer(&other, "api://a")), (200, answer(&mine, "api://b"))]).await;
    let deployments = BTreeSet::from([azure("t1", "o2", "api://a"), azure("t1", "o3", "api://b")]);
    assert_eq!(jwt_of(imds.identity().proof(&deployments).await.unwrap()), other);
}

#[tokio::test]
async fn proof_needs_an_azure_deployment() {
    let identity = ManagedIdentity::at(Arc::new(seal_net::TcpDialer), "127.0.0.1", 1);
    let role = IdentityMatcher::AwsRole { role_arn: "arn:aws:iam::1:role/r".into(), role_id: "AROA1".into() };
    let aws = BTreeSet::from([role]);
    for deployments in [BTreeSet::new(), aws] {
        assert!(matches!(identity.proof(&deployments).await, Err(CloudError::Deployment(m)) if m.contains("no Azure")));
    }
}

/// Runs inside an ACI confidential container group with one managed identity (`--ignored live_capture
/// --nocapture`): the whole Azure cloud from `Cloud::detect`, and the header and claims (never the signature)
/// of IMDS tokens.
#[tokio::test]
#[ignore = "needs an ACI confidential container group"]
async fn live_capture() {
    let cloud = crate::Cloud::detect().unwrap();
    let crate::Cloud::AzureSnpAci(aci) = &cloud else { panic!("not Azure") };
    println!("CAPTURE pin {}", cloud.tenant_pin());
    println!("CAPTURE measurement {}", cloud.attestor().measurement());
    println!("CAPTURE clock {:?}", cloud.clock().now().await);
    for audience in ["https://management.azure.com/", "api://seal-dev-azure-unregistered"] {
        match aci.identity.token(audience).await {
            Ok(token) => {
                let parts: Vec<&str> = token.expose().split('.').collect();
                let decode = |part: &str| {
                    String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
                };
                println!("CAPTURE token {audience} header {}", decode(parts[0]));
                println!("CAPTURE token {audience} claims {}", decode(parts[1]));
            }
            Err(e) => println!("CAPTURE token {audience} error {e}"),
        }
    }
}

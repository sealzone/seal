use seal_authz::DeploymentProof;
use seal_proto::identity::{IdentityProof, OidcProvider, WorkloadIdentity};
use seal_proto::{Bearer, KeyId, Measurement, PlatformId, TenantPin, TrustedTime};
use seal_tee::sim::{SimAttestor, SystemClock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::sim::Sim;
use crate::{Cloud, CloudError};

fn pin() -> TenantPin {
    format!("acme@{}", "ab".repeat(32)).parse().unwrap()
}

fn identity() -> WorkloadIdentity {
    WorkloadIdentity::Azure { entra_tenant: "t".into(), object_id: "o".into() }
}

fn cloud(offset: i64, deployment: DeploymentProof) -> Cloud {
    Cloud::Sim(Sim::new(SimAttestor::new(Measurement([3; 48])), SystemClock::new(offset), pin(), deployment))
}

#[tokio::test]
async fn sim_cloud_attests_and_tells_time() {
    let cloud = cloud(600, DeploymentProof::Attested(identity()));
    let attestor = cloud.attestor();
    assert_eq!(attestor.platform(), PlatformId::Sim);
    assert_eq!(attestor.measurement(), Measurement([3; 48]));
    let evidence = attestor.attest([4; 32]).await.unwrap();
    let verified = seal_attest::verify(&evidence, &TrustedTime::exact(0)).unwrap();
    assert_eq!((verified.measurement, verified.report_data), (Measurement([3; 48]), [4; 32]));

    let system = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let t = cloud.clock().now().await.unwrap();
    assert_eq!(t.radius, 0);
    assert!(t.now.abs_diff(system + 600) <= 1);

    assert_eq!(cloud.tenant_pin(), &pin());
    match cloud.deployment(&Default::default()).await.unwrap() {
        DeploymentProof::Attested(id) => assert_eq!(id, identity()),
        DeploymentProof::Proof(_) => panic!("not the given proof"),
    }
}

#[tokio::test]
async fn deployment_proofs_are_returned_intact() {
    let proofs = [
        IdentityProof::Oidc { provider: OidcProvider::Azure, jwt: Bearer::new("eyJ.a.b".into()) },
        IdentityProof::AwsSigV4 {
            method: "POST".into(),
            url: "https://sts.amazonaws.com/".into(),
            headers: vec![("authorization".into(), Bearer::new("AWS4 x".into()))],
            body: "Action=GetCallerIdentity".into(),
        },
        IdentityProof::AppKey { key_id: KeyId([1; 32]), signature: vec![2; 64] },
    ];
    for proof in proofs {
        let expected = serde_json::to_string(&proof).unwrap();
        let cloud = cloud(0, DeploymentProof::Proof(proof));
        for _ in 0..2 {
            match cloud.deployment(&Default::default()).await.unwrap() {
                DeploymentProof::Proof(p) => assert_eq!(serde_json::to_string(&p).unwrap(), expected),
                DeploymentProof::Attested(_) => panic!("not the given proof"),
            }
        }
    }
}

#[tokio::test]
async fn sim_dialer_is_tcp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"hi").await.unwrap();
    });
    let mut stream = cloud(0, DeploymentProof::Attested(identity())).dialer().dial("127.0.0.1", port).await.unwrap();
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");
    server.await.unwrap();
}

#[test]
fn sim_from_environment() {
    let measurement = || SimAttestor::new(Measurement([5; 48]));
    let pin_text = pin().to_string();
    let deployment = serde_json::to_string(&identity()).unwrap();
    let vars = |tenant: Option<&str>, dep: Option<&str>, offset: Option<&str>| {
        let (tenant, dep, offset) = (tenant.map(String::from), dep.map(String::from), offset.map(String::from));
        move |name: &str| match name {
            "SEAL_TENANT" => tenant.clone(),
            "SEAL_SIM_DEPLOYMENT" => dep.clone(),
            "SEAL_SIM_CLOCK_OFFSET" => offset.clone(),
            _ => None,
        }
    };
    let sim = Sim::from_vars(measurement(), vars(Some(&pin_text), Some(&deployment), Some("-60"))).unwrap();
    assert_eq!(sim.pin, pin());
    assert!(matches!(sim.deployment(), DeploymentProof::Attested(id) if id == identity()));
    assert!(Sim::from_vars(measurement(), vars(Some(&pin_text), Some(&deployment), None)).is_ok());

    assert!(matches!(Sim::from_vars(measurement(), vars(None, Some(&deployment), None)), Err(CloudError::Pin(_))));
    assert!(matches!(
        Sim::from_vars(measurement(), vars(Some("not a pin"), Some(&deployment), None)),
        Err(CloudError::Pin(_))
    ));
    assert!(matches!(Sim::from_vars(measurement(), vars(Some(&pin_text), None, None)), Err(CloudError::Deployment(_))));
    assert!(matches!(
        Sim::from_vars(measurement(), vars(Some(&pin_text), Some("{}"), None)),
        Err(CloudError::Deployment(_))
    ));
    assert!(Sim::from_vars(measurement(), vars(Some(&pin_text), Some(&deployment), Some("soon"))).is_err());
}

#[test]
fn detect_without_a_tee_or_sim_selection() {
    if std::env::var_os("SEAL_SIM").is_some() {
        return;
    }
    assert!(matches!(Cloud::detect(), Err(CloudError::Tee(seal_tee::TeeError::NotInTee))));
}

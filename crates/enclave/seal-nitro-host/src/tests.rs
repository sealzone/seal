//! The host against the enclave's own side of the protocol (`seal_cloud::nitro`), over this
//! machine's vsock loopback (`vsock_loopback`: both ends are CID 1). Skipped where there is
//! none. The request parsing and policy are tested without sockets.

use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use seal_authz::DeploymentProof;
use seal_cloud::nitro::{Nitro, ParentDialer, ParentLink};
use seal_net::vsock::{self, VsockListener, CID_ANY, CID_LOCAL, PORT_ANY};
use seal_net::{BoxStream, Dialer, NetError};
use seal_proto::identity::{IdentityMatcher, IdentityProof};
use seal_proto::nitro::{ParentMessage, EGRESS_PORT, PARENT_PORT};
use seal_proto::{Measurement, TenantPin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::egress::{self, forbidden, parse_request, Policy, Refusal};
use crate::parent::{self, CredentialSource, Messages};
use crate::sigv4::{Credentials, Sts};
use crate::{imds, ingress};

fn pin() -> TenantPin {
    format!("acme@{}", "ab".repeat(32)).parse().unwrap()
}

/// A vsock listener on loopback, or `None` (and the test skips) without vsock.
fn listener() -> Option<VsockListener> {
    match VsockListener::bind(CID_ANY, PORT_ANY) {
        Ok(listener) => Some(listener),
        Err(e) if vsock::unsupported(&e) => {
            eprintln!("no vsock here ({e}); skipped");
            None
        }
        Err(e) => panic!("{e}"),
    }
}

/// The enclave's link to its parent, carried over loopback to the test's ports.
struct Loopback {
    parent_port: u32,
    egress_port: u32,
}

#[async_trait]
impl ParentLink for Loopback {
    async fn open(&self, port: u32) -> io::Result<BoxStream> {
        let port = match port {
            PARENT_PORT => self.parent_port,
            EGRESS_PORT => self.egress_port,
            _ => return Err(io::ErrorKind::ConnectionRefused.into()),
        };
        Ok(Box::new(vsock::connect(CID_LOCAL, port, Duration::from_secs(5)).await?))
    }
}

/// A TCP echo server on loopback.
async fn echo() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

// ---- egress ----

#[test]
fn connect_requests() {
    let ok = |head: &str| parse_request(head.as_bytes()).unwrap();
    assert_eq!(ok("CONNECT db.internal:5432 HTTP/1.1\r\nHost: db.internal:5432\r\n\r\n"), ("db.internal".into(), 5432));
    assert_eq!(ok("CONNECT [2001:db8::1]:443 HTTP/1.0\r\n\r\n"), ("2001:db8::1".into(), 443));
    assert_eq!(ok("CONNECT 10.0.0.7:6379 HTTP/1.1\r\n\r\n"), ("10.0.0.7".into(), 6379));
    let status = |head: &str| parse_request(head.as_bytes()).unwrap_err().status;
    assert_eq!(status("GET http://x/ HTTP/1.1\r\n\r\n"), 405);
    for bad in [
        "CONNECT x HTTP/1.1\r\n\r\n",
        "CONNECT x:0 HTTP/1.1\r\n\r\n",
        "CONNECT x:65536 HTTP/1.1\r\n\r\n",
        "CONNECT x:+1 HTTP/1.1\r\n\r\n",
        "CONNECT :443 HTTP/1.1\r\n\r\n",
        "CONNECT a@b:443 HTTP/1.1\r\n\r\n",
        "CONNECT [nothost]:443 HTTP/1.1\r\n\r\n",
        "CONNECT x:443 HTTP/2\r\n\r\n",
        "CONNECT x:443  HTTP/1.1\r\n\r\n",
        "CONNECT x:443\r\n\r\n",
    ] {
        assert_eq!(status(bad), 400, "{bad:?}");
    }
    assert_eq!(parse_request(b"\xff\xfe").unwrap_err().status, 400);
}

#[test]
fn the_instances_own_addresses_are_refused() {
    for ip in [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "127.9.9.9",
        "169.254.169.254",
        "169.254.169.123",
        "169.254.169.253",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fd00:ec2::254",
        "fd00:ec2::23",
        "ff02::1",
        "::ffff:169.254.169.254",
        "::ffff:127.0.0.1",
    ] {
        assert!(forbidden(ip.parse().unwrap()).is_some(), "{ip}");
    }
    // What a NAT gateway reaches: public and private networks.
    for ip in
        ["10.0.0.7", "172.16.0.1", "192.168.1.1", "100.64.0.1", "52.94.1.1", "2600:1f18::1", "fd00:1::1", "fc00::1"]
    {
        assert!(forbidden(ip.parse().unwrap()).is_none(), "{ip}");
    }
}

#[tokio::test]
async fn egress_over_a_pipe() {
    let upstream = echo().await;
    // Relayed: the 200, then the upstream's bytes.
    let (mut enclave, parent) = tokio::io::duplex(4096);
    let policy = Policy { allow_loopback: true };
    let served = tokio::spawn(async move { egress::handle(parent, &policy).await });
    enclave
        .write_all(format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\nhello").as_bytes())
        .await
        .unwrap();
    let mut answer = vec![0u8; 39 + 5];
    enclave.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, b"HTTP/1.1 200 Connection established\r\n\r\nhello");
    drop(enclave);
    assert!(served.await.unwrap().is_ok());

    // Refused: loopback under the default policy, IMDS, nothing to read.
    for (request, status) in [
        (format!("CONNECT {upstream} HTTP/1.1\r\n\r\n"), 403),
        ("CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n".to_string(), 403),
        ("CONNECT [fd00:ec2::254]:80 HTTP/1.1\r\n\r\n".to_string(), 403),
        ("CONNECT name.invalid:443 HTTP/1.1\r\n\r\n".to_string(), 502),
        ("CONNECT x:443 HTTP/1.1\r\n".to_string(), 400),
    ] {
        let (mut enclave, parent) = tokio::io::duplex(4096);
        let served = tokio::spawn(async move { egress::handle(parent, &Policy::default()).await });
        enclave.write_all(request.as_bytes()).await.unwrap();
        if request.ends_with("\r\n\r\n") {
            let mut answer = Vec::new();
            enclave.read_to_end(&mut answer).await.unwrap();
            let expected = format!("HTTP/1.1 {status} ");
            assert!(answer.starts_with(expected.as_bytes()), "{request:?}: {}", String::from_utf8_lossy(&answer));
        } else {
            enclave.shutdown().await.unwrap();
        }
        let Err(Refusal { status: got, .. }) = served.await.unwrap() else { panic!("{request:?} served") };
        assert_eq!(got, status, "{request:?}");
    }
}

#[tokio::test]
async fn the_enclaves_dialer_through_the_hosts_egress() {
    let Some(egress_listener) = listener() else { return };
    let egress_port = egress_listener.port();
    tokio::spawn(egress::serve(egress_listener, CID_LOCAL, 16, Policy { allow_loopback: true }));
    let upstream = echo().await;
    let dialer = ParentDialer::new(Arc::new(Loopback { parent_port: 0, egress_port }));
    for host in ["127.0.0.1", "localhost"] {
        let mut stream = dialer.dial(host, upstream.port()).await.unwrap();
        stream.write_all(b"through the parent").await.unwrap();
        let mut back = [0u8; 18];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"through the parent", "{host}");
    }
    // What the parent refuses reaches the enclave as a failed dial.
    let Some(strict) = listener() else { return };
    let strict_port = strict.port();
    tokio::spawn(egress::serve(strict, CID_LOCAL, 16, Policy::default()));
    let dialer = ParentDialer::new(Arc::new(Loopback { parent_port: 0, egress_port: strict_port }));
    for (host, status) in [("127.0.0.1", "403"), ("169.254.169.254", "403"), ("name.invalid", "502")] {
        match dialer.dial(host, upstream.port()).await {
            Err(NetError::Connect { reason, .. }) => assert!(reason.contains(status), "{host}: {reason}"),
            other => panic!("{host}: {:?}", other.map(|_| ())),
        }
    }
}

#[tokio::test]
async fn egress_serves_only_the_enclaves_cid_and_caps_tunnels() {
    let Some(other) = listener() else { return };
    let port = other.port();
    // Loopback connections come from CID 1, not the enclave's 16.
    tokio::spawn(egress::serve(other, 16, 16, Policy { allow_loopback: true }));
    let dialer = ParentDialer::new(Arc::new(Loopback { parent_port: 0, egress_port: port }));
    assert!(dialer.dial("127.0.0.1", 1).await.is_err());

    let Some(capped) = listener() else { return };
    let port = capped.port();
    tokio::spawn(egress::serve(capped, CID_LOCAL, 1, Policy { allow_loopback: true }));
    let upstream = echo().await;
    let dialer = ParentDialer::new(Arc::new(Loopback { parent_port: 0, egress_port: port }));
    let held = dialer.dial("127.0.0.1", upstream.port()).await.unwrap();
    match dialer.dial("127.0.0.1", upstream.port()).await {
        Err(NetError::Connect { reason, .. }) => assert!(reason.contains("503"), "{reason}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
    drop(held);
}

// ---- the parent's messages ----

struct Static;

#[async_trait]
impl CredentialSource for Static {
    async fn credentials(&self) -> anyhow::Result<Credentials> {
        Ok(Credentials {
            access_key_id: "ASIAEXAMPLE".into(),
            secret_access_key: Zeroizing::new("secret".into()),
            session_token: Some(Zeroizing::new("token/+=".into())),
        })
    }
}

fn messages(credentials: Arc<dyn CredentialSource>) -> Arc<Messages> {
    Arc::new(Messages { tenant: pin(), sts: Sts::global(), credentials })
}

#[tokio::test]
async fn messages_carry_the_pin_and_a_fresh_proof() {
    let a: ParentMessage = serde_json::from_slice(&messages(Arc::new(Static)).message().await.unwrap()).unwrap();
    assert_eq!(a.tenant, pin());
    let IdentityProof::AwsSigV4 { url, .. } = a.deployment else { panic!("not SigV4") };
    assert!(url.starts_with("https://sts.amazonaws.com/?Action=GetCallerIdentity&"), "{url}");
    // From IMDS.
    let (addr, _) = imds::tests::fake_imds("Success").await;
    let from_imds = messages(Arc::new(imds::Imds::at(addr))).message().await.unwrap();
    assert!(String::from_utf8(from_imds).unwrap().contains("X-Amz-Credential=ASIAEXAMPLE%2F"));
    // No credentials, no message.
    let (addr, _) = imds::tests::fake_imds("Expired").await;
    assert!(messages(Arc::new(imds::Imds::at(addr))).message().await.is_err());
}

#[tokio::test]
async fn the_enclave_boots_on_the_hosts_messages() {
    use seal_tee::sim::{SimAttestor, SystemClock};
    use seal_tee::{Attestor, Clock};

    let Some(message_listener) = listener() else { return };
    let parent_port = message_listener.port();
    tokio::spawn(parent::serve(message_listener, CID_LOCAL, messages(Arc::new(Static))));
    let link = Arc::new(Loopback { parent_port, egress_port: 0 });
    let attestor = Attestor::Sim(SimAttestor::new(Measurement([3; 48])));
    let nitro = Nitro::with(attestor, Clock::System(SystemClock::new(0)), link, Duration::from_secs(5)).await.unwrap();
    let cloud = seal_cloud::Cloud::AwsNitro(nitro);
    assert_eq!(cloud.tenant_pin(), &pin());
    let role: BTreeSet<IdentityMatcher> =
        [IdentityMatcher::AwsRole { role_arn: "arn:aws:iam::123456789012:role/seal".into(), role_id: "AROA1".into() }]
            .into();
    let DeploymentProof::Proof(IdentityProof::AwsSigV4 { method, url, headers, body }) =
        cloud.deployment(&role).await.unwrap()
    else {
        panic!("not the parent's presigned request")
    };
    assert_eq!((method.as_str(), body.as_str()), ("GET", ""));
    assert!(url.contains("X-Amz-SignedHeaders=host&"), "{url}");
    assert_eq!(headers.len(), 1);

    // A host serving another CID's enclave sends this one nothing: no pin, no boot.
    let Some(other) = listener() else { return };
    let parent_port = other.port();
    tokio::spawn(parent::serve(other, 16, messages(Arc::new(Static))));
    let attestor = Attestor::Sim(SimAttestor::new(Measurement([3; 48])));
    let link = Arc::new(Loopback { parent_port, egress_port: 0 });
    assert!(Nitro::with(attestor, Clock::System(SystemClock::new(0)), link, Duration::from_secs(1)).await.is_err());
}

// ---- ingress ----

#[tokio::test]
async fn ingress_names_the_client_to_the_enclave() {
    let Some(enclave) = listener() else { return };
    let enclave_port = enclave.port();
    let inbound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = inbound.local_addr().unwrap();
    tokio::spawn(ingress::serve(inbound, CID_LOCAL, enclave_port, 4));

    let mut client = tokio::net::TcpStream::connect(listen).await.unwrap();
    let client_addr = client.local_addr().unwrap();
    client.write_all(b"\x16\x03\x01hello").await.unwrap();

    let (mut accepted, cid) = enclave.accept().await.unwrap();
    assert_eq!(cid, CID_LOCAL);
    let header = ingress::proxy_v2(client_addr, listen);
    let mut got = vec![0u8; header.len() + 8];
    accepted.read_exact(&mut got).await.unwrap();
    assert_eq!(&got[..header.len()], header, "a PROXY v2 header naming the client first");
    assert_eq!(&got[header.len()..], b"\x16\x03\x01hello", "then the client's bytes, untouched");
    accepted.write_all(b"from the enclave").await.unwrap();
    drop(accepted);
    let mut back = Vec::new();
    client.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"from the enclave");
}

#[tokio::test]
async fn ingress_closes_clients_when_the_enclave_is_not_there() {
    let Some(probe) = listener() else { return };
    let gone = probe.port();
    drop(probe);
    let inbound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = inbound.local_addr().unwrap();
    tokio::spawn(ingress::serve(inbound, CID_LOCAL, gone, 4));
    let mut client = tokio::net::TcpStream::connect(listen).await.unwrap();
    let mut buf = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut buf)).await;
    assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "{closed:?}");
}

//! The enclave's side of the parent protocol over in-memory pipes (`FakeParent`): the
//! `CONNECT` exchange, the parent's messages, the pin and the deployment proof. The parent's
//! side is `seal-nitro-host`, whose tests run both ends together.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use seal_net::{BoxStream, Dialer, NetError};
use seal_proto::identity::IdentityProof;
use seal_proto::nitro::{ParentMessage, EGRESS_PORT, MAX_PARENT_MESSAGE, PARENT_PORT};
use seal_proto::{Bearer, TenantPin};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;

fn pin(name: &str) -> TenantPin {
    format!("{name}@{}", "ab".repeat(32)).parse().unwrap()
}

fn presigned(signature: &str) -> IdentityProof {
    IdentityProof::AwsSigV4 {
        method: "GET".into(),
        url: format!(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Signature={signature}"
        ),
        headers: vec![("host".into(), Bearer::new("sts.amazonaws.com".into()))],
        body: String::new(),
    }
}

fn message(tenant: &str, deployment: IdentityProof) -> Vec<u8> {
    serde_json::to_vec(&ParentMessage { tenant: pin(tenant), deployment }).unwrap()
}

type Egress = Box<dyn Fn(DuplexStream) + Send + Sync>;

/// A parent over in-memory pipes: each `PARENT_PORT` connection gets the next queued message
/// (none left: refused), each `EGRESS_PORT` connection goes to `egress`.
struct FakeParent {
    messages: Mutex<VecDeque<Vec<u8>>>,
    egress: Egress,
    opened: Mutex<Vec<u32>>,
}

impl FakeParent {
    fn new(messages: Vec<Vec<u8>>, egress: Egress) -> Arc<Self> {
        Arc::new(Self { messages: Mutex::new(messages.into()), egress, opened: Mutex::new(Vec::new()) })
    }

    fn with_messages(messages: Vec<Vec<u8>>) -> Arc<Self> {
        Self::new(messages, Box::new(|_| panic!("no egress expected")))
    }

    fn opened(&self) -> Vec<u32> {
        self.opened.lock().unwrap().clone()
    }
}

#[async_trait]
impl ParentLink for FakeParent {
    async fn open(&self, port: u32) -> io::Result<BoxStream> {
        self.opened.lock().unwrap().push(port);
        let (ours, theirs) = tokio::io::duplex(256 * 1024);
        match port {
            PARENT_PORT => {
                let message = self.messages.lock().unwrap().pop_front().ok_or(io::ErrorKind::ConnectionRefused)?;
                tokio::spawn(async move {
                    let mut theirs = theirs;
                    let _ = theirs.write_all(&message).await;
                    let _ = theirs.shutdown().await;
                });
            }
            EGRESS_PORT => (self.egress)(theirs),
            _ => return Err(io::ErrorKind::ConnectionRefused.into()),
        }
        Ok(Box::new(ours))
    }
}

/// Reads one request head, as the parent's proxy does.
async fn read_head(stream: &mut DuplexStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

/// A proxy that checks the request, answers `answer`, then echoes.
fn proxy(expect: &'static str, answer: &'static [u8]) -> Egress {
    Box::new(move |mut stream| {
        tokio::spawn(async move {
            assert_eq!(read_head(&mut stream).await, expect);
            stream.write_all(answer).await.unwrap();
            let mut buf = [0u8; 64];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
    })
}

// ---- CONNECT ----

#[test]
fn connect_requests_name_only_hosts() {
    assert_eq!(
        connect_request("db.internal", 5432).unwrap(),
        "CONNECT db.internal:5432 HTTP/1.1\r\nHost: db.internal:5432\r\n\r\n"
    );
    assert_eq!(authority("10.0.0.7", 443).unwrap(), "10.0.0.7:443");
    assert_eq!(authority("sts.us-east-1.amazonaws.com", 443).unwrap(), "sts.us-east-1.amazonaws.com:443");
    assert_eq!(authority("::1", 443).unwrap(), "[::1]:443");
    assert_eq!(authority("[2001:db8::7]", 6379).unwrap(), "[2001:db8::7]:6379");
    assert_eq!(authority("my_host-1.example", 1).unwrap(), "my_host-1.example:1");
    for bad in ["", "a b", "a\r\nX-Evil: 1", "user@host", "host/path", "host:1", "[nothost]", "h\0", "é.example"] {
        assert!(authority(bad, 443).is_none(), "{bad:?}");
    }
    assert!(authority(&"a".repeat(254), 443).is_none());
    assert!(authority("example.com", 0).is_none());
}

async fn answer(bytes: &[u8]) -> (Result<(), String>, Vec<u8>) {
    let (mut ours, mut theirs) = tokio::io::duplex(8192);
    theirs.write_all(bytes).await.unwrap();
    drop(theirs);
    let result = read_connect_response(&mut ours).await;
    let mut rest = Vec::new();
    let _ = ours.read_to_end(&mut rest).await;
    (result, rest)
}

#[tokio::test]
async fn connect_responses() {
    // Exactly the head is read; what follows is the destination's.
    let (result, rest) = answer(b"HTTP/1.1 200 Connection established\r\nVia: x\r\n\r\n\x16\x03\x01").await;
    assert_eq!((result, rest), (Ok(()), b"\x16\x03\x01".to_vec()));
    assert_eq!(answer(b"HTTP/1.0 200 OK\r\n\r\n").await.0, Ok(()));
    for (bytes, needle) in [
        (&b"HTTP/1.1 403 Forbidden\r\n\r\n"[..], "answered 403"),
        (b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", "answered 502"),
        (b"SSH-2.0-OpenSSH\r\n\r\n", "garbage"),
        (b"HTTP/1.1 2x0 OK\r\n\r\n", "garbage"),
        (b"HTTP/1.1 200 OK\r\n", "closed"),
        (b"", "closed"),
    ] {
        let (result, _) = answer(bytes).await;
        assert!(result.as_ref().is_err_and(|e| e.contains(needle)), "{bytes:?}: {result:?}");
    }
    let mut long = b"HTTP/1.1 200 OK\r\n".to_vec();
    long.extend(std::iter::repeat_n(b'x', MAX_CONNECT_HEAD));
    assert!(answer(&long).await.0.is_err_and(|e| e.contains("too long")));
}

#[tokio::test]
async fn the_dialer_connects_through_the_parent() {
    let parent = FakeParent::new(
        vec![],
        proxy(
            "CONNECT guardian.example:443 HTTP/1.1\r\nHost: guardian.example:443\r\n\r\n",
            b"HTTP/1.1 200 Connection established\r\n\r\n",
        ),
    );
    let dialer = ParentDialer::new(parent.clone());
    let mut stream = dialer.dial("guardian.example", 443).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    assert_eq!(parent.opened(), [EGRESS_PORT]);
}

#[tokio::test]
async fn the_dialer_reports_refusals() {
    let parent = FakeParent::new(
        vec![],
        proxy("CONNECT [::1]:22 HTTP/1.1\r\nHost: [::1]:22\r\n\r\n", b"HTTP/1.1 403 Forbidden\r\n\r\n"),
    );
    match ParentDialer::new(parent).dial("[::1]", 22).await {
        Err(NetError::Connect { host, port, reason }) => {
            assert_eq!((host.as_str(), port), ("[::1]", 22));
            assert!(reason.contains("403"), "{reason}");
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
    // Not a host: refused before the parent hears of it.
    let parent = FakeParent::with_messages(vec![]);
    assert!(ParentDialer::new(parent.clone()).dial("evil.com\r\nX: 1", 443).await.is_err());
    assert!(parent.opened().is_empty());
    // No egress port at all.
    struct Nobody;
    #[async_trait]
    impl ParentLink for Nobody {
        async fn open(&self, _: u32) -> io::Result<BoxStream> {
            Err(io::ErrorKind::ConnectionRefused.into())
        }
    }
    assert!(ParentDialer::new(Arc::new(Nobody)).dial("example.com", 443).await.is_err());
}

#[tokio::test(start_paused = true)]
async fn the_dialer_gives_up_on_a_silent_parent() {
    let parent = FakeParent::new(
        vec![],
        Box::new(|stream| {
            // Holds the connection and never answers.
            tokio::spawn(async move {
                let _held = stream;
                std::future::pending::<()>().await;
            });
        }),
    );
    match ParentDialer::new(parent).dial("example.com", 443).await {
        Err(NetError::Connect { reason, .. }) => assert!(reason.contains("timed out"), "{reason}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

// ---- messages ----

#[tokio::test]
async fn messages_are_read_whole_and_bounded() {
    let parent = FakeParent::with_messages(vec![
        message("acme", presigned("a")),
        b"{\"tenant\":".to_vec(),
        vec![b' '; MAX_PARENT_MESSAGE + 1],
        Vec::new(),
    ]);
    assert_eq!(super::message(&*parent).await.unwrap().tenant, pin("acme"));
    assert!(super::message(&*parent).await.unwrap_err().contains("the parent's message"));
    assert!(super::message(&*parent).await.unwrap_err().contains("too long"));
    assert!(super::message(&*parent).await.unwrap_err().contains("the parent's message"));
    assert!(super::message(&*parent).await.unwrap_err().contains("connect to the parent"));
}

/// Refuses the first `refusals` connections, then serves `message`.
struct LateParent {
    refusals: Mutex<u32>,
    inner: Arc<FakeParent>,
}

#[async_trait]
impl ParentLink for LateParent {
    async fn open(&self, port: u32) -> io::Result<BoxStream> {
        {
            let mut refusals = self.refusals.lock().unwrap();
            if *refusals > 0 {
                *refusals -= 1;
                return Err(io::ErrorKind::ConnectionRefused.into());
            }
        }
        self.inner.open(port).await
    }
}

#[tokio::test(start_paused = true)]
async fn boot_waits_for_the_parent() {
    let late = LateParent {
        refusals: Mutex::new(10),
        inner: FakeParent::with_messages(vec![message("acme", presigned("a"))]),
    };
    let started = tokio::time::Instant::now();
    assert_eq!(first_message(&late, PARENT_WAIT).await.unwrap().tenant, pin("acme"));
    assert_eq!(started.elapsed(), Duration::from_secs(10));

    let never = LateParent { refusals: Mutex::new(u32::MAX), inner: FakeParent::with_messages(vec![]) };
    let started = tokio::time::Instant::now();
    match first_message(&never, PARENT_WAIT).await {
        Err(CloudError::Pin(e)) => assert!(e.contains("no message from the parent within 60 s"), "{e}"),
        other => panic!("{:?}", other.map(|m| m.tenant)),
    }
    assert!(started.elapsed() <= PARENT_WAIT);
}

// ---- the cloud ----

#[cfg(feature = "sim")]
mod cloud {
    use seal_authz::DeploymentProof;
    use seal_proto::identity::{IdentityMatcher, OidcProvider};
    use seal_proto::Measurement;
    use seal_tee::sim::{SimAttestor, SystemClock};

    use super::*;
    use crate::{Cloud, Listen};

    fn role() -> BTreeSet<IdentityMatcher> {
        [IdentityMatcher::AwsRole { role_arn: "arn:aws:iam::123456789012:role/seal".into(), role_id: "AROA1".into() }]
            .into()
    }

    async fn nitro(parent: Arc<FakeParent>) -> Result<Cloud, CloudError> {
        let attestor = Attestor::Sim(SimAttestor::new(Measurement([3; 48])));
        let clock = Clock::System(SystemClock::new(0));
        Ok(Cloud::AwsNitro(Nitro::with(attestor, clock, parent, Duration::from_secs(1)).await?))
    }

    #[tokio::test]
    async fn the_pin_is_the_first_message_and_each_proof_a_fresh_one() {
        let parent = FakeParent::with_messages(vec![
            message("acme", presigned("first")),
            message("acme", presigned("second")),
            message("acme", presigned("third")),
        ]);
        let cloud = nitro(parent.clone()).await.unwrap();
        assert_eq!(cloud.tenant_pin(), &pin("acme"));
        // Nothing asked while the tenant names no AWS role.
        assert!(matches!(
            cloud.deployment(&BTreeSet::new()).await,
            Err(CloudError::Deployment(e)) if e.contains("no AWS role")
        ));
        assert_eq!(parent.opened(), [PARENT_PORT]);
        for expected in ["second", "third"] {
            match cloud.deployment(&role()).await.unwrap() {
                DeploymentProof::Proof(proof) => assert_eq!(proof, presigned(expected)),
                DeploymentProof::Attested(_) => panic!("the parent's proof is not attested"),
            }
        }
        assert_eq!(parent.opened(), [PARENT_PORT; 3]);
        // The parent is gone.
        assert!(matches!(cloud.deployment(&role()).await, Err(CloudError::Deployment(_))));
    }

    #[tokio::test]
    async fn proofs_for_another_tenant_or_of_another_kind_are_refused() {
        let oidc = IdentityProof::Oidc { provider: OidcProvider::Azure, jwt: Bearer::new("eyJ.a.b".into()) };
        let parent = FakeParent::with_messages(vec![
            message("acme", presigned("a")),
            message("other", presigned("b")),
            message("acme", oidc),
        ]);
        let cloud = nitro(parent).await.unwrap();
        assert!(matches!(
            cloud.deployment(&role()).await,
            Err(CloudError::Deployment(e)) if e.contains("names tenant other")
        ));
        assert!(matches!(
            cloud.deployment(&role()).await,
            Err(CloudError::Deployment(e)) if e.contains("not a presigned STS request")
        ));
    }

    #[tokio::test]
    async fn nitro_listens_on_vsock_and_dials_through_the_parent() {
        let parent = FakeParent::with_messages(vec![message("acme", presigned("a"))]);
        let cloud = nitro(parent).await.unwrap();
        let listen = cloud.listen("0.0.0.0:8443".parse().unwrap());
        assert_eq!(listen, Listen::Parent { port: 8443 });
        assert_eq!(listen.to_string(), "vsock port 8443");
        assert!(cloud.dialer().dial("bad host", 443).await.is_err());
        // A parent without a message: no cloud.
        assert!(matches!(nitro(FakeParent::with_messages(vec![])).await, Err(CloudError::Pin(_))));
    }
}

// ---- the listener ----

#[tokio::test]
async fn tcp_listeners_take_the_peer_address() {
    let listener = crate::Listen::Tcp("127.0.0.1:0".parse().unwrap()).bind().await.unwrap();
    assert!(!listener.names_clients());
    let crate::Listener::Tcp(tcp) = &listener else { panic!("not TCP") };
    let addr = tcp.local_addr().unwrap();
    assert_eq!(listener.local(), addr.to_string());
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (_, peer) = listener.accept().await.unwrap();
    assert_eq!(peer, client.local_addr().unwrap());
}

#[tokio::test]
async fn vsock_listeners_take_only_the_parent() {
    let probe = match seal_net::vsock::VsockListener::bind(seal_net::vsock::CID_ANY, seal_net::vsock::PORT_ANY) {
        Ok(listener) => listener.port(),
        Err(e) => return eprintln!("no vsock here ({e}); skipped"),
    };
    let listener = crate::Listen::Parent { port: probe }.bind().await.unwrap();
    assert!(listener.names_clients());
    assert_eq!(listener.local(), format!("vsock port {probe}"));
    // On loopback the peer is CID 1, not the parent's 3: closed, and never handed on.
    let Ok(mut client) = seal_net::vsock::connect(seal_net::vsock::CID_LOCAL, probe, Duration::from_secs(5)).await
    else {
        return eprintln!("no vsock loopback here; skipped");
    };
    let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept());
    let (accepted, closed) = tokio::join!(accepted, async {
        let mut buf = [0u8; 1];
        client.read(&mut buf).await
    });
    assert!(accepted.is_err(), "a connection not from the parent was accepted");
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
}

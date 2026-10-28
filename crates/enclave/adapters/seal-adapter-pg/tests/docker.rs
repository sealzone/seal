//! End to end against a real Postgres in Docker (image `SEAL_PG_IMAGE`, default `postgres:17`):
//! SCRAM-SHA-256 only, TLS with a test CA that the connector trusts as a sim build's extra
//! root. Skipped when Docker is not available, unless `SEAL_REQUIRE_DOCKER=1`.

mod common;

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{connect, connect_to, contains, error_field, extended_msgs, message, query_msg, startup_packet};
use seal_adapter::testing::{claims, FixedResolver};
use seal_adapter::{AdapterError, Outcome, UpstreamConnector, UpstreamErrorKind};
use seal_adapter_pg::PostgresAdapter;
use seal_net::BakedRootsConnector;
use seal_proto::policy::Destination;
use seal_proto::telemetry::Sqlstate;
use seal_proto::ErrorCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "pg.seal.test";
const SECRET: &str = "Seal-E2E-pw-4f9c";
const TOKEN: &str = "seallk_docker";
const LOGIN: &[(&str, &str)] = &[("user", "postgres"), ("database", "postgres"), ("application_name", "e2e")];

mod pki {
    use base64::Engine;
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::EncodePrivateKey;
    use sha2::{Digest, Sha256};
    use std::str::FromStr;
    use std::time::{Duration, SystemTime};
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder, CertificateBuilder};
    use x509_cert::certificate::TbsCertificate;
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::der::oid::ObjectIdentifier;
    use x509_cert::der::pem::LineEnding;
    use x509_cert::der::EncodePem;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};
    use x509_cert::ext::{Extension, ToExtension};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoRef;
    use x509_cert::time::{Time, Validity};
    use x509_cert::{Certificate, SubjectPublicKeyInfo};

    const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

    struct Profile {
        issuer: Name,
        subject: Name,
        ca: bool,
        sans: Vec<GeneralName>,
    }

    impl BuilderProfile for Profile {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.issuer.clone()
        }
        fn get_subject(&self) -> Name {
            self.subject.clone()
        }
        fn build_extensions(
            &self,
            _spk: SubjectPublicKeyInfoRef<'_>,
            _issuer_spk: SubjectPublicKeyInfoRef<'_>,
            tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let subject = tbs.subject();
            let mut exts =
                vec![(&BasicConstraints { ca: self.ca, path_len_constraint: None }).to_extension(subject, &[])?];
            let usage =
                if self.ca { KeyUsages::KeyCertSign | KeyUsages::CRLSign } else { KeyUsages::DigitalSignature.into() };
            exts.push((&KeyUsage(usage)).to_extension(subject, &[])?);
            if !self.ca {
                exts.push((&ExtendedKeyUsage(vec![SERVER_AUTH])).to_extension(subject, &[])?);
                exts.push((&SubjectAltName(self.sans.clone())).to_extension(subject, &[])?);
            }
            Ok(exts)
        }
    }

    fn build(profile: Profile, serial: u32, subject_key: &SigningKey, signer: &SigningKey) -> Certificate {
        let now = SystemTime::now();
        let day = Duration::from_secs(86_400);
        let validity = Validity::new(Time::try_from(now - day).unwrap(), Time::try_from(now + day).unwrap());
        let spki = SubjectPublicKeyInfo::from_key(subject_key.verifying_key()).unwrap();
        let builder = CertificateBuilder::new(profile, SerialNumber::from(serial), validity, spki).unwrap();
        builder.build::<_, DerSignature>(signer).unwrap()
    }

    /// Root CA, leaf certificate for `host` and the leaf's PKCS#8 key, all PEM.
    pub fn issue(host: &str) -> (String, String, String) {
        let key = |label: &str| SigningKey::from_slice(&Sha256::digest(label.as_bytes())).unwrap();
        let root_name = Name::from_str("CN=Seal pg test root,O=Seal Test,C=US").unwrap();
        let root_key = key("pg-root");
        let profile = Profile { issuer: root_name.clone(), subject: root_name.clone(), ca: true, sans: vec![] };
        let root = build(profile, 1, &root_key, &root_key);
        let leaf_key = key("pg-leaf");
        let sans = vec![GeneralName::DnsName(Ia5String::new(host).unwrap())];
        let subject = Name::from_str(&format!("CN={host}")).unwrap();
        let leaf = build(Profile { issuer: root_name, subject, ca: false, sans }, 2, &leaf_key, &root_key);
        let der = leaf_key.to_pkcs8_der().unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_bytes());
        let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
        let key_pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", lines.join("\n"));
        (root.to_pem(LineEnding::LF).unwrap(), leaf.to_pem(LineEnding::LF).unwrap(), key_pem)
    }
}

/// A Postgres container, removed on drop.
struct Postgres {
    id: String,
    addr: SocketAddr,
}

impl Drop for Postgres {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

fn docker_available() -> bool {
    Command::new("docker").args(["info", "--format", "{{.ServerVersion}}"]).output().is_ok_and(|o| o.status.success())
}

/// Starts Postgres with the user `app`, database `orders`, password `SECRET`, SCRAM-only
/// `pg_hba` and TLS from the test PKI; waits until it answers `SSLRequest` with `S`.
async fn start_postgres(cert: &str, key: &str) -> Postgres {
    let image = std::env::var("SEAL_PG_IMAGE").unwrap_or_else(|_| "postgres:17".into());
    let script = r#"printf '%s' "$PG_CERT" > /tmp/server.crt && printf '%s' "$PG_KEY" > /tmp/server.key \
        && chown postgres /tmp/server.crt /tmp/server.key && chmod 600 /tmp/server.key \
        && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key \
           -c password_encryption=scram-sha-256"#;
    let out = Command::new("docker")
        .args(["run", "-d", "-p", "127.0.0.1::5432"])
        .args(["-e", "POSTGRES_USER=app", "-e", "POSTGRES_DB=orders"])
        .args(["-e", &format!("POSTGRES_PASSWORD={SECRET}")])
        .args(["-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256", "-e", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256"])
        .args(["-e", &format!("PG_CERT={cert}"), "-e", &format!("PG_KEY={key}")])
        .args(["--entrypoint", "bash", &image, "-c", script])
        .output()
        .expect("docker run");
    assert!(out.status.success(), "docker run: {}", String::from_utf8_lossy(&out.stderr));
    let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let port = Command::new("docker").args(["port", &id, "5432/tcp"]).output().unwrap();
    let mapped = String::from_utf8(port.stdout).unwrap();
    let addr: SocketAddr = mapped.lines().next().expect("a mapped port").trim().parse().unwrap();
    let pg = Postgres { id, addr };

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok(mut s) = tokio::net::TcpStream::connect(pg.addr).await {
            let mut reply = [0u8; 1];
            let asked = s.write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]).await.is_ok();
            let read = tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut reply));
            if asked && read.await.is_ok_and(|r| r.is_ok()) && reply[0] == b'S' {
                return pg;
            }
        }
        assert!(Instant::now() < deadline, "Postgres did not start");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

struct FixedDialer(SocketAddr);

#[async_trait::async_trait]
impl seal_net::Dialer for FixedDialer {
    async fn dial(&self, _host: &str, _port: u16) -> Result<seal_net::BoxStream, seal_net::NetError> {
        seal_net::TcpDialer.dial(&self.0.ip().to_string(), self.0.port()).await
    }
}

fn resolver(secret: &str) -> Arc<FixedResolver> {
    let resolver = FixedResolver::new();
    let dest = Destination::parse(&format!("postgres://app@{HOST}:5432/orders")).unwrap();
    resolver.insert(TOKEN, claims(dest, secret.as_bytes()));
    resolver
}

/// The text values of a `DataRow` body.
fn row(body: &[u8]) -> Vec<String> {
    let count = i16::from_be_bytes([body[0], body[1]]) as usize;
    let mut rest = &body[2..];
    let mut out = Vec::new();
    for _ in 0..count {
        let len = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        out.push(String::from_utf8_lossy(&rest[4..4 + len]).into_owned());
        rest = &rest[4 + len..];
    }
    out
}

fn rows(msgs: &[(u8, Vec<u8>)]) -> Vec<Vec<String>> {
    msgs.iter().filter(|m| m.0 == b'D').map(|m| row(&m.1)).collect()
}

#[tokio::test]
async fn real_postgres_over_tls_with_scram() {
    if !docker_available() {
        assert!(
            std::env::var("SEAL_REQUIRE_DOCKER").is_err(),
            "SEAL_REQUIRE_DOCKER is set but Docker is not available"
        );
        eprintln!("skipped: Docker is not available");
        return;
    }
    let (root, cert, key) = pki::issue(HOST);
    let pg = start_postgres(&cert, &key).await;
    let connector: Arc<dyn UpstreamConnector> =
        Arc::new(BakedRootsConnector::with_extra_roots(Arc::new(FixedDialer(pg.addr)), root.as_bytes()).unwrap());

    // Queries run as the destination's user and database, whatever the client asked for.
    let r = resolver(SECRET);
    let adapter = Arc::new(PostgresAdapter::default());
    let (mut c, task) = connect_to(adapter.clone(), r.clone(), connector.clone());
    let greeting = c.login(LOGIN, TOKEN).await;
    assert_eq!(greeting.first().map(|m| m.0), Some(b'R'), "{greeting:?}");
    assert_eq!(greeting.last().map(|m| m.0), Some(b'Z'));
    let key_data = &greeting.iter().find(|m| m.0 == b'K').unwrap().1;
    let who = "SELECT current_user, current_database(), current_setting('application_name'), ssl, pid \
               FROM pg_stat_ssl WHERE pid = pg_backend_pid()";
    let reply = c.query(who).await;
    let row = &rows(&reply)[0];
    assert_eq!(row[..4], ["app", "orders", "e2e", "t"], "{reply:?}");
    assert_ne!(key_data[..4], row[4].parse::<i32>().unwrap().to_be_bytes(), "the client's key is the adapter's own");

    // The secret is scrubbed from rows and errors.
    let leak = c.query(&format!("SELECT '{SECRET}' AS leak")).await;
    assert_eq!(rows(&leak), [["*".repeat(SECRET.len())]]);
    let raised = c.query(&format!("DO $$BEGIN RAISE EXCEPTION 'leak %', '{SECRET}'; END$$")).await;
    let error = raised.iter().find(|m| m.0 == b'E').unwrap();
    assert_eq!(error_field(&error.1, b'M').unwrap(), format!("leak {}", "*".repeat(SECRET.len())));

    // Extended protocol.
    c.send(&extended_msgs("SELECT 42")).await;
    let extended = c.until_ready().await;
    assert_eq!(rows(&extended), [["42"]]);

    c.send(&message(b'X', b"")).await;
    c.drain().await;
    task.await.unwrap().unwrap();
    assert!(!contains(&c.received, SECRET.as_bytes()));
    let done: Vec<(String, Outcome)> = r.take_completions().into_iter().map(|d| (d.action, d.outcome)).collect();
    let raised = Outcome::UpstreamError(UpstreamErrorKind::Sqlstate(Sqlstate::new(*b"P0001").unwrap()));
    assert_eq!(
        done,
        [
            ("QUERY".into(), Outcome::Allowed),
            ("QUERY".into(), Outcome::Allowed),
            ("QUERY".into(), raised),
            ("PARSE".into(), Outcome::Allowed)
        ]
    );
    let observed: Vec<String> = r.take_observations().into_iter().map(|o| o.action).collect();
    assert_eq!(observed, ["QUERY", "QUERY", "QUERY", "PARSE"]);

    // A wrong Seal credential never reaches Postgres.
    let (mut c, task) = connect(r.clone(), connector.clone());
    let reply = c.login(LOGIN, "seallk_nope").await;
    assert_eq!(error_field(&reply[0].1, b'C').unwrap(), "28P01");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::NotAllowed))));

    // A stale secret: Postgres refuses it; the client sees only the adapter's text.
    let stale = resolver("not-the-password");
    let (mut c, task) = connect(stale.clone(), connector.clone());
    let reply = c.login(LOGIN, TOKEN).await;
    assert_eq!(error_field(&reply[0].1, b'C').unwrap(), "08004");
    assert!(error_field(&reply[0].1, b'M').unwrap().starts_with("seal: "));
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Upstream(UpstreamErrorKind::AuthRejected))));
    assert_eq!(stale.take_completions()[0].outcome, Outcome::UpstreamError(UpstreamErrorKind::AuthRejected));

    // A cancel request with the key the adapter gave cancels the running query, over a new
    // verified TLS connection with the upstream's own key; any other key does nothing.
    let (mut c, task) = connect_to(adapter.clone(), r.clone(), connector.clone());
    let greeting = c.login(LOGIN, TOKEN).await;
    let key = greeting.iter().find(|m| m.0 == b'K').unwrap().1.clone();
    c.send(&query_msg("SELECT pg_sleep(30)")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let cancel = |key: &[u8]| [&[0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e][..], key].concat();
    let mut wrong = key.clone();
    wrong[7] ^= 1;
    let (mut x, x_task) = connect_to(adapter.clone(), r.clone(), connector.clone());
    x.send(&cancel(&wrong)).await;
    assert!(x.drain().await.is_empty());
    assert!(matches!(x_task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::NotAllowed))));
    let (mut x, x_task) = connect_to(adapter.clone(), r.clone(), connector.clone());
    let started = Instant::now();
    x.send(&cancel(&key)).await;
    assert!(x.drain().await.is_empty());
    x_task.await.unwrap().unwrap();
    let cancelled = tokio::time::timeout(Duration::from_secs(10), c.until_ready()).await.expect("cancelled");
    assert!(started.elapsed() < Duration::from_secs(10));
    let error = cancelled.iter().find(|m| m.0 == b'E').expect("an ErrorResponse");
    assert_eq!(error_field(&error.1, b'C').unwrap(), "57014", "query_canceled");
    c.send(&message(b'X', b"")).await;
    c.drain().await;
    task.await.unwrap().unwrap();
    let done: Vec<(String, Outcome)> = r.take_completions().into_iter().map(|d| (d.action, d.outcome)).collect();
    let canceled = Outcome::UpstreamError(UpstreamErrorKind::Sqlstate(Sqlstate::new(*b"57014").unwrap()));
    assert_eq!(done, [("CANCEL".into(), Outcome::Allowed), ("QUERY".into(), canceled)]);
    r.take_observations();

    // Replication is refused.
    let (mut c, task) = connect(r.clone(), connector.clone());
    c.send(&startup_packet(&[("user", "app"), ("database", "orders"), ("replication", "database")])).await;
    assert_eq!(error_field(&c.drain().await[0].1, b'C').unwrap(), "0A000");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::PolicyDenied))));

    // Ending the session cuts a running query.
    let (mut c, task) = connect(r.clone(), connector.clone());
    c.login(LOGIN, TOKEN).await;
    c.send(&query_msg("SELECT pg_sleep(30)")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    r.end_all(ErrorCode::SessionEnded);
    let cut = tokio::time::timeout(Duration::from_secs(5), c.drain()).await.expect("cut at once");
    assert_eq!(cut.len(), 1);
    assert_eq!(error_field(&cut[0].1, b'C').unwrap(), "57P01");
    assert_eq!(error_field(&cut[0].1, b'S').unwrap(), "FATAL");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::SessionEnded))));
    let done = r.take_completions();
    assert_eq!((done[0].action.as_str(), &done[0].outcome), ("QUERY", &Outcome::Aborted));
    assert!(done[0].bytes_up > 0);
}

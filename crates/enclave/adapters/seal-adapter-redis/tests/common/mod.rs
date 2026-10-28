//! Test client over an in-memory pipe, and a test PKI.
#![allow(dead_code)]

use std::time::Duration;

use bytes::BytesMut;
use seal_adapter::{Adapter, AdapterCtx, AdapterError, ConnMeta};
use seal_adapter_redis::resp::{encode_command, ReplyScanner};
use seal_adapter_redis::RedisAdapter;
use seal_proto::policy::Protocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

pub const WAIT: Duration = Duration::from_secs(10);

/// One inbound connection: the adapter's task and the client's end of the pipe.
pub struct TestClient {
    io: DuplexStream,
    buf: BytesMut,
    pub served: JoinHandle<Result<(), AdapterError>>,
}

pub fn connect(ctx: &AdapterCtx) -> TestClient {
    let (client, server) = tokio::io::duplex(1 << 20);
    let ctx = ctx.clone();
    let meta = ConnMeta {
        connection_id: 7,
        protocol: Protocol::Redis,
        peer: None,
        tunnel: seal_proto::tunnel::TunnelConnect {
            token: seal_proto::Bearer::new("sealtok_preamble".into()),
            local_key_sha256: [0; 32],
        },
    };
    let served = tokio::spawn(async move { RedisAdapter.serve(Box::new(server), meta, ctx).await });
    TestClient { io: client, buf: BytesMut::new(), served }
}

/// Splits a command line on spaces.
pub fn words(line: &str) -> Vec<&str> {
    line.split(' ').collect()
}

impl TestClient {
    pub async fn send(&mut self, line: &str) {
        self.raw(&encode_command(&words(line))).await;
    }

    pub async fn send_args(&mut self, args: &[&[u8]]) {
        self.raw(&encode_command(args)).await;
    }

    pub async fn raw(&mut self, bytes: &[u8]) {
        self.io.write_all(bytes).await.unwrap();
    }

    /// The next whole reply, as bytes.
    pub async fn reply(&mut self) -> Vec<u8> {
        tokio::time::timeout(WAIT, self.try_reply()).await.expect("a reply in time").expect("a reply before EOF")
    }

    async fn try_reply(&mut self) -> Option<Vec<u8>> {
        let mut scanner = ReplyScanner::default();
        let mut frame = Vec::new();
        loop {
            while !self.buf.is_empty() {
                let (n, done) = scanner.feed(&self.buf).expect("a well-formed reply");
                frame.extend_from_slice(&self.buf.split_to(n));
                if done.is_some() {
                    return Some(frame);
                }
            }
            if self.io.read_buf(&mut self.buf).await.unwrap() == 0 {
                return None;
            }
        }
    }

    /// The next reply as text.
    pub async fn text(&mut self) -> String {
        String::from_utf8(self.reply().await).unwrap()
    }

    /// Sends `line` and returns the reply as text.
    pub async fn call(&mut self, line: &str) -> String {
        self.send(line).await;
        self.text().await
    }

    /// Closes the client's end; how `serve` returned.
    pub async fn hang_up(self) -> Result<(), AdapterError> {
        drop(self.io);
        tokio::time::timeout(WAIT, self.served).await.expect("serve returns").unwrap()
    }

    /// Whatever the adapter sends until it closes, then how `serve` returned.
    pub async fn closed(mut self) -> (String, Result<(), AdapterError>) {
        let mut rest = self.buf.to_vec();
        tokio::time::timeout(WAIT, self.io.read_to_end(&mut rest)).await.expect("the adapter closes").unwrap();
        let result = tokio::time::timeout(WAIT, self.served).await.expect("serve returns").unwrap();
        (String::from_utf8(rest).unwrap(), result)
    }
}

/// `$<len>\r\n<value>\r\n`.
pub fn bulk(value: &str) -> String {
    format!("${}\r\n{value}\r\n", value.len())
}

/// A test CA and a leaf for some DNS names, as PEM.
pub mod pki {
    use p256::ecdsa::{DerSignature, SigningKey};
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

    fn key(label: &str) -> SigningKey {
        SigningKey::from_slice(&Sha256::digest(label.as_bytes())).unwrap()
    }

    fn build(profile: Profile, serial: u32, subject_key: &SigningKey, signer: &SigningKey) -> Certificate {
        let now = SystemTime::now();
        let day = Duration::from_secs(86_400);
        let validity = Validity::new(Time::try_from(now - day).unwrap(), Time::try_from(now + day).unwrap());
        let spki = SubjectPublicKeyInfo::from_key(subject_key.verifying_key()).unwrap();
        let builder = CertificateBuilder::new(profile, SerialNumber::from(serial), validity, spki).unwrap();
        builder.build::<_, DerSignature>(signer).unwrap()
    }

    pub struct Issued {
        pub ca_pem: String,
        pub cert_pem: String,
        pub key_pem: String,
    }

    pub fn issue(hosts: &[&str]) -> Issued {
        use p256::pkcs8::EncodePrivateKey;
        let root_name = Name::from_str("CN=Seal redis test root,O=Seal Test,C=US").unwrap();
        let root_key = key("redis-root");
        let root = build(
            Profile { issuer: root_name.clone(), subject: root_name.clone(), ca: true, sans: vec![] },
            1,
            &root_key,
            &root_key,
        );
        let leaf_key = key("redis-leaf");
        let sans = hosts.iter().map(|h| GeneralName::DnsName(Ia5String::new(h).unwrap())).collect();
        let leaf = build(
            Profile { issuer: root_name, subject: Name::from_str("CN=redis-leaf").unwrap(), ca: false, sans },
            2,
            &leaf_key,
            &root_key,
        );
        let key_der = leaf_key.to_pkcs8_der().unwrap();
        Issued {
            ca_pem: root.to_pem(LineEnding::LF).unwrap(),
            cert_pem: leaf.to_pem(LineEnding::LF).unwrap(),
            key_pem: x509_cert::der::pem::encode_string("PRIVATE KEY", LineEnding::LF, key_der.as_bytes()).unwrap(),
        }
    }
}

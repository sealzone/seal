//! The enclave's deterministic TLS certificates: a CA certificate, and a leaf certificate for
//! the handshake key, signed by the CA (`TlsKey::{ca_certificate_der, leaf_certificate_der}`). The enclave presents
//! `[leaf, CA]`. Two levels because many clients (rustls/webpki among them) refuse a CA
//! certificate presented as the server's own.
//!
//! Every input is fixed or derived, so every replica of a tenant and service key version
//! builds the same bytes: validity 2026-01-01T00:00:00Z..2126-01-01T00:00:00Z, ECDSA P-256
//! with SHA-256 and RFC 6979 nonces, subjectKeyIdentifier = the first 20 bytes of SHA-256 of
//! the subject public key (RFC 7093 method 1).
//! - CA: serial 1, CN `"Seal enclave CA <tenant> <service key version>"`, self-signed;
//!   basicConstraints (critical, CA:true, pathLen 0), keyUsage (critical, keyCertSign),
//!   extendedKeyUsage (serverAuth), nameConstraints (critical, permitted dNSName subtrees = the
//!   DNS names), subjectKeyIdentifier.
//! - Leaf: serial 2, CN `"Seal enclave <tenant> <service key version>"`, issuer the CA;
//!   basicConstraints (critical, CA:false), keyUsage (critical, digitalSignature),
//!   extendedKeyUsage (serverAuth), subjectAltName (the DNS names), subjectKeyIdentifier,
//!   authorityKeyIdentifier (the CA's key identifier).

use std::str::FromStr;
use std::time::Duration;

use der::asn1::{GeneralizedTime, Ia5String, OctetString};
use der::Encode;
use p256::ecdsa::{DerSignature, SigningKey};
use sha2::{Digest, Sha256};
use spki::{ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, NameConstraints, SubjectAltName,
    SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use crate::{CryptoError, TlsKey};

/// 2026-01-01T00:00:00Z.
pub const NOT_BEFORE: u64 = 1_767_225_600;
/// 2126-01-01T00:00:00Z.
pub const NOT_AFTER: u64 = 4_922_899_200;
const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// Subject and issuer given explicitly; extensions added by the caller.
struct Names {
    subject: Name,
    issuer: Name,
}

impl BuilderProfile for Names {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    fn build_extensions(
        &self,
        _spk: spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

fn time(unix: u64) -> Result<Time, CryptoError> {
    GeneralizedTime::from_unix_duration(Duration::from_secs(unix))
        .map(Time::GeneralTime)
        .map_err(|e| CryptoError::Malformed(format!("certificate time: {e}")))
}

fn malformed(what: &str) -> impl Fn(der::Error) -> CryptoError + '_ {
    move |e| CryptoError::Malformed(format!("certificate {what}: {e}"))
}

fn dns_names(dns_names: &[String]) -> Result<Vec<GeneralName>, CryptoError> {
    if dns_names.is_empty() {
        return Err(CryptoError::Malformed("certificate needs at least one DNS name".into()));
    }
    dns_names
        .iter()
        .map(|n| {
            // No wildcards: a name constraint cannot hold one, and every name is a literal host.
            if n.is_empty() || !n.is_ascii() || n.contains('*') {
                return Err(CryptoError::Malformed(format!("certificate DNS name `{}`", n.escape_debug())));
            }
            Ia5String::new(n).map(GeneralName::DnsName).map_err(malformed("DNS name"))
        })
        .collect()
}

fn spki(secret: &p256::SecretKey) -> Result<SubjectPublicKeyInfoOwned, CryptoError> {
    use p256::pkcs8::EncodePublicKey;
    let der = secret.public_key().to_public_key_der().expect("SPKI encoding of a P-256 key cannot fail");
    SubjectPublicKeyInfoOwned::try_from(der.as_bytes())
        .map_err(|e| CryptoError::Malformed(format!("certificate public key: {e}")))
}

fn key_identifier(spki: &SubjectPublicKeyInfoOwned) -> [u8; 20] {
    let digest = Sha256::digest(spki.subject_public_key.raw_bytes());
    digest[..20].try_into().expect("20 of 32 bytes")
}

fn ca_name(key: &TlsKey) -> Result<Name, CryptoError> {
    Name::from_str(&format!("CN=Seal enclave CA {} {}", key.tenant, key.service_key_version))
        .map_err(malformed("subject"))
}

fn builder(
    names: Names,
    serial: u8,
    spki: SubjectPublicKeyInfoOwned,
) -> Result<CertificateBuilder<Names>, CryptoError> {
    // Validity is GeneralizedTime here; the builder re-encodes pre-2050 times as UTCTime.
    let validity = Validity::new(time(NOT_BEFORE)?, time(NOT_AFTER)?);
    let serial = SerialNumber::new(&[serial]).map_err(malformed("serial"))?;
    CertificateBuilder::new(names, serial, validity, spki)
        .map_err(|e| CryptoError::Malformed(format!("certificate: {e}")))
}

fn sign(builder: CertificateBuilder<Names>, signer: &SigningKey) -> Result<Vec<u8>, CryptoError> {
    let cert =
        builder.build::<_, DerSignature>(signer).map_err(|e| CryptoError::Malformed(format!("certificate: {e}")))?;
    cert.to_der().map_err(malformed("encoding"))
}

pub(crate) fn ca(key: &TlsKey, names: &[String]) -> Result<Vec<u8>, CryptoError> {
    let names = dns_names(names)?;
    let name = ca_name(key)?;
    let spki = spki(&key.ca_secret)?;
    let ski = key_identifier(&spki);
    let mut b = builder(Names { subject: name.clone(), issuer: name }, 1, spki)?;
    let enc = malformed("extension");
    b.add_extension(&BasicConstraints { ca: true, path_len_constraint: Some(0) }).map_err(&enc)?;
    b.add_extension(&KeyUsage(KeyUsages::KeyCertSign.into())).map_err(&enc)?;
    b.add_extension(&ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH])).map_err(&enc)?;
    b.add_extension(&NameConstraints {
        permitted_subtrees: Some(
            names.into_iter().map(|base| GeneralSubtree { base, minimum: 0, maximum: None }).collect(),
        ),
        excluded_subtrees: None,
    })
    .map_err(&enc)?;
    b.add_extension(&SubjectKeyIdentifier(OctetString::new(&ski[..]).map_err(&enc)?)).map_err(&enc)?;
    sign(b, &SigningKey::from(&key.ca_secret))
}

pub(crate) fn leaf(key: &TlsKey, names: &[String]) -> Result<Vec<u8>, CryptoError> {
    let names = dns_names(names)?;
    let subject = Name::from_str(&format!("CN=Seal enclave {} {}", key.tenant, key.service_key_version))
        .map_err(malformed("subject"))?;
    let ca_ski = key_identifier(&spki(&key.ca_secret)?);
    let spki = spki(&key.secret)?;
    let ski = key_identifier(&spki);
    let mut b = builder(Names { subject, issuer: ca_name(key)? }, 2, spki)?;
    let enc = malformed("extension");
    b.add_extension(&BasicConstraints { ca: false, path_len_constraint: None }).map_err(&enc)?;
    b.add_extension(&KeyUsage(KeyUsages::DigitalSignature.into())).map_err(&enc)?;
    b.add_extension(&ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH])).map_err(&enc)?;
    b.add_extension(&SubjectAltName(names)).map_err(&enc)?;
    b.add_extension(&SubjectKeyIdentifier(OctetString::new(&ski[..]).map_err(&enc)?)).map_err(&enc)?;
    b.add_extension(&AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new(&ca_ski[..]).map_err(&enc)?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    })
    .map_err(&enc)?;
    sign(b, &SigningKey::from(&key.ca_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key32;
    use der::Decode;
    use p256::ecdsa::signature::Verifier;
    use seal_proto::{ServiceKeyVersion, TenantId};
    use x509_cert::Certificate;

    fn key(seed: u8) -> TlsKey {
        TlsKey::from_seed(&Key32::from_bytes([seed; 32]), TenantId::new("acme").unwrap(), ServiceKeyVersion(2))
    }
    fn names() -> Vec<String> {
        vec!["acme.enclave.seal.zone".into(), "replica.acme.enclave.seal.zone".into()]
    }
    fn ext<'a>(cert: &'a Certificate, oid: &str) -> &'a Extension {
        let oid = ObjectIdentifier::new_unwrap(oid);
        cert.tbs_certificate().extensions().unwrap().iter().find(|e| e.extn_id == oid).unwrap()
    }
    fn verifies_under(cert: &Certificate, key: &p256::SecretKey) -> bool {
        let vk = p256::ecdsa::VerifyingKey::from(&key.public_key());
        let sig = DerSignature::from_bytes(cert.signature().raw_bytes()).unwrap();
        vk.verify(&cert.tbs_certificate().to_der().unwrap(), &sig).is_ok()
    }

    #[test]
    fn both_certificates_are_deterministic() {
        let k = key(1);
        for build in [TlsKey::ca_certificate_der, TlsKey::leaf_certificate_der] {
            let der = build(&k, &names()).unwrap();
            assert_eq!(der, build(&key(1), &names()).unwrap());
            assert_ne!(der, build(&key(2), &names()).unwrap());
            assert_ne!(der, build(&k, &["other.example".into()]).unwrap());
        }
        // The CA key is not the handshake key.
        assert_ne!(spki(&k.ca_secret).unwrap().to_der().unwrap(), k.spki_der());
    }

    #[test]
    fn ca_certificate_is_a_name_constrained_root() {
        let k = key(1);
        let ca = Certificate::from_der(&k.ca_certificate_der(&names()).unwrap()).unwrap();
        let tbs = ca.tbs_certificate();
        assert_eq!(tbs.subject(), tbs.issuer());
        assert_eq!(tbs.subject().to_string(), "CN=Seal enclave CA acme v2");
        assert_eq!(tbs.serial_number().as_bytes(), &[1]);
        assert_eq!(tbs.validity().not_before.to_unix_duration().as_secs(), NOT_BEFORE);
        assert_eq!(tbs.validity().not_after.to_unix_duration().as_secs(), NOT_AFTER);
        assert!(verifies_under(&ca, &k.ca_secret));
        let bc = ext(&ca, "2.5.29.19");
        assert!(bc.critical && BasicConstraints::from_der(bc.extn_value.as_bytes()).unwrap().ca);
        let nc = ext(&ca, "2.5.29.30");
        assert!(nc.critical);
        let permitted: Vec<_> = NameConstraints::from_der(nc.extn_value.as_bytes())
            .unwrap()
            .permitted_subtrees
            .unwrap()
            .into_iter()
            .map(|s| match s.base {
                GeneralName::DnsName(n) => n.to_string(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(permitted, ["acme.enclave.seal.zone", "replica.acme.enclave.seal.zone"]);
    }

    #[test]
    fn leaf_is_the_handshake_key_signed_by_the_ca() {
        let k = key(1);
        let ca = Certificate::from_der(&k.ca_certificate_der(&names()).unwrap()).unwrap();
        let leaf = Certificate::from_der(&k.leaf_certificate_der(&names()).unwrap()).unwrap();
        let tbs = leaf.tbs_certificate();
        assert_eq!(tbs.issuer(), ca.tbs_certificate().subject());
        assert_eq!(tbs.subject().to_string(), "CN=Seal enclave acme v2");
        assert_eq!(tbs.serial_number().as_bytes(), &[2]);
        assert_eq!(tbs.subject_public_key_info().to_der().unwrap(), k.spki_der());
        assert!(verifies_under(&leaf, &k.ca_secret));
        assert!(!verifies_under(&leaf, &k.secret));
        let bc = ext(&leaf, "2.5.29.19");
        assert!(bc.critical && !BasicConstraints::from_der(bc.extn_value.as_bytes()).unwrap().ca);
        assert_eq!(SubjectAltName::from_der(ext(&leaf, "2.5.29.17").extn_value.as_bytes()).unwrap().0.len(), 2);
    }

    /// What the two levels are for: a stock rustls/webpki client that trusts only the CA
    /// accepts the leaf for the replica's names and nothing else, and refuses the CA
    /// certificate presented as the server's own.
    #[test]
    fn a_rustls_client_trusting_the_ca_accepts_the_leaf() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use std::sync::Arc;

        let k = key(1);
        let ca = CertificateDer::from(k.ca_certificate_der(&names()).unwrap());
        let leaf = CertificateDer::from(k.leaf_certificate_der(&names()).unwrap());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000));
        let check = |cert: &CertificateDer<'_>, name: &str| {
            verifier.verify_server_cert(cert, &[], &ServerName::try_from(name.to_string()).unwrap(), &[], now)
        };
        check(&leaf, "acme.enclave.seal.zone").unwrap();
        check(&leaf, "replica.acme.enclave.seal.zone").unwrap();
        assert!(check(&leaf, "r1.acme.enclave.seal.zone").is_err());
        assert!(check(&leaf, "other.example").is_err());
        assert!(check(&ca, "acme.enclave.seal.zone").is_err());
    }

    #[test]
    fn certificates_need_valid_names() {
        let k = key(1);
        for build in [TlsKey::ca_certificate_der, TlsKey::leaf_certificate_der] {
            assert!(build(&k, &[]).is_err());
            assert!(build(&k, &["".into()]).is_err());
            assert!(build(&k, &["bücher.example".into()]).is_err());
            assert!(build(&k, &["*.acme.enclave.seal.zone".into()]).is_err());
        }
    }
}

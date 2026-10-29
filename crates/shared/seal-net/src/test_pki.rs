//! Test PKI: roots, intermediates and leaves built with x509-cert, keys derived from labels.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use p256::ecdsa::{DerSignature, SigningKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use seal_proto::policy::SpkiPin;
use sha2::{Digest, Sha256};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::Encode;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoRef;
use x509_cert::time::{Time, Validity};
use x509_cert::SubjectPublicKeyInfo;

const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// A certificate with its key.
pub struct Issued {
    pub der: CertificateDer<'static>,
    pub key: SigningKey,
    pub name: Name,
}

impl Issued {
    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        use p256::pkcs8::EncodePrivateKey;
        let doc = self.key.to_pkcs8_der().expect("pkcs8");
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(doc.as_bytes().to_vec()))
    }

    /// SHA-256 of the certificate's SubjectPublicKeyInfo DER, computed with x509-cert.
    pub fn pin(&self) -> SpkiPin {
        use x509_cert::der::Decode;
        let cert = x509_cert::Certificate::from_der(self.der.as_ref()).expect("parse");
        let spki = cert.tbs_certificate().subject_public_key_info().to_der().expect("spki");
        SpkiPin(Sha256::digest(&spki).into())
    }

    #[cfg(feature = "sim")]
    pub fn pem(&self) -> String {
        use x509_cert::der::Decode;
        use x509_cert::der::{pem::LineEnding, EncodePem};
        x509_cert::Certificate::from_der(self.der.as_ref()).expect("parse").to_pem(LineEnding::LF).expect("pem")
    }
}

#[derive(Clone, Copy)]
pub enum Life {
    Valid,
    Expired,
}

impl Life {
    fn validity(self) -> Validity {
        let now = SystemTime::now();
        let day = Duration::from_secs(86_400);
        let (from, to) = match self {
            Life::Valid => (now - day, now + day),
            Life::Expired => (now - 3 * day, now - day),
        };
        Validity::new(Time::try_from(from).expect("time"), Time::try_from(to).expect("time"))
    }
}

pub fn dns(name: &str) -> GeneralName {
    GeneralName::DnsName(Ia5String::new(name).expect("ia5"))
}

pub fn ip(addr: &str) -> GeneralName {
    GeneralName::from(IpAddr::from_str(addr).expect("ip"))
}

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
        let mut exts = vec![(&BasicConstraints { ca: self.ca, path_len_constraint: None }).to_extension(subject, &[])?];
        let usage =
            if self.ca { KeyUsages::KeyCertSign | KeyUsages::CRLSign } else { KeyUsages::DigitalSignature.into() };
        exts.push((&KeyUsage(usage)).to_extension(subject, &[])?);
        if !self.ca {
            exts.push((&ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH])).to_extension(subject, &[])?);
            exts.push((&SubjectAltName(self.sans.clone())).to_extension(subject, &[])?);
        }
        Ok(exts)
    }
}

fn key(label: &str) -> SigningKey {
    SigningKey::from_slice(&Sha256::digest(label.as_bytes())).expect("scalar")
}

fn serial(label: &str) -> SerialNumber {
    let d = Sha256::digest(label.as_bytes());
    SerialNumber::from(u32::from_be_bytes([d[0] & 0x7f, d[1], d[2], d[3]]) | 1)
}

fn build(profile: Profile, label: &str, life: Life, subject_key: SigningKey, signer: &SigningKey) -> Issued {
    let name = profile.subject.clone();
    let spki = SubjectPublicKeyInfo::from_key(subject_key.verifying_key()).expect("spki");
    let builder = CertificateBuilder::new(profile, serial(label), life.validity(), spki).expect("builder");
    let cert = builder.build::<_, DerSignature>(signer).expect("sign");
    Issued { der: CertificateDer::from(cert.to_der().expect("der")), key: subject_key, name }
}

/// A self-signed CA.
pub fn root(label: &str) -> Issued {
    root_living(label, Life::Valid)
}

/// A self-signed CA with this lifetime.
pub fn root_living(label: &str, life: Life) -> Issued {
    let subject = Name::from_str(&format!("CN={label},O=Seal Test,C=US")).expect("name");
    let k = key(label);
    build(Profile { issuer: subject.clone(), subject, ca: true, sans: vec![] }, label, life, k.clone(), &k)
}

/// An intermediate CA under `issuer`.
pub fn intermediate(issuer: &Issued, label: &str) -> Issued {
    intermediate_living(issuer, label, Life::Valid)
}

/// An intermediate CA under `issuer` with this lifetime.
pub fn intermediate_living(issuer: &Issued, label: &str, life: Life) -> Issued {
    let subject = Name::from_str(&format!("CN={label},O=Seal Test,C=US")).expect("name");
    build(
        Profile { issuer: issuer.name.clone(), subject, ca: true, sans: vec![] },
        label,
        life,
        key(label),
        &issuer.key,
    )
}

/// A server certificate under `issuer` with these SANs.
pub fn leaf(issuer: &Issued, label: &str, sans: Vec<GeneralName>, life: Life) -> Issued {
    let subject = Name::from_str(&format!("CN={label}")).expect("name");
    build(Profile { issuer: issuer.name.clone(), subject, ca: false, sans }, label, life, key(label), &issuer.key)
}

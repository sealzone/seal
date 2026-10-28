//! The few X.509 checks the verifiers need, on `x509-cert` with RustCrypto signatures.
//! Signatures are checked over the TBSCertificate bytes exactly as received, never a
//! re-encoding.

use der::{Decode, Encode, Header, Reader, SliceReader};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::signature::Verifier;
use spki::ObjectIdentifier;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage};
use x509_cert::Certificate;

use crate::AttestError;

const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

pub(crate) fn reject(msg: impl Into<String>) -> AttestError {
    AttestError::Rejected(msg.into())
}

/// A parsed certificate with the DER it was parsed from.
pub(crate) struct Cert {
    pub der: Vec<u8>,
    pub cert: Certificate,
}

impl Cert {
    pub fn parse(der: &[u8], what: &str) -> Result<Self, AttestError> {
        let cert = Certificate::from_der(der).map_err(|e| reject(format!("{what}: bad certificate: {e}")))?;
        Ok(Self { der: der.to_vec(), cert })
    }

    /// Certificates of a PEM bundle, in order.
    pub fn parse_pem_chain(pem: &[u8], what: &str) -> Result<Vec<Self>, AttestError> {
        let certs = Certificate::load_pem_chain(pem).map_err(|e| reject(format!("{what}: bad PEM: {e}")))?;
        certs
            .into_iter()
            .map(|cert| {
                let der = cert.to_der().map_err(|e| reject(format!("{what}: {e}")))?;
                Ok(Self { der, cert })
            })
            .collect()
    }

    /// The TBSCertificate exactly as encoded in `der`.
    fn tbs_bytes(&self) -> Result<&[u8], AttestError> {
        let e = |e: der::Error| reject(format!("certificate DER: {e}"));
        let mut r = SliceReader::new(&self.der).map_err(e)?;
        Header::decode(&mut r).map_err(e)?;
        let start = u32::from(r.position()) as usize;
        let tbs = Header::decode(&mut r).map_err(e)?;
        let end = u32::from(r.position()) as usize + u32::from(tbs.length()) as usize;
        self.der.get(start..end).ok_or_else(|| reject("certificate DER: truncated TBSCertificate"))
    }

    /// The raw subjectPublicKey bits.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.cert.tbs_certificate().subject_public_key_info().subject_public_key.raw_bytes()
    }

    fn rsa_public_key(&self) -> Result<rsa::RsaPublicKey, AttestError> {
        rsa::RsaPublicKey::from_pkcs1_der(self.public_key_bytes())
            .map_err(|e| reject(format!("issuer key is not RSA: {e}")))
    }

    pub fn subject_is_issuer_of(&self, subject: &Cert) -> bool {
        subject.cert.tbs_certificate().issuer() == self.cert.tbs_certificate().subject()
    }

    /// Whether `self` signed `subject` with RSASSA-PSS (SHA-384, MGF1-SHA-384, salt 48), the
    /// only scheme AMD's KDS uses.
    pub fn verify_pss_sha384(&self, subject: &Cert) -> Result<(), AttestError> {
        if !self.subject_is_issuer_of(subject) {
            return Err(reject("certificate issuer does not match the signer's subject"));
        }
        if subject.cert.signature_algorithm().oid != RSA_PSS {
            return Err(reject("certificate is not signed with RSASSA-PSS"));
        }
        let vk = rsa::pss::VerifyingKey::<sha2::Sha384>::new(self.rsa_public_key()?);
        let sig = rsa::pss::Signature::try_from(subject.signature_bytes()?)
            .map_err(|e| reject(format!("certificate signature: {e}")))?;
        vk.verify(subject.tbs_bytes()?, &sig).map_err(|_| reject("certificate signature does not verify"))
    }

    /// Whether `self` signed `subject` with RSA PKCS#1 v1.5 over SHA-256, -384 or -512.
    pub fn verify_pkcs1v15(&self, subject: &Cert) -> Result<(), AttestError> {
        if !self.subject_is_issuer_of(subject) {
            return Err(reject("certificate issuer does not match the signer's subject"));
        }
        let key = self.rsa_public_key()?;
        let sig = rsa::pkcs1v15::Signature::try_from(subject.signature_bytes()?)
            .map_err(|e| reject(format!("certificate signature: {e}")))?;
        let tbs = subject.tbs_bytes()?;
        let oid = subject.cert.signature_algorithm().oid;
        let ok = if oid == SHA256_WITH_RSA {
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key).verify(tbs, &sig)
        } else if oid == SHA384_WITH_RSA {
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key).verify(tbs, &sig)
        } else if oid == SHA512_WITH_RSA {
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key).verify(tbs, &sig)
        } else {
            return Err(reject(format!("unsupported certificate signature algorithm {oid}")));
        };
        ok.map_err(|_| reject("certificate signature does not verify"))
    }

    /// Whether `self` signed `subject` with ECDSA P-384 over SHA-384, the only scheme of AWS's
    /// Nitro attestation PKI.
    pub fn verify_ecdsa_p384(&self, subject: &Cert) -> Result<(), AttestError> {
        if !self.subject_is_issuer_of(subject) {
            return Err(reject("certificate issuer does not match the signer's subject"));
        }
        if subject.cert.signature_algorithm().oid != ECDSA_WITH_SHA384 {
            return Err(reject("certificate is not signed with ECDSA SHA-384"));
        }
        let sig = p384::ecdsa::Signature::from_der(subject.signature_bytes()?)
            .map_err(|e| reject(format!("certificate signature: {e}")))?;
        self.p384_public_key()?
            .verify(subject.tbs_bytes()?, &sig)
            .map_err(|_| reject("certificate signature does not verify"))
    }

    pub fn p384_public_key(&self) -> Result<p384::ecdsa::VerifyingKey, AttestError> {
        p384::ecdsa::VerifyingKey::from_sec1_bytes(self.public_key_bytes())
            .map_err(|_| reject("certificate key is not P-384"))
    }

    /// The subject's one common name.
    pub fn common_name(&self) -> Result<String, AttestError> {
        let mut names = self.cert.tbs_certificate().subject().iter().filter(|atv| atv.oid == COMMON_NAME);
        let (Some(cn), None) = (names.next(), names.next()) else {
            return Err(reject("certificate subject does not have exactly one common name"));
        };
        cn.value
            .decode_as::<der::asn1::Utf8StringRef<'_>>()
            .map(|s| s.as_str().to_owned())
            .or_else(|_| cn.value.decode_as::<der::asn1::PrintableStringRef<'_>>().map(|s| s.as_str().to_owned()))
            .map_err(|_| reject("certificate common name is not a string"))
    }

    fn signature_bytes(&self) -> Result<&[u8], AttestError> {
        self.cert.signature().as_bytes().ok_or_else(|| reject("certificate signature has unused bits"))
    }

    /// (notBefore, notAfter) in Unix seconds.
    pub fn validity(&self) -> (u64, u64) {
        let v = self.cert.tbs_certificate().validity();
        (v.not_before.to_unix_duration().as_secs(), v.not_after.to_unix_duration().as_secs())
    }

    /// Valid for the whole interval `[earliest, latest]`.
    pub fn check_valid(&self, earliest: u64, latest: u64, what: &str) -> Result<(), AttestError> {
        let (not_before, not_after) = self.validity();
        if earliest < not_before || latest > not_after {
            return Err(reject(format!("{what} not valid at {earliest}..{latest} (valid {not_before}..{not_after})")));
        }
        Ok(())
    }

    /// The raw `extnValue` contents of extension `oid`.
    pub fn extension(&self, oid: &ObjectIdentifier) -> Option<&[u8]> {
        self.cert.tbs_certificate().extensions()?.iter().find(|e| e.extn_id == *oid).map(|e| e.extn_value.as_bytes())
    }

    pub fn has_eku(&self, oid: &ObjectIdentifier) -> Result<bool, AttestError> {
        match self.cert.tbs_certificate().get_extension::<ExtendedKeyUsage>() {
            Ok(Some((_, eku))) => Ok(eku.0.contains(oid)),
            Ok(None) => Ok(false),
            Err(e) => Err(reject(format!("bad extended key usage: {e}"))),
        }
    }

    pub fn is_ca(&self) -> Result<bool, AttestError> {
        match self.cert.tbs_certificate().get_extension::<BasicConstraints>() {
            Ok(Some((_, bc))) => Ok(bc.ca),
            Ok(None) => Ok(false),
            Err(e) => Err(reject(format!("bad basic constraints: {e}"))),
        }
    }
}

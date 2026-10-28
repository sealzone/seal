//! Upstream certificate verification: webpki against the baked roots, with exactly one
//! name-matching exception, plus the per-blob key pins.

use std::collections::BTreeSet;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, WebPkiServerVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use seal_proto::policy::SpkiPin;
use sha2::{Digest, Sha256};

/// rustls' `WebPkiServerVerifier`, except that a leaf whose only matching DNS SAN carries a
/// single trailing dot (`db.example.sql.goog.`) is accepted for the same name without it, once
/// the chain itself has verified against the same roots. Every other check is webpki's.
#[derive(Debug)]
pub(crate) struct SealVerifier {
    inner: Arc<WebPkiServerVerifier>,
    roots: Arc<RootCertStore>,
    algs: WebPkiSupportedAlgorithms,
}

impl SealVerifier {
    pub(crate) fn new(
        roots: Arc<RootCertStore>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, String> {
        let algs = provider.signature_verification_algorithms;
        let inner =
            WebPkiServerVerifier::builder_with_provider(roots.clone(), provider).build().map_err(|e| e.to_string())?;
        Ok(Self { inner, roots, algs })
    }
}

impl ServerCertVerifier for SealVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => {
                let name_error = || Error::InvalidCertificate(CertificateError::NotValidForName);
                let ServerName::DnsName(reference) = server_name else {
                    return Err(name_error());
                };
                // The chain on its own, against the same roots, with server-auth usage.
                let cert = ParsedCertificate::try_from(end_entity)?;
                verify_server_cert_signed_by_trust_anchor(&cert, &self.roots, intermediates, now, self.algs.all)?;
                if has_dotted_dns_san(end_entity, reference.as_ref()) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(name_error())
                }
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// True when the leaf has a DNS SAN that equals `reference` (ASCII case-insensitively) after
/// removing exactly one trailing dot. No wildcards, no other normalization.
fn has_dotted_dns_san(end_entity: &CertificateDer<'_>, reference: &str) -> bool {
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};

    if reference.is_empty() || reference.ends_with('.') {
        return false;
    }
    let Ok(cert) = x509_cert::Certificate::from_der(end_entity.as_ref()) else {
        return false;
    };
    let Ok(Some((_, SubjectAltName(names)))) = cert.tbs_certificate().get_extension::<SubjectAltName>() else {
        return false;
    };
    names.iter().any(|name| match name {
        GeneralName::DnsName(dns) => {
            dns.as_str().strip_suffix('.').is_some_and(|stripped| stripped.eq_ignore_ascii_case(reference))
        }
        _ => false,
    })
}

/// SHA-256 of a SubjectPublicKeyInfo given its DER contents (what webpki keeps in a
/// `TrustAnchor`): the hash covers the full DER, outer SEQUENCE header included.
fn spki_pin_from_contents(contents: &[u8]) -> SpkiPin {
    let mut h = Sha256::new();
    h.update([0x30]);
    let len = contents.len();
    if len < 0x80 {
        h.update([len as u8]);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        h.update([0x80 | (bytes.len() - skip) as u8]);
        h.update(&bytes[skip..]);
    }
    h.update(contents);
    SpkiPin(h.finalize().into())
}

pub(crate) fn anchor_pin(anchor: &TrustAnchor<'_>) -> SpkiPin {
    spki_pin_from_contents(anchor.subject_public_key_info.as_ref())
}

/// A certificate as a trust anchor (its subject and key), as webpki parses it.
fn cert_as_anchor(cert: &CertificateDer<'_>) -> Option<TrustAnchor<'static>> {
    let mut store = RootCertStore::empty();
    store.add(cert.clone().into_owned()).ok()?;
    store.roots.pop()
}

/// The SPKI pin of a certificate, if webpki can parse it.
pub(crate) fn cert_pin(cert: &CertificateDer<'_>) -> Option<SpkiPin> {
    cert_as_anchor(cert).as_ref().map(anchor_pin)
}

/// Pins narrow the roots: after the chain verified, a pinned key must be on a valid path. The
/// leaf's key counts directly; a pinned intermediate or root counts when the leaf verifies with
/// the presented intermediates against a store holding only pinned keys (presented
/// certificates with a pinned key, and baked roots with a pinned key). A pinned certificate
/// that is merely sent along, off the path, does not count.
pub(crate) fn chain_has_pin(
    presented: &[CertificateDer<'static>],
    roots: &RootCertStore,
    pins: &BTreeSet<SpkiPin>,
    algs: &WebPkiSupportedAlgorithms,
    now: UnixTime,
) -> bool {
    if pins.is_empty() {
        return true;
    }
    let Some((leaf, intermediates)) = presented.split_first() else {
        return false;
    };
    if cert_pin(leaf).is_some_and(|p| pins.contains(&p)) {
        return true;
    }
    let mut pinned = RootCertStore::empty();
    pinned.roots.extend(intermediates.iter().filter_map(cert_as_anchor).filter(|a| pins.contains(&anchor_pin(a))));
    pinned.roots.extend(roots.roots.iter().filter(|a| pins.contains(&anchor_pin(a))).cloned());
    if pinned.is_empty() {
        return false;
    }
    let Ok(cert) = ParsedCertificate::try_from(leaf) else {
        return false;
    };
    verify_server_cert_signed_by_trust_anchor(&cert, &pinned, intermediates, now, algs.all).is_ok()
}

/// RFC 5929 `tls-server-end-point` data for a leaf certificate: its DER hashed with its
/// signature's hash, SHA-256 standing in for MD5 and SHA-1. `None` for a signature algorithm
/// without a single named hash (Ed25519, RSASSA-PSS) or an unparseable certificate.
pub(crate) fn tls_server_end_point(leaf: &rustls::pki_types::CertificateDer<'_>) -> Option<Vec<u8>> {
    use sha2::Digest;
    use x509_cert::der::Decode;

    let cert = x509_cert::Certificate::from_der(leaf.as_ref()).ok()?;
    let der = leaf.as_ref();
    match cert.signature_algorithm().oid.to_string().as_str() {
        // md5WithRSA, sha1WithRSA, sha256WithRSA, ecdsa-with-SHA1, ecdsa-with-SHA256
        "1.2.840.113549.1.1.4"
        | "1.2.840.113549.1.1.5"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.10045.4.1"
        | "1.2.840.10045.4.3.2" => Some(sha2::Sha256::digest(der).to_vec()),
        // sha384WithRSA, ecdsa-with-SHA384
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => Some(sha2::Sha384::digest(der).to_vec()),
        // sha512WithRSA, ecdsa-with-SHA512
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => Some(sha2::Sha512::digest(der).to_vec()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_form_der_length() {
        // 300-byte contents: header 30 82 01 2c.
        let contents = vec![7u8; 300];
        let mut full = vec![0x30, 0x82, 0x01, 0x2c];
        full.extend_from_slice(&contents);
        assert_eq!(spki_pin_from_contents(&contents).0, <[u8; 32]>::from(Sha256::digest(&full)));
        let short = vec![1u8; 89];
        let mut full = vec![0x30, 89];
        full.extend_from_slice(&short);
        assert_eq!(spki_pin_from_contents(&short).0, <[u8; 32]>::from(Sha256::digest(&full)));
    }
}

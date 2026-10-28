//! Secret-holding types. All zeroize on drop; `Debug` prints `<redacted>`.

use std::collections::BTreeSet;

use seal_proto::release::{
    ReleasedKeys, ServiceKeyCertificate, SignedServiceKeyCertificate, SignedTenantWrapKey, TenantWrapKey,
    SERVICE_KEY_CERTIFICATE_LABEL, TENANT_WRAP_KEY_LABEL,
};
use seal_proto::{PlatformId, ServiceKeyVersion, TenantId, TenantKeyVersion, TenantRootId};
use zeroize::Zeroizing;

use crate::kdf::{self, derive32, platform_bytes};
use crate::sign::SigningKey;
use crate::CryptoError;

/// Variable-length secret bytes (an upstream secret, a plaintext payload).
pub struct SecretBytes(zeroize::Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(v: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(v))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// A 256-bit symmetric key or seed.
pub struct Key32(zeroize::Zeroizing<[u8; 32]>);

impl Key32 {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(b))
    }
    /// From released key material; errors unless exactly 32 bytes.
    pub fn from_secret_vec(v: &seal_proto::SecretVec) -> Result<Self, crate::CryptoError> {
        let bytes = v.expose();
        if bytes.len() != 32 {
            return Err(CryptoError::Malformed(format!("expected a 32-byte key, got {} bytes", bytes.len())));
        }
        let mut k = Self::from_bytes([0; 32]);
        k.0.copy_from_slice(bytes);
        Ok(k)
    }
    pub fn generate(rng: &mut impl rand::CryptoRng) -> Self {
        let mut k = Self::from_bytes([0; 32]);
        rng.fill_bytes(k.0.as_mut());
        k
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
    fn to_secret_vec(&self) -> seal_proto::SecretVec {
        seal_proto::SecretVec::new(self.0.to_vec())
    }
}

macro_rules! redacted_debug {
    ($($t:ty),*) => {$(
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, concat!(stringify!($t), "(<redacted>)"))
            }
        }
    )*};
}
redacted_debug!(
    SecretBytes,
    Key32,
    PlatformMasterKey,
    TenantWrappingKey,
    TokenKey,
    IngestKey,
    TelemetryKey,
    EphemeralKey,
    TlsKey,
    TicketKey,
    ChallengeKey,
    ServiceKeys
);

fn x25519_public(secret: &x25519_dalek::StaticSecret) -> seal_proto::PublicKey {
    seal_proto::PublicKey(x25519_dalek::PublicKey::from(secret).to_bytes())
}

fn x25519_from_seed(seed: &Key32) -> x25519_dalek::StaticSecret {
    x25519_dalek::StaticSecret::from(*seed.expose())
}

/// The platform master key. Exists only inside that platform's guardian.
pub struct PlatformMasterKey {
    pub(crate) key: Key32,
    pub platform: PlatformId,
}

/// The five service seeds of one tenant root and service key version, as released.
struct ServiceSeeds {
    token: Key32,
    ingest: Key32,
    telemetry: Key32,
    tls: Key32,
    ticket: Key32,
}

impl PlatformMasterKey {
    /// From the platform root secret the guardian's `KeySource` unseals.
    pub fn from_root_secret(platform: PlatformId, root: &Key32) -> Self {
        Self { key: derive32(root.expose(), kdf::PLATFORM_MASTER_KEY_FROM_ROOT, &[platform_bytes(platform)]), platform }
    }

    fn tenant_seed(&self, tenant: &TenantId, root_id: &TenantRootId, v: TenantKeyVersion) -> Key32 {
        derive32(
            self.key.expose(),
            kdf::TENANT_WRAPPING_KEY,
            &[platform_bytes(self.platform), tenant.as_str().as_bytes(), &root_id.0, &v.0.to_be_bytes()],
        )
    }

    fn service_seed(&self, label: &str, tenant: &TenantId, root_id: &TenantRootId, v: ServiceKeyVersion) -> Key32 {
        derive32(
            self.key.expose(),
            label,
            &[platform_bytes(self.platform), tenant.as_str().as_bytes(), &root_id.0, &v.0.to_be_bytes()],
        )
    }

    fn service_seeds(&self, tenant: &TenantId, root_id: &TenantRootId, v: ServiceKeyVersion) -> ServiceSeeds {
        ServiceSeeds {
            token: self.service_seed(kdf::TOKEN_SEED, tenant, root_id, v),
            ingest: self.service_seed(kdf::INGEST_SEED, tenant, root_id, v),
            telemetry: self.service_seed(kdf::TELEMETRY_SEED, tenant, root_id, v),
            tls: self.service_seed(kdf::TLS_SEED, tenant, root_id, v),
            ticket: self.service_seed(kdf::TICKET_SEED, tenant, root_id, v),
        }
    }

    pub fn tenant_wrapping_key(
        &self,
        tenant: &TenantId,
        root_id: &TenantRootId,
        tenant_key_version: TenantKeyVersion,
    ) -> TenantWrappingKey {
        TenantWrappingKey {
            secret: x25519_from_seed(&self.tenant_seed(tenant, root_id, tenant_key_version)),
            scope: TenantWrappingKeyScope {
                platform: self.platform,
                tenant: tenant.clone(),
                root_id: *root_id,
                tenant_key_version,
            },
        }
    }
    /// The public half of `tenant_wrapping_key`, certified with the guardian key
    /// (`TENANT_WRAP_KEY_LABEL`). Public: the guardian serves it to anyone.
    pub fn tenant_wrap_key(
        &self,
        tenant: &TenantId,
        root_id: &TenantRootId,
        tenant_key_version: TenantKeyVersion,
    ) -> seal_proto::release::SignedTenantWrapKey {
        let body = TenantWrapKey {
            platform: self.platform,
            tenant: tenant.clone(),
            root_id: *root_id,
            tenant_key_version,
            public_key: self.tenant_wrapping_key(tenant, root_id, tenant_key_version).public_key(),
        };
        let signed: SignedTenantWrapKey = self.guardian_key().sign_into(TENANT_WRAP_KEY_LABEL, body);
        signed
    }
    /// `ReleasedKeys::Service` for one tenant's `service_key_version`, with the guardian's
    /// `ServiceKeyCertificate` over its public keys. The telemetry public keys cover versions
    /// 1..=`service_key_version`, one derivation each.
    pub fn release_service(
        &self,
        tenant: &TenantId,
        root_id: &TenantRootId,
        service_key_version: ServiceKeyVersion,
    ) -> ReleasedKeys {
        let seeds = self.service_seeds(tenant, root_id, service_key_version);
        let telemetry_public_keys: Vec<_> = (1..=service_key_version.0)
            .map(|v| {
                let v = ServiceKeyVersion(v);
                let seed = self.service_seed(kdf::TELEMETRY_SEED, tenant, root_id, v);
                (v, SigningKey::from_seed(seed.expose()).public_key())
            })
            .collect();
        let tls = TlsKey::from_seed(&seeds.tls, tenant.clone(), service_key_version);
        let ingest = IngestKey { secret: x25519_from_seed(&seeds.ingest) };
        let certificate = ServiceKeyCertificate {
            platform: self.platform,
            tenant: tenant.clone(),
            root_id: *root_id,
            service_key_version,
            tls_spki_sha256: tls.spki_sha256(),
            ingest_public_key: ingest.public_key(),
            telemetry_public_keys: telemetry_public_keys.clone(),
        };
        ReleasedKeys::Service {
            tenant: tenant.clone(),
            root_id: *root_id,
            service_key_version,
            token: seeds.token.to_secret_vec(),
            ingest: seeds.ingest.to_secret_vec(),
            telemetry: seeds.telemetry.to_secret_vec(),
            tls: seeds.tls.to_secret_vec(),
            ticket: seeds.ticket.to_secret_vec(),
            telemetry_public_keys,
            certificate: self.guardian_key().sign_into(SERVICE_KEY_CERTIFICATE_LABEL, certificate),
        }
    }
    /// `ReleasedKeys::Tenant` for `tenant_key_versions`.
    pub fn release_tenant(
        &self,
        tenant: &TenantId,
        root_id: &TenantRootId,
        tenant_key_versions: &[TenantKeyVersion],
    ) -> ReleasedKeys {
        ReleasedKeys::Tenant {
            tenant: tenant.clone(),
            root_id: *root_id,
            keys: tenant_key_versions
                .iter()
                .map(|v| (*v, self.tenant_seed(tenant, root_id, *v).to_secret_vec()))
                .collect(),
        }
    }
    /// The guardian key: signs `ServiceKeyCertificate`s. Fixed for the platform's life; its
    /// public half is compiled into `seal_verify::Trust::guardians`.
    pub fn guardian_key(&self) -> crate::sign::SigningKey {
        let seed = derive32(self.key.expose(), kdf::GUARDIAN_KEY, &[platform_bytes(self.platform)]);
        SigningKey::from_seed(seed.expose())
    }
    /// MACs this guardian's stateless `GuardianChallenge`s; the same on every instance.
    pub fn challenge_key(&self) -> ChallengeKey {
        ChallengeKey(derive32(self.key.expose(), kdf::GUARDIAN_CHALLENGE_KEY, &[platform_bytes(self.platform)]))
    }
}

/// Wraps and unwraps one tenant's DEKs for one tenant key version (on the master key's platform).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantWrappingKeyScope {
    pub platform: PlatformId,
    pub tenant: TenantId,
    pub root_id: TenantRootId,
    pub tenant_key_version: TenantKeyVersion,
}

/// One tenant's service keys of one version (on the master key's platform). No service key is
/// shared across tenants, so extracting one enclave's keys exposes only its own tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceKeyScope {
    pub platform: PlatformId,
    pub tenant: TenantId,
    pub root_id: TenantRootId,
    pub service_key_version: ServiceKeyVersion,
}

/// The private wrap key: X25519, from HKDF over the platform master key. Its public half is
/// what other platforms' enclaves wrap DEKs to.
pub struct TenantWrappingKey {
    pub(crate) secret: x25519_dalek::StaticSecret,
    pub(crate) scope: TenantWrappingKeyScope,
}

impl TenantWrappingKey {
    pub fn scope(&self) -> &TenantWrappingKeyScope {
        &self.scope
    }
    pub fn public_key(&self) -> seal_proto::PublicKey {
        x25519_public(&self.secret)
    }
    /// One key per tenant key version in `keys`, scoped to `platform`. Errors unless `keys`
    /// is `ReleasedKeys::Tenant` with 32-byte keys and distinct versions.
    pub fn from_released(platform: PlatformId, keys: &ReleasedKeys) -> Result<Vec<Self>, crate::CryptoError> {
        let ReleasedKeys::Tenant { tenant, root_id, keys } = keys else {
            return Err(CryptoError::Malformed("expected tenant keys".into()));
        };
        let mut seen = BTreeSet::new();
        keys.iter()
            .map(|(v, seed)| {
                if !seen.insert(*v) {
                    return Err(CryptoError::Malformed(format!("tenant key version {v} released twice")));
                }
                Ok(Self {
                    secret: x25519_from_seed(&Key32::from_secret_vec(seed)?),
                    scope: TenantWrappingKeyScope {
                        platform,
                        tenant: tenant.clone(),
                        root_id: *root_id,
                        tenant_key_version: *v,
                    },
                })
            })
            .collect()
    }
}

/// Root of session-token keys; each token derives its own AEAD key from a random salt.
pub struct TokenKey {
    pub(crate) seed: Key32,
    pub(crate) service_key_version: ServiceKeyVersion,
}

/// X25519 key pair secrets are HPKE-sealed to.
pub struct IngestKey {
    pub(crate) secret: x25519_dalek::StaticSecret,
}

impl IngestKey {
    pub fn public_key(&self) -> seal_proto::PublicKey {
        x25519_public(&self.secret)
    }
}

/// Ed25519 key that signs telemetry and enclave-issued integrity signals.
pub struct TelemetryKey(pub(crate) crate::sign::SigningKey);

impl TelemetryKey {
    pub fn public_key(&self) -> seal_proto::PublicKey {
        self.0.public_key()
    }
    pub fn signer(&self) -> &crate::sign::SigningKey {
        &self.0
    }
}

/// The inbound TLS identity, derived identically on every replica of a tenant and service key
/// version: the handshake (leaf) key, whose SPKI is what clients pin and proofs bind, and a CA
/// key that signs the leaf certificate. Each P-256 scalar is the first valid one of
/// `HKDF-SHA256(tls seed, info(label, [counter u8]))`, counter from 0, with `TLS_SCALAR` for
/// the leaf and `TLS_CA_SCALAR` for the CA.
pub struct TlsKey {
    pub(crate) secret: p256::SecretKey,
    pub(crate) ca_secret: p256::SecretKey,
    pub(crate) tenant: TenantId,
    pub(crate) service_key_version: ServiceKeyVersion,
}

fn p256_from_seed(seed: &Key32, label: &str) -> p256::SecretKey {
    for counter in 0u8..=u8::MAX {
        let mut scalar = Zeroizing::new([0u8; 32]);
        kdf::expand_into(None, seed.expose(), &kdf::info(label, &[&[counter]]), scalar.as_mut());
        // Fails only for zero or a value ≥ the group order (probability about 2^-32 each).
        if let Ok(secret) = p256::SecretKey::from_slice(scalar.as_ref()) {
            return secret;
        }
    }
    unreachable!("256 consecutive HKDF outputs outside the P-256 scalar range")
}

impl TlsKey {
    pub(crate) fn from_seed(seed: &Key32, tenant: TenantId, service_key_version: ServiceKeyVersion) -> Self {
        Self {
            secret: p256_from_seed(seed, kdf::TLS_SCALAR),
            ca_secret: p256_from_seed(seed, kdf::TLS_CA_SCALAR),
            tenant,
            service_key_version,
        }
    }
    /// PKCS#8 DER private key, for rustls. Zeroized on drop.
    pub fn private_key_pkcs8_der(&self) -> zeroize::Zeroizing<Vec<u8>> {
        use p256::pkcs8::EncodePrivateKey;
        let doc = self.secret.to_pkcs8_der().expect("PKCS#8 encoding of a P-256 key cannot fail");
        Zeroizing::new(doc.as_bytes().to_vec())
    }
    /// SubjectPublicKeyInfo DER.
    pub fn spki_der(&self) -> Vec<u8> {
        use p256::pkcs8::EncodePublicKey;
        self.secret.public_key().to_public_key_der().expect("SPKI encoding of a P-256 key cannot fail").into_vec()
    }
    /// SHA-256 of `spki_der()`: what clients pin and proofs bind.
    pub fn spki_sha256(&self) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(self.spki_der()).into()
    }
    /// The CA certificate, sent after the leaf (clients pin the attested leaf key; the CA only
    /// completes a chain TLS stacks accept): self-signed by the CA key,
    /// CA:true, path length 0, name constraints permitting only `dns_names`, so it cannot vouch
    /// for any other host even if installed as a root. Byte-identical on every replica.
    /// `Malformed` unless `dns_names` is non-empty and every name is ASCII, without wildcards.
    pub fn ca_certificate_der(&self, dns_names: &[String]) -> Result<Vec<u8>, CryptoError> {
        crate::cert::ca(self, dns_names)
    }
    /// The certificate the enclave presents, followed by `ca_certificate_der` in the chain:
    /// the handshake key, CA:false, server authentication, SANs = `dns_names`, signed by the CA
    /// key. Byte-identical on every replica. Same name rules as `ca_certificate_der`.
    pub fn leaf_certificate_der(&self, dns_names: &[String]) -> Result<Vec<u8>, CryptoError> {
        crate::cert::leaf(self, dns_names)
    }
}

/// HMAC key for stateless proof tickets (see `ticket`).
pub struct TicketKey(pub(crate) Key32);

/// HMAC key for the guardian's stateless challenges (see `ticket`).
pub struct ChallengeKey(pub(crate) Key32);

/// Single-use X25519 pair for receiving `ReleasedKeys` from the guardian.
pub struct EphemeralKey(pub(crate) x25519_dalek::StaticSecret);

impl EphemeralKey {
    pub fn generate(rng: &mut impl rand::CryptoRng) -> Self {
        Self(x25519_dalek::StaticSecret::random_from_rng(rng))
    }
    pub fn public_key(&self) -> seal_proto::PublicKey {
        x25519_public(&self.0)
    }
}

/// Everything an app enclave holds after boot: its tenant's service keys (tenant wrapping
/// keys are fetched separately).
pub struct ServiceKeys {
    pub scope: ServiceKeyScope,
    pub token: TokenKey,
    pub ingest: IngestKey,
    pub telemetry: TelemetryKey,
    pub tls: TlsKey,
    pub ticket: TicketKey,
    /// Telemetry public keys of service key versions 1..=`service_key_version`, for verifying
    /// enclave-signed integrity signals (`seal_verify::TenantVerifier::new`).
    pub telemetry_public_keys: Vec<(ServiceKeyVersion, seal_proto::PublicKey)>,
    /// The guardian's certificate over these keys, served in `AttestationResponse`.
    pub certificate: seal_proto::release::SignedServiceKeyCertificate,
}

impl ServiceKeys {
    /// Scoped to `platform` and the tenant the keys name. Errors unless `keys` is
    /// `ReleasedKeys::Service` with 32-byte seeds and a certificate for exactly these keys
    /// (platform, tenant, root, version, TLS SPKI, ingest key, telemetry keys including this
    /// version's). The certificate's signature is not checked here: the keys arrived over the
    /// attested HPKE channel from the guardian, and clients check it against `Trust::guardians`.
    pub fn from_released(platform: PlatformId, keys: &ReleasedKeys) -> Result<Self, crate::CryptoError> {
        let ReleasedKeys::Service {
            tenant,
            root_id,
            service_key_version,
            token,
            ingest,
            telemetry,
            tls,
            ticket,
            telemetry_public_keys,
            certificate,
        } = keys
        else {
            return Err(CryptoError::Malformed("expected service keys".into()));
        };
        let v = *service_key_version;
        let token = TokenKey { seed: Key32::from_secret_vec(token)?, service_key_version: v };
        let ingest = IngestKey { secret: x25519_from_seed(&Key32::from_secret_vec(ingest)?) };
        let telemetry = TelemetryKey(SigningKey::from_seed(Key32::from_secret_vec(telemetry)?.expose()));
        let tls = TlsKey::from_seed(&Key32::from_secret_vec(tls)?, tenant.clone(), v);
        let ticket = TicketKey(Key32::from_secret_vec(ticket)?);

        let expected = ServiceKeyCertificate {
            platform,
            tenant: tenant.clone(),
            root_id: *root_id,
            service_key_version: v,
            tls_spki_sha256: tls.spki_sha256(),
            ingest_public_key: ingest.public_key(),
            telemetry_public_keys: telemetry_public_keys.clone(),
        };
        if certificate.body != expected {
            return Err(CryptoError::Malformed("service key certificate does not match the released keys".into()));
        }
        if !telemetry_public_keys.contains(&(v, telemetry.public_key())) {
            return Err(CryptoError::Malformed("telemetry public keys omit this version's key".into()));
        }
        let certificate: SignedServiceKeyCertificate = certificate.clone();
        Ok(Self {
            scope: ServiceKeyScope { platform, tenant: tenant.clone(), root_id: *root_id, service_key_version: v },
            token,
            ingest,
            telemetry,
            tls,
            ticket,
            telemetry_public_keys: telemetry_public_keys.clone(),
            certificate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign;

    fn tenant() -> TenantId {
        TenantId::new("acme").unwrap()
    }
    fn master(platform: PlatformId) -> PlatformMasterKey {
        PlatformMasterKey::from_root_secret(platform, &Key32::from_bytes([7; 32]))
    }

    #[test]
    fn debug_is_redacted() {
        let k = Key32::from_bytes([0xab; 32]);
        assert_eq!(format!("{k:?}"), "Key32(<redacted>)");
        let s = SecretBytes::new(b"hunter2".to_vec());
        assert!(!format!("{s:?}").contains("hunter2"));
        let m = master(PlatformId::Sim);
        assert_eq!(format!("{m:?}"), "PlatformMasterKey(<redacted>)");
        let keys = m.release_service(&tenant(), &TenantRootId([1; 32]), ServiceKeyVersion(1));
        let sk = ServiceKeys::from_released(PlatformId::Sim, &keys).unwrap();
        assert_eq!(format!("{sk:?}"), "ServiceKeys(<redacted>)");
    }

    #[test]
    fn key32_from_secret_vec_requires_32_bytes() {
        assert!(Key32::from_secret_vec(&seal_proto::SecretVec::new(vec![1; 32])).is_ok());
        for n in [0, 31, 33] {
            let e = Key32::from_secret_vec(&seal_proto::SecretVec::new(vec![9; n])).unwrap_err();
            assert!(matches!(e, CryptoError::Malformed(_)));
        }
    }

    #[test]
    fn derivations_are_scoped() {
        let root = TenantRootId([1; 32]);
        let other_root = TenantRootId([2; 32]);
        let other = TenantId::new("bravo").unwrap();
        let sim = master(PlatformId::Sim);
        let nitro = master(PlatformId::AwsNitro);
        let pk = |m: &PlatformMasterKey, t: &TenantId, r: &TenantRootId, v| {
            m.tenant_wrapping_key(t, r, TenantKeyVersion(v)).public_key()
        };
        let base = pk(&sim, &tenant(), &root, 1);
        assert_eq!(base, pk(&sim, &tenant(), &root, 1));
        for different in [
            pk(&nitro, &tenant(), &root, 1),
            pk(&sim, &other, &root, 1),
            pk(&sim, &tenant(), &other_root, 1),
            pk(&sim, &tenant(), &root, 2),
        ] {
            assert_ne!(base, different);
        }
        assert_ne!(sim.guardian_key().public_key(), nitro.guardian_key().public_key());
        let other_root_master = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([8; 32]));
        assert_ne!(sim.guardian_key().public_key(), other_root_master.guardian_key().public_key());
        assert_ne!(sim.challenge_key().0.expose(), nitro.challenge_key().0.expose());
    }

    #[test]
    fn tenant_wrap_key_is_certified_by_the_guardian_key() {
        let m = master(PlatformId::AzureSnpAci);
        let root = TenantRootId([3; 32]);
        let signed = m.tenant_wrap_key(&tenant(), &root, TenantKeyVersion(4));
        assert_eq!(signed.body.public_key, m.tenant_wrapping_key(&tenant(), &root, TenantKeyVersion(4)).public_key());
        assert_eq!(signed.body.platform, PlatformId::AzureSnpAci);
        sign::verify_threshold(&[m.guardian_key().public_key()], 1, TENANT_WRAP_KEY_LABEL, &signed).unwrap();
    }

    #[test]
    fn released_tenant_keys_match_the_guardian_derivation() {
        let m = master(PlatformId::Sim);
        let root = TenantRootId([3; 32]);
        let versions = [TenantKeyVersion(1), TenantKeyVersion(3)];
        let keys =
            TenantWrappingKey::from_released(PlatformId::Sim, &m.release_tenant(&tenant(), &root, &versions)).unwrap();
        assert_eq!(keys.len(), 2);
        for (k, v) in keys.iter().zip(versions) {
            assert_eq!(k.public_key(), m.tenant_wrapping_key(&tenant(), &root, v).public_key());
            assert_eq!(k.scope(), m.tenant_wrapping_key(&tenant(), &root, v).scope());
        }
        // Wrong kind, duplicate versions, short keys.
        let service = m.release_service(&tenant(), &root, ServiceKeyVersion(1));
        assert!(TenantWrappingKey::from_released(PlatformId::Sim, &service).is_err());
        let dup = m.release_tenant(&tenant(), &root, &[TenantKeyVersion(1), TenantKeyVersion(1)]);
        assert!(TenantWrappingKey::from_released(PlatformId::Sim, &dup).is_err());
        let short = ReleasedKeys::Tenant {
            tenant: tenant(),
            root_id: root,
            keys: vec![(TenantKeyVersion(1), seal_proto::SecretVec::new(vec![0; 31]))],
        };
        assert!(TenantWrappingKey::from_released(PlatformId::Sim, &short).is_err());
    }

    #[test]
    fn released_service_keys_match_their_certificate() {
        let m = master(PlatformId::GcpConfidentialSpace);
        let root = TenantRootId([5; 32]);
        let released = m.release_service(&tenant(), &root, ServiceKeyVersion(3));
        let keys = ServiceKeys::from_released(PlatformId::GcpConfidentialSpace, &released).unwrap();
        let cert = &keys.certificate;
        sign::verify_threshold(&[m.guardian_key().public_key()], 1, SERVICE_KEY_CERTIFICATE_LABEL, cert).unwrap();
        assert_eq!(cert.body.tls_spki_sha256, keys.tls.spki_sha256());
        assert_eq!(cert.body.ingest_public_key, keys.ingest.public_key());
        assert_eq!(keys.telemetry_public_keys.len(), 3);
        assert_eq!(keys.telemetry_public_keys[2], (ServiceKeyVersion(3), keys.telemetry.public_key()));
        // Older versions' telemetry keys are the keys those versions release.
        let v1 = ServiceKeys::from_released(
            PlatformId::GcpConfidentialSpace,
            &m.release_service(&tenant(), &root, ServiceKeyVersion(1)),
        )
        .unwrap();
        assert_eq!(keys.telemetry_public_keys[0], (ServiceKeyVersion(1), v1.telemetry.public_key()));
        assert_ne!(v1.tls.spki_sha256(), keys.tls.spki_sha256());
        assert_eq!(keys.scope.service_key_version, ServiceKeyVersion(3));

        // Scoped to a different platform than the certificate names.
        assert!(ServiceKeys::from_released(PlatformId::Sim, &released).is_err());
        // A certificate for other keys.
        let ReleasedKeys::Service {
            tenant: t,
            root_id,
            service_key_version,
            token,
            ingest,
            telemetry,
            tls,
            ticket,
            telemetry_public_keys,
            ..
        } = &released
        else {
            unreachable!()
        };
        let ReleasedKeys::Service { certificate: other_cert, .. } =
            m.release_service(&tenant(), &TenantRootId([6; 32]), ServiceKeyVersion(3))
        else {
            unreachable!()
        };
        let swapped = ReleasedKeys::Service {
            tenant: t.clone(),
            root_id: *root_id,
            service_key_version: *service_key_version,
            token: token.duplicate(),
            ingest: ingest.duplicate(),
            telemetry: telemetry.duplicate(),
            tls: tls.duplicate(),
            ticket: ticket.duplicate(),
            telemetry_public_keys: telemetry_public_keys.clone(),
            certificate: other_cert,
        };
        assert!(ServiceKeys::from_released(PlatformId::GcpConfidentialSpace, &swapped).is_err());
        // Wrong kind.
        assert!(ServiceKeys::from_released(PlatformId::Sim, &m.release_tenant(&tenant(), &root, &[])).is_err());
    }

    #[test]
    fn tls_key_encodings() {
        let k = TlsKey::from_seed(&Key32::from_bytes([1; 32]), tenant(), ServiceKeyVersion(1));
        use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
        let back = p256::SecretKey::from_pkcs8_der(&k.private_key_pkcs8_der()).unwrap();
        assert_eq!(back.to_bytes(), k.secret.to_bytes());
        let public = p256::PublicKey::from_public_key_der(&k.spki_der()).unwrap();
        assert_eq!(public, k.secret.public_key());
    }

    #[test]
    fn ephemeral_keys_are_random() {
        let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
        assert_ne!(EphemeralKey::generate(&mut rng).public_key(), EphemeralKey::generate(&mut rng).public_key());
        assert_ne!(Key32::generate(&mut rng).expose(), Key32::generate(&mut rng).expose());
    }
}

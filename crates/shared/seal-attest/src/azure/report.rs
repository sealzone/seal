//! The SEV-SNP ATTESTATION_REPORT (AMD SEV-SNP ABI, publication 56860, "ATTESTATION_REPORT
//! Structure") and its VCEK (AMD VCEK certificate and KDS interface, publication 57230),
//! checked offline against the baked AMD roots.

use std::collections::BTreeMap;

use der::Decode;
use p384::ecdsa::signature::Verifier;
use spki::ObjectIdentifier;

use crate::x509::{reject, Cert};
use crate::AttestError;

const REPORT_LEN: usize = 0x4A0;
/// The signature covers bytes `0..0x2A0`.
const SIGNED_LEN: usize = 0x2A0;
/// Guest policy bit 19: debugging allowed.
const POLICY_DEBUG: u64 = 1 << 19;
/// `sig_algo` 1: ECDSA P-384 with SHA-384.
const SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;

/// AMD chip families with a baked ARK and ASK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    Milan,
    Genoa,
    Turin,
}

const FAMILIES: [Family; 3] = [Family::Milan, Family::Genoa, Family::Turin];

impl Family {
    /// `cert_chain` from AMD's KDS (ASK, then ARK); see `roots/README.md`.
    fn baked_chain(self) -> &'static str {
        match self {
            Family::Milan => include_str!("../../roots/milan_cert_chain.pem"),
            Family::Genoa => include_str!("../../roots/genoa_cert_chain.pem"),
            Family::Turin => include_str!("../../roots/turin_cert_chain.pem"),
        }
    }

    /// From the report's CPUID family and model (report version 3 and later). Bergamo and
    /// Siena (Genoa models 0xA0..=0xAF) use the Genoa keys.
    fn from_cpuid(family: u8, model: u8) -> Option<Self> {
        match (family, model) {
            (0x19, 0x00..=0x0F) => Some(Family::Milan),
            (0x19, 0x10..=0x1F | 0xA0..=0xAF) => Some(Family::Genoa),
            (0x1A, 0x00..=0x11) => Some(Family::Turin),
            _ => None,
        }
    }

    /// Length of the VCEK's hwID: the whole 64-byte CHIP_ID before Turin, 8 bytes from Turin
    /// on (the rest of CHIP_ID is zero).
    fn hwid_len(self) -> usize {
        match self {
            Family::Milan | Family::Genoa => 64,
            Family::Turin => 8,
        }
    }

    /// REPORTED_TCB as named components with their VCEK extension. Never compared as a packed
    /// integer: AMD reorders the bytes between generations.
    fn decode_tcb(self, raw: u64) -> Vec<(&'static str, u64, ObjectIdentifier)> {
        let b = raw.to_le_bytes().map(u64::from);
        match self {
            Family::Milan | Family::Genoa => vec![
                ("bootloader", b[0], OID_BOOTLOADER),
                ("tee", b[1], OID_TEE),
                ("snp", b[6], OID_SNP),
                ("microcode", b[7], OID_MICROCODE),
            ],
            Family::Turin => vec![
                ("fmc", b[0], OID_FMC),
                ("bootloader", b[1], OID_BOOTLOADER),
                ("tee", b[2], OID_TEE),
                ("snp", b[3], OID_SNP),
                ("microcode", b[7], OID_MICROCODE),
            ],
        }
    }
}

// VCEK extensions (publication 57230, "VCEK Certificate Extensions").
const OID_BOOTLOADER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.1");
const OID_TEE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.2");
const OID_SNP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.3");
const OID_MICROCODE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.8");
const OID_FMC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.9");
const OID_HWID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.4");

/// Fields at fixed offsets of a report of exactly `REPORT_LEN` bytes.
struct Report<'a>(&'a [u8; REPORT_LEN]);

impl Report<'_> {
    fn u32(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0[at..at + 4].try_into().expect("4 bytes"))
    }
    fn u64(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.0[at..at + 8].try_into().expect("8 bytes"))
    }
    fn version(&self) -> u32 {
        self.u32(0x00)
    }
    fn policy(&self) -> u64 {
        self.u64(0x08)
    }
    fn vmpl(&self) -> u32 {
        self.u32(0x30)
    }
    fn sig_algo(&self) -> u32 {
        self.u32(0x34)
    }
    /// Bit 1: MASK_CHIP_ID. Bits 4:2: SIGNING_KEY (0 = VCEK, 1 = VLEK, 7 = none).
    fn key_info(&self) -> u32 {
        self.u32(0x48)
    }
    fn report_data(&self) -> &[u8] {
        &self.0[0x50..0x90]
    }
    fn measurement(&self) -> [u8; 48] {
        self.0[0x90..0xC0].try_into().expect("48 bytes")
    }
    fn host_data(&self) -> [u8; 32] {
        self.0[0xC0..0xE0].try_into().expect("32 bytes")
    }
    fn reported_tcb(&self) -> u64 {
        self.u64(0x180)
    }
    /// CPUID_FAM_ID and CPUID_MOD_ID, present from version 3.
    fn cpuid(&self) -> Option<(u8, u8)> {
        (self.version() >= 3).then(|| (self.0[0x188], self.0[0x189]))
    }
    fn chip_id(&self) -> &[u8] {
        &self.0[0x1A0..0x1E0]
    }

    /// R and S are 72-byte little-endian fields; P-384 uses the low 48 bytes of each.
    fn signature(&self) -> Result<p384::ecdsa::Signature, AttestError> {
        let r = &self.0[0x2A0..0x2E8];
        let s = &self.0[0x2E8..0x330];
        if r[48..].iter().chain(&s[48..]).any(|b| *b != 0) {
            return Err(reject("report signature component wider than P-384"));
        }
        let mut be = [0u8; 96];
        be[..48].copy_from_slice(&r[..48]);
        be[48..].copy_from_slice(&s[..48]);
        be[..48].reverse();
        be[48..].reverse();
        p384::ecdsa::Signature::from_slice(&be).map_err(|_| reject("malformed report signature"))
    }
}

/// What a verified report says.
#[derive(Debug)]
pub(crate) struct Hardware {
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub report_data: [u8; 32],
    pub tcb: BTreeMap<String, u64>,
}

/// Checks `report` and its VCEK against the baked AMD roots at `[earliest, latest]`.
pub(crate) fn verify(report: &[u8], vcek_der: &[u8], earliest: u64, latest: u64) -> Result<Hardware, AttestError> {
    let bytes: &[u8; REPORT_LEN] =
        report.try_into().map_err(|_| reject(format!("report is {} bytes, expected {REPORT_LEN}", report.len())))?;
    let r = Report(bytes);

    // The report's own claims. Checked first: none of them needs the chain.
    if r.version() < 2 {
        return Err(reject(format!("report version {} is not supported", r.version())));
    }
    if r.sig_algo() != SIG_ALGO_ECDSA_P384_SHA384 {
        return Err(reject(format!("report sig_algo {} is not ECDSA P-384", r.sig_algo())));
    }
    if (r.key_info() >> 2) & 7 != 0 {
        return Err(reject("report is not signed by a VCEK"));
    }
    if r.policy() & POLICY_DEBUG != 0 {
        return Err(AttestError::DebugMode);
    }
    if r.vmpl() != 0 {
        return Err(reject(format!("report VMPL is {}, expected 0", r.vmpl())));
    }
    if r.key_info() & 2 != 0 || r.chip_id().iter().all(|b| *b == 0) {
        return Err(reject("report CHIP_ID is masked"));
    }
    let report_data = r.report_data();
    if report_data[32..].iter().any(|b| *b != 0) {
        return Err(reject("report_data bytes 32..64 are not zero"));
    }

    // ARK → ASK → VCEK. The family is the one whose baked ASK signed the VCEK.
    let vcek = Cert::parse(vcek_der, "VCEK")?;
    let (family, ark, ask) = FAMILIES
        .into_iter()
        .find_map(|family| {
            let chain = baked_chain(family);
            chain.1.verify_pss_sha384(&vcek).is_ok().then_some((family, chain.0, chain.1))
        })
        .ok_or_else(|| reject("VCEK is not signed by a known AMD ASK"))?;
    ark.verify_pss_sha384(&ark).map_err(|e| reject(format!("ARK: {e}")))?;
    ark.verify_pss_sha384(&ask).map_err(|e| reject(format!("ASK: {e}")))?;
    for (cert, what) in [(&ark, "ARK"), (&ask, "ASK"), (&vcek, "VCEK")] {
        cert.check_valid(earliest, latest, what)?;
    }
    if let Some((cpu_family, model)) = r.cpuid() {
        let cpu = Family::from_cpuid(cpu_family, model)
            .ok_or_else(|| reject(format!("report CPUID family {cpu_family:#x} model {model:#x} is not supported")))?;
        if cpu != family {
            return Err(reject(format!("report CPUID is {cpu:?} but the VCEK is {family:?}")));
        }
    }

    // The VCEK is this chip's key at this REPORTED_TCB.
    let components = family.decode_tcb(r.reported_tcb());
    for (name, value, oid) in &components {
        let ext = vcek.extension(oid).ok_or_else(|| reject(format!("VCEK has no {name} extension")))?;
        let in_cert = u8::from_der(ext).map_err(|_| reject(format!("VCEK {name} extension malformed")))?;
        if u64::from(in_cert) != *value {
            return Err(reject(format!("VCEK {name} {in_cert} does not match REPORTED_TCB {value}")));
        }
    }
    let hwid = vcek.extension(&OID_HWID).ok_or_else(|| reject("VCEK has no hwID extension"))?;
    let (chip, padding) = r.chip_id().split_at(family.hwid_len());
    if hwid != chip || padding.iter().any(|b| *b != 0) {
        return Err(reject("VCEK hwID does not match report CHIP_ID"));
    }

    // The signature, over the report bytes as received.
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(vcek.public_key_bytes())
        .map_err(|_| reject("VCEK key is not P-384"))?;
    key.verify(&bytes[..SIGNED_LEN], &r.signature()?).map_err(|_| reject("report signature does not verify"))?;

    Ok(Hardware {
        measurement: r.measurement(),
        host_data: r.host_data(),
        report_data: report_data[..32].try_into().expect("32 bytes"),
        tcb: components.into_iter().map(|(name, value, _)| (name.to_owned(), value)).collect(),
    })
}

/// (ARK, ASK) for `family`. The PEM is baked, so a parse failure is a build defect.
/// The baked ASK and ARK (PEM, ASK first) of the family whose ASK signed `vcek_der`.
pub(crate) fn chain_pem_for(vcek_der: &[u8]) -> Option<&'static str> {
    let vcek = Cert::parse(vcek_der, "VCEK").ok()?;
    FAMILIES.into_iter().find(|family| baked_chain(*family).1.verify_pss_sha384(&vcek).is_ok()).map(Family::baked_chain)
}

fn baked_chain(family: Family) -> (Cert, Cert) {
    let mut certs =
        Cert::parse_pem_chain(family.baked_chain().as_bytes(), "baked AMD chain").expect("baked AMD chain parses");
    assert_eq!(certs.len(), 2, "baked AMD chain is ASK then ARK");
    let ark = certs.pop().expect("ARK");
    let ask = certs.pop().expect("ASK");
    (ark, ask)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn baked_roots() {
        let expected = [
            (Family::Milan, "22e62f8d2c21a156470145fc75f7b5a377cb053ced3e97f0bd3f8d8ca5941ce6"),
            (Family::Genoa, "e6ecc853fa56d3170a624d40851f98a1036f974b50204ea69e6aec91d777aca3"),
            (Family::Turin, "cc9a52fbed3fbc6e4a0a50149a541a75938f975658909c2a6084767829b36e85"),
        ];
        for (family, sha256) in expected {
            assert_eq!(hex::encode(Sha256::digest(family.baked_chain())), sha256, "{family:?}");
            let (ark, ask) = baked_chain(family);
            ark.verify_pss_sha384(&ark).unwrap();
            ark.verify_pss_sha384(&ask).unwrap();
            let name = format!("{family:?}");
            assert!(ark.cert.tbs_certificate().subject().to_string().contains(&format!("CN=ARK-{name}")));
            assert!(ask.cert.tbs_certificate().subject().to_string().contains(&format!("CN=SEV-{name}")));
        }
    }

    #[test]
    fn baked_roots_do_not_cross_sign() {
        for a in FAMILIES {
            for b in FAMILIES {
                if a != b {
                    assert!(baked_chain(a).0.verify_pss_sha384(&baked_chain(b).1).is_err());
                }
            }
        }
    }

    #[test]
    fn cpuid_families() {
        assert_eq!(Family::from_cpuid(0x19, 0x01), Some(Family::Milan));
        assert_eq!(Family::from_cpuid(0x19, 0x11), Some(Family::Genoa));
        assert_eq!(Family::from_cpuid(0x19, 0xA0), Some(Family::Genoa));
        assert_eq!(Family::from_cpuid(0x1A, 0x02), Some(Family::Turin));
        assert_eq!(Family::from_cpuid(0x19, 0x20), None);
        assert_eq!(Family::from_cpuid(0x17, 0x31), None);
    }

    #[test]
    fn tcb_layout_per_family() {
        let raw = u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let names = |f: Family| f.decode_tcb(raw).into_iter().map(|(n, v, _)| (n, v)).collect::<BTreeMap<_, _>>();
        let milan = BTreeMap::from([("bootloader", 1), ("tee", 2), ("snp", 7), ("microcode", 8)]);
        assert_eq!(names(Family::Milan), milan);
        assert_eq!(names(Family::Genoa), milan);
        let turin = BTreeMap::from([("fmc", 1), ("bootloader", 2), ("tee", 3), ("snp", 4), ("microcode", 8)]);
        assert_eq!(names(Family::Turin), turin);
    }
}

//! The report and endorsement checks on their own, against the vectors in `tests/data`
//! (sources in `tests/data/README.md`). Whole-evidence tests are in `tests/azure.rs`.

use std::collections::BTreeMap;

use ciborium::Value;
use coset::{CoseSign1, Label, TaggedCborSerializable};

use super::endorsement::{self, Endorsement};
use super::report::{self, Hardware};
use crate::x509::Cert;
use crate::AttestError;

/// 2026-10-26T07:33:20Z: every test VCEK is valid.
const NOW: u64 = 1_793_000_000;

macro_rules! data {
    ($path:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $path)).as_slice()
    };
}

const MILAN: &[u8] = data!("ccf/milan_attestation.bin");
const GENOA: &[u8] = data!("ccf/genoa_attestation.bin");
const TURIN: &[u8] = data!("ccf/turin_attestation.bin");
const MILAN_V2: &[u8] = data!("ccf/v2_format_milan_attestation.bin");
const MILAN_V2_VCEK: &[u8] = data!("kds/v2_milan_vcek.der");
const VIRTEE_VCEK: &[u8] = data!("virtee/vcek_milan.der");

/// The VCEK of a `[VCEK, ASK, ARK]` PEM bundle.
fn vcek(pem: &[u8]) -> Vec<u8> {
    Cert::parse_pem_chain(pem, "test").unwrap().remove(0).der
}
fn milan_vcek() -> Vec<u8> {
    vcek(data!("ccf/milan_endorsements.pem"))
}
fn genoa_vcek() -> Vec<u8> {
    vcek(data!("ccf/genoa_endorsements.pem"))
}
fn turin_vcek() -> Vec<u8> {
    vcek(data!("ccf/turin_endorsements.pem"))
}

fn hw(report: &[u8], vcek: &[u8]) -> Result<Hardware, AttestError> {
    report::verify(report, vcek, NOW, NOW)
}

fn tcb(entries: &[(&str, u64)]) -> BTreeMap<String, u64> {
    entries.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

fn hex48(s: &str) -> [u8; 48] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[track_caller]
fn assert_rejected<T: std::fmt::Debug>(r: Result<T, AttestError>, needle: &str) {
    match r {
        Err(AttestError::Rejected(msg)) => {
            assert!(msg.contains(needle), "{msg:?} does not mention {needle:?}")
        }
        other => panic!("expected a rejection mentioning {needle:?}, got {other:?}"),
    }
}

fn tampered(report: &[u8], f: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut r = report.to_vec();
    f(&mut r);
    r
}

// --- real reports ---

const CCF_HOST_DATA: &str = "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10";

#[test]
fn milan_report() {
    let h = hw(MILAN, &milan_vcek()).unwrap();
    assert_eq!(h.tcb, tcb(&[("milan.bootloader", 4), ("milan.tee", 0), ("milan.snp", 24), ("milan.microcode", 219)]));
    assert_eq!(
        h.measurement,
        hex48("5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887920ab2fa0096903a0c23fca1")
    );
    assert_eq!(h.host_data, hex32(CCF_HOST_DATA));
    assert_eq!(h.report_data, [0; 32]);
}

#[test]
fn genoa_report() {
    let h = hw(GENOA, &genoa_vcek()).unwrap();
    assert_eq!(h.tcb, tcb(&[("genoa.bootloader", 10), ("genoa.tee", 0), ("genoa.snp", 23), ("genoa.microcode", 84)]));
    assert_eq!(h.host_data, hex32(CCF_HOST_DATA));
}

#[test]
fn turin_report() {
    let h = hw(TURIN, &turin_vcek()).unwrap();
    assert_eq!(
        h.tcb,
        tcb(&[("turin.fmc", 1), ("turin.bootloader", 1), ("turin.tee", 1), ("turin.snp", 4), ("turin.microcode", 81)])
    );
    assert_eq!(
        h.measurement,
        hex48("6d6c354511d6f7c6d7504668903dc5bdc066a048b651840d8d03fb85299ebfa142fccf1d1b0baca496841bdf243619d4")
    );
    assert_eq!(h.host_data, hex32("b3452a0ed30f1010bd32740dd1610bc63296ceb0f882f2cac3a3152d651fe7e4"));
}

#[test]
fn version_2_report_without_cpuid() {
    let h = hw(MILAN_V2, MILAN_V2_VCEK).unwrap();
    // CURRENT_TCB differs (microcode 0xD2); REPORTED_TCB is what the VCEK certifies.
    assert_eq!(h.tcb, tcb(&[("milan.bootloader", 3), ("milan.tee", 0), ("milan.snp", 8), ("milan.microcode", 115)]));
    assert_eq!(h.report_data, hex32("7a6a68c0a2b85b8aae00ca04f644831680222f44167e5558a9e072b70c60e958"));
}

// --- the VCEK ---

#[test]
fn vcek_of_another_family_is_rejected() {
    assert_rejected(hw(MILAN, &genoa_vcek()), "CPUID is Milan but the VCEK is Genoa");
    assert_rejected(hw(GENOA, &turin_vcek()), "CPUID is Genoa but the VCEK is Turin");
    assert_rejected(hw(TURIN, &milan_vcek()), "CPUID is Turin but the VCEK is Milan");
    // Version 2 has no CPUID: the Genoa VCEK fails the binding, then the signature would.
    assert!(hw(MILAN_V2, &genoa_vcek()).is_err());
}

#[test]
fn the_chain_for_a_vcek_is_its_family_s() {
    for (vcek, ask) in [(milan_vcek(), "SEV-Milan"), (genoa_vcek(), "SEV-Genoa"), (turin_vcek(), "SEV-Turin")] {
        let pem = super::amd_chain_pem(&vcek).unwrap();
        let certs = Cert::parse_pem_chain(pem.as_bytes(), "chain").unwrap();
        assert_eq!(certs.len(), 2);
        assert!(certs[0].verify_pss_sha384(&Cert::parse(&vcek, "VCEK").unwrap()).is_ok(), "{ask}");
    }
    assert!(super::amd_chain_pem(b"not a certificate").is_none());
}

#[test]
fn vcek_of_another_chip_is_rejected() {
    // Same family and same TCB, different chip.
    assert_rejected(hw(MILAN_V2, VIRTEE_VCEK), "hwID");
}

#[test]
fn vcek_of_other_firmware_is_rejected() {
    // The v2 chip's VCEK certifies bootloader 3; the CCF Milan report has REPORTED_TCB 4.
    assert_rejected(hw(MILAN, MILAN_V2_VCEK), "bootloader 3 does not match REPORTED_TCB 4");
    // REPORTED_TCB rewritten to look newer than the VCEK.
    let r = tampered(MILAN_V2, |r| r[0x187] = 0xFF);
    assert_rejected(hw(&r, MILAN_V2_VCEK), "microcode 115 does not match REPORTED_TCB 255");
}

#[test]
fn vcek_not_signed_by_amd_is_rejected() {
    let mut forged = MILAN_V2_VCEK.to_vec();
    let n = forged.len();
    forged[n - 10] ^= 1;
    assert_rejected(hw(MILAN_V2, &forged), "not signed by a known AMD ASK");
    assert_rejected(hw(MILAN_V2, b"not a certificate"), "VCEK");
    // An AMD ASK is not a VCEK.
    let ask = Cert::parse_pem_chain(include_bytes!("../../roots/milan_cert_chain.pem"), "t").unwrap();
    assert_rejected(hw(MILAN_V2, &ask[0].der), "not signed by a known AMD ASK");
}

#[test]
fn chain_is_checked_at_time() {
    // The v2 VCEK is valid from 2026-10-26T00:19:34Z (1792973974) to 2033-10-26.
    assert_rejected(report::verify(MILAN_V2, MILAN_V2_VCEK, 2_208_988_800, 2_208_988_800), "VCEK not valid");
    assert_rejected(report::verify(MILAN_V2, MILAN_V2_VCEK, 1_792_973_973, NOW), "VCEK not valid");
    assert!(report::verify(MILAN_V2, MILAN_V2_VCEK, 1_792_973_974, NOW).is_ok());
    // Past the ARK's lifetime (2045) too.
    assert_rejected(report::verify(MILAN, &milan_vcek(), 2_400_000_000, 2_400_000_000), "not valid");
}

// --- the report ---

#[test]
fn tampered_report_is_rejected() {
    for at in [0x50, 0x90, 0xC0, 0x1E0, 0x29F] {
        let r = tampered(MILAN, |r| r[at] ^= 1);
        assert_rejected(hw(&r, &milan_vcek()), "report signature does not verify");
    }
    let r = tampered(MILAN, |r| r[0x2A0] ^= 1);
    assert_rejected(hw(&r, &milan_vcek()), "report signature");
    let r = tampered(MILAN, |r| r[0x2A0 + 60] = 1);
    assert_rejected(hw(&r, &milan_vcek()), "wider than P-384");
    assert_rejected(hw(&MILAN[..0x49F], &milan_vcek()), "report is 1183 bytes");
    assert_rejected(hw(&[MILAN, &[0]].concat(), &milan_vcek()), "report is 1185 bytes");
}

#[test]
fn debug_policy_is_refused() {
    let r = tampered(MILAN, |r| r[0x0A] |= 0x08);
    assert!(matches!(hw(&r, &milan_vcek()), Err(AttestError::DebugMode)));
}

#[test]
fn migration_agent_policy_is_refused() {
    let r = tampered(MILAN, |r| r[0x0A] |= 0x04);
    assert_rejected(hw(&r, &milan_vcek()), "migration agent");
}

#[test]
fn vmpl_other_than_0_is_refused() {
    for vmpl in [1u32, 3, 0xFFFF_FFFF] {
        let r = tampered(MILAN, |r| r[0x30..0x34].copy_from_slice(&vmpl.to_le_bytes()));
        assert_rejected(hw(&r, &milan_vcek()), "VMPL");
    }
}

#[test]
fn masked_chip_id_is_refused() {
    let r = tampered(MILAN, |r| r[0x1A0..0x1E0].fill(0));
    assert_rejected(hw(&r, &milan_vcek()), "CHIP_ID is masked");
    let r = tampered(MILAN, |r| r[0x48] |= 2);
    assert_rejected(hw(&r, &milan_vcek()), "CHIP_ID is masked");
}

#[test]
fn non_zero_upper_report_data_is_refused() {
    // A real Milan report (virtee/sev) committing to 64 bytes.
    let report = hex::decode(data!("virtee/report_milan.hex").trim_ascii()).unwrap();
    assert_rejected(hw(&report, VIRTEE_VCEK), "report_data bytes 32..64 are not zero");
    let r = tampered(MILAN, |r| r[0x8F] = 1);
    assert_rejected(hw(&r, &milan_vcek()), "report_data bytes 32..64");
}

#[test]
fn other_signing_setups_are_refused() {
    let r = tampered(MILAN, |r| r[0x34] = 2);
    assert_rejected(hw(&r, &milan_vcek()), "sig_algo 2");
    let r = tampered(MILAN, |r| r[0x48] |= 1 << 2); // VLEK
    assert_rejected(hw(&r, &milan_vcek()), "not signed by a VCEK");
    let r = tampered(MILAN, |r| r[0] = 1);
    assert_rejected(hw(&r, &milan_vcek()), "version 1");
}

#[test]
fn cpuid_must_name_a_known_family() {
    let r = tampered(MILAN, |r| r[0x189] = 0x11);
    assert_rejected(hw(&r, &milan_vcek()), "CPUID is Genoa but the VCEK is Milan");
    let r = tampered(MILAN, |r| r[0x188] = 0x17);
    assert_rejected(hw(&r, &milan_vcek()), "not supported");
}

// --- the UVM endorsement ---

const UVM_0_2_9: &[u8] = data!("ccf/uvm_0.2.9.cose");
const UVM_0_2_10: &[u8] = data!("ccf/uvm_0.2.10.cose");
const CONF_AKS: &[u8] = data!("ccf/ecdsa_test1.cose");

fn uvm(bytes: &[u8]) -> Result<Endorsement, AttestError> {
    endorsement::verify_raw(bytes)
}

#[test]
fn legacy_endorsements() {
    let cases: [(&[u8], u64, &str, u64); 4] = [
        (
            UVM_0_2_9,
            103,
            "d0c9e2be22046e60779be88868cff64c2aa22047c15d3127ba495cee3fbc2854c5633f9da2096e6c64ae2b69bbff8082",
            1_759_253_046,
        ),
        (
            data!("ccf/int_svn.cose"),
            102,
            "d0c9e2be22046e60779be88868cff64c2aa22047c15d3127ba495cee3fbc2854c5633f9da2096e6c64ae2b69bbff8082",
            1_753_124_023,
        ),
        (
            data!("ccf/rsa_test1.cose"),
            100,
            "02c3b0d5bf1d256fa4e3b5deefc07b55ff2f7029085ed350f60959140a1a51f1310753ba5ab2c03a0536b1c0c193af47",
            1_699_989_632,
        ),
        // guestsvn as a string only, without guestsvn-int.
        (
            data!("aci/body.uvm_reference_info.bin"),
            22,
            "51068107cdc7ee3d89c7821b05bca6147eb77b2005ae759050fc049b65a1b0beabc65a9d857acecf23225f5ec76849f5",
            1_675_834_943,
        ),
    ];
    for (bytes, svn, m, signed_at) in cases {
        assert_eq!(uvm(bytes).unwrap(), Endorsement { launch_measurement: hex48(m), svn, signed_at });
    }
}

#[test]
fn cwt_endorsement() {
    assert_eq!(
        uvm(UVM_0_2_10).unwrap(),
        Endorsement {
            launch_measurement: hex48(
                "4904167aa9102a7557b97ac102469f50289d5be76036fcbb8107897ee146a6184772c4ea6e3f050a1bac6951c285bc89"
            ),
            svn: 104,
            signed_at: 1_766_437_887,
        }
    );
}

#[test]
fn endorsement_is_base64() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(UVM_0_2_10);
    assert_eq!(endorsement::verify(&b64).unwrap().svn, 104);
    assert_eq!(endorsement::verify(&format!("{b64}\n")).unwrap().svn, 104);
    assert_rejected(endorsement::verify("not base64!"), "not base64");
    assert_rejected(endorsement::verify("AAAA"), "not a COSE_Sign1");
}

#[test]
fn conf_aks_endorsement_is_refused() {
    // Same root, but the ConfAKS EKU and feed.
    assert_rejected(uvm(CONF_AKS), "issuer did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.5 is not trusted");
    // Claiming the ContainerPlat issuer and feed does not help: its leaf lacks the EKU.
    let forged = with_protected(CONF_AKS, |h| {
        set_text(h, "iss", endorsement::TRUSTED_ISSUER);
        set_text(h, "feed", endorsement::TRUSTED_FEED);
    });
    assert_rejected(uvm(&forged), "lacks the did:x509 EKU");
}

#[test]
fn tampered_endorsement_is_refused() {
    for original in [UVM_0_2_9, UVM_0_2_10] {
        let mut sign1 = CoseSign1::from_tagged_slice(original).unwrap();
        sign1.signature[10] ^= 1;
        assert_rejected(uvm(&sign1.to_tagged_vec().unwrap()), "signature does not verify");

        let mut sign1 = CoseSign1::from_tagged_slice(original).unwrap();
        let payload = sign1.payload.as_mut().unwrap();
        let last = payload.len() - 2;
        payload[last] ^= 1;
        assert_rejected(uvm(&sign1.to_tagged_vec().unwrap()), "signature does not verify");

        // Re-encoding the protected header with any change breaks the signature.
        let forged = with_protected(original, |h| h.rest.push((Label::Text("x".into()), Value::from(1))));
        assert_rejected(uvm(&forged), "signature does not verify");
    }
}

#[test]
fn endorsement_issuer_and_feed_are_exact() {
    let forged =
        with_protected(UVM_0_2_9, |h| set_text(h, "iss", &format!("{}::eku:1.2.3", endorsement::TRUSTED_ISSUER)));
    assert_rejected(uvm(&forged), "is not trusted");
    let forged = with_protected(UVM_0_2_9, |h| set_text(h, "feed", "ContainerPlat-AMD-UVM-test"));
    assert_rejected(uvm(&forged), "feed ContainerPlat-AMD-UVM-test");
    let forged = with_protected(UVM_0_2_10, |h| {
        let cwt = cwt_claims(h);
        set_map(cwt, Value::from(2), Value::from("ConfAKS-AMD-UVM"));
    });
    assert_rejected(uvm(&forged), "feed ConfAKS-AMD-UVM");
}

#[test]
fn endorsement_chain_must_end_at_the_pinned_root() {
    // Drop the root: the chain now ends at the intermediate.
    let forged = with_protected(UVM_0_2_9, |h| {
        let chain = x5chain(h);
        chain.pop();
    });
    assert_rejected(uvm(&forged), "root is not the did:x509 root");
    // Only the leaf.
    let forged = with_protected(UVM_0_2_9, |h| {
        let chain = x5chain(h);
        chain.truncate(1);
    });
    assert_rejected(uvm(&forged), "x5chain is not a certificate chain");
    // Leaf replaced by the intermediate: no EKU.
    let forged = with_protected(UVM_0_2_9, |h| {
        let chain = x5chain(h);
        chain.remove(0);
    });
    assert_rejected(uvm(&forged), "lacks the did:x509 EKU");
}

#[test]
fn endorsement_chain_is_checked_at_its_signing_time() {
    // The 0.2.9 leaf is valid 2025-05-15 to 2026-05-15 and was signed 2025-09-30.
    let forged = with_protected(UVM_0_2_9, |h| {
        set(h, Label::Text("signingtime".into()), Value::Tag(1, Box::new(Value::from(1_790_000_000))))
    });
    assert_rejected(uvm(&forged), "x5chain[0] not valid");
    let forged = with_protected(UVM_0_2_10, |h| {
        let cwt = cwt_claims(h);
        set_map(cwt, Value::from(6), Value::from(1_700_000_000));
    });
    assert_rejected(uvm(&forged), "x5chain[0] not valid");
    let forged = with_protected(UVM_0_2_9, |h| h.rest.retain(|(l, _)| *l != Label::Text("signingtime".into())));
    assert_rejected(uvm(&forged), "no signingtime");
}

#[test]
fn endorsement_format_is_strict() {
    let forged = with_protected(UVM_0_2_9, |h| h.alg = Some(coset::Algorithm::Assigned(coset::iana::Algorithm::PS256)));
    assert_rejected(uvm(&forged), "PS384");
    let forged = with_protected(UVM_0_2_9, |h| h.content_type = Some(coset::ContentType::Text("text/plain".into())));
    assert_rejected(uvm(&forged), "application/json");
    let forged = with_protected(UVM_0_2_10, |h| set(h, Label::Int(258), Value::from(-16)));
    assert_rejected(uvm(&forged), "SHA-384");
    let forged = with_protected(UVM_0_2_10, |h| set(h, Label::Int(259), Value::from("application/json")));
    assert_rejected(uvm(&forged), "application/octet-stream");
    let forged = with_protected(UVM_0_2_10, |h| {
        let cwt = cwt_claims(h);
        set_map(cwt, Value::from("svn"), Value::from(-1));
    });
    assert_rejected(uvm(&forged), "svn");
}

// --- COSE editing helpers: re-encode the protected header after `f` changes it ---

fn with_protected(original: &[u8], f: impl FnOnce(&mut coset::Header)) -> Vec<u8> {
    let mut sign1 = CoseSign1::from_tagged_slice(original).unwrap();
    f(&mut sign1.protected.header);
    sign1.protected.original_data = None;
    sign1.to_tagged_vec().unwrap()
}

fn set(h: &mut coset::Header, label: Label, value: Value) {
    let entry = h.rest.iter_mut().find(|(l, _)| *l == label).expect("label present");
    entry.1 = value;
}

fn set_text(h: &mut coset::Header, label: &str, value: &str) {
    set(h, Label::Text(label.into()), Value::from(value));
}

fn x5chain(h: &mut coset::Header) -> &mut Vec<Value> {
    let entry = h.rest.iter_mut().find(|(l, _)| *l == Label::Int(33)).unwrap();
    match &mut entry.1 {
        Value::Array(a) => a,
        _ => panic!("x5chain"),
    }
}

fn cwt_claims(h: &mut coset::Header) -> &mut Vec<(Value, Value)> {
    let entry = h.rest.iter_mut().find(|(l, _)| *l == Label::Int(15)).unwrap();
    match &mut entry.1 {
        Value::Map(m) => m,
        _ => panic!("CWT claims"),
    }
}

fn set_map(m: &mut [(Value, Value)], key: Value, value: Value) {
    m.iter_mut().find(|(k, _)| *k == key).expect("claim present").1 = value;
}

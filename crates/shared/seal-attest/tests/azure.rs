//! Whole Azure evidence through `seal_attest::verify`, on real paired vectors (sources in
//! `tests/data/README.md`).

use base64::Engine;
use seal_attest::{azure, verify, AttestError, VerifiedEvidence};
use seal_proto::release::Tcb;
use seal_proto::{Evidence, PlatformId, TrustedTime};
use sha2::{Digest, Sha256};

/// 2026-10-26T07:33:20Z: every test VCEK is valid.
const NOW: TrustedTime = TrustedTime { now: 1_793_000_000, radius: 10 };

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn tcb(entries: &[(&str, u64)]) -> Tcb {
    Tcb(entries.iter().map(|(k, v)| (k.to_string(), *v)).collect())
}

/// One floor for both real chips: a Milan floor above the ACI Milan sample's `snp` 8, and a
/// Genoa floor the Genoa capture meets.
fn floor() -> Tcb {
    tcb(&[("milan.snp", 9), ("milan.microcode", 115), ("genoa.snp", 23), ("genoa.microcode", 84)])
}

/// A confidential container group from production Azure (microsoft/confidential-sidecar-containers):
/// the SNP report, the `vcekCert` of `host-amd-cert-base64`, `reference-info-base64` and the
/// security policy.
fn aci_sample() -> (Evidence, Vec<u8>) {
    let certs: serde_json::Value =
        serde_json::from_slice(include_bytes!("data/aci/uvm_host_amd_certificate.json")).unwrap();
    let vcek_pem = certs["vcekCert"].as_str().unwrap();
    let vcek = x509_cert::Certificate::load_pem_chain(vcek_pem.as_bytes()).unwrap().remove(0);
    let evidence = Evidence::AzureSnpAci {
        report: include_bytes!("data/aci/snp_report.bin").to_vec(),
        vcek_der: der::Encode::to_der(&vcek).unwrap(),
        uvm_endorsement: b64(include_bytes!("data/aci/body.uvm_reference_info.bin")),
    };
    let policy = base64::engine::general_purpose::STANDARD
        .decode(include_str!("data/aci/uvm_security_policy.base64").trim())
        .unwrap();
    (evidence, policy)
}

/// CCF's version-2 Milan report, its VCEK from AMD's KDS and the matching UVM endorsement
/// (svn 100, legacy format).
fn ccf_v2_sample() -> Evidence {
    Evidence::AzureSnpAci {
        report: include_bytes!("data/ccf/v2_format_milan_attestation.bin").to_vec(),
        vcek_der: include_bytes!("data/kds/v2_milan_vcek.der").to_vec(),
        uvm_endorsement: b64(include_bytes!("data/ccf/rsa_test1.cose")),
    }
}

fn with_report(e: &Evidence, f: impl FnOnce(&mut Vec<u8>)) -> Evidence {
    let mut e = e.clone();
    let Evidence::AzureSnpAci { report, .. } = &mut e else { unreachable!() };
    f(report);
    e
}

fn with_endorsement(e: &Evidence, endorsement: &[u8]) -> Evidence {
    let mut e = e.clone();
    let Evidence::AzureSnpAci { uvm_endorsement, .. } = &mut e else { unreachable!() };
    *uvm_endorsement = b64(endorsement);
    e
}

#[track_caller]
fn assert_rejected(r: Result<VerifiedEvidence, AttestError>, needle: &str) {
    match r {
        Err(e @ AttestError::Rejected(_)) => {
            assert!(e.to_string().contains(needle), "{e} does not mention {needle:?}");
            assert_eq!(e.code(), seal_proto::ErrorCode::VerificationFailed);
        }
        other => panic!("expected a rejection mentioning {needle:?}, got {other:?}"),
    }
}

#[test]
fn aci_sample_verifies() {
    let (evidence, policy) = aci_sample();
    let host_data: [u8; 32] = Sha256::digest(&policy).into();
    let expected = VerifiedEvidence {
        platform: PlatformId::AzureSnpAci,
        measurement: azure::measurement(&host_data),
        tcb: tcb(&[
            ("milan.bootloader", 3),
            ("milan.tee", 0),
            ("milan.snp", 8),
            ("milan.microcode", 115),
            ("uvm_svn", 22),
        ]),
        report_data: hex::decode("ee986ff2bd7e3f22e29f640918627816cf8e23b9d9c312767168eab68c861c71")
            .unwrap()
            .try_into()
            .unwrap(),
        deployment: None,
    };
    assert_eq!(verify(&evidence, &NOW).unwrap(), expected);
    // Its own family's floor refuses it; Genoa's floor (`genoa.snp` 23) is never applied to it.
    assert!(!expected.tcb.passes(&floor()));
    assert!(expected.tcb.passes(&tcb(&[("milan.snp", 8), ("genoa.snp", 23), ("genoa.microcode", 84)])));
    assert!(!expected.tcb.passes(&tcb(&[("genoa.snp", 0)])), "a family the floor does not list");
    seal_attest::check_floor(PlatformId::AzureSnpAci, &floor()).unwrap();
    seal_attest::check_floor(PlatformId::AzureSnpAci, &tcb(&[("turin.fmc", 1), ("uvm_svn", 100)])).unwrap();
    // Without its family, or misspelled, a component would refuse every chip for good.
    assert!(seal_attest::check_floor(PlatformId::AzureSnpAci, &tcb(&[("snp", 24)])).is_err());
    assert!(seal_attest::check_floor(PlatformId::AzureSnpAci, &tcb(&[("milan.fmc", 1)])).is_err());
    assert!(seal_attest::check_floor(PlatformId::AwsNitro, &tcb(&[("uvm_svn", 100)])).is_err());
    assert_eq!(
        expected.measurement.to_string(),
        "69d6cfe598d6bbdcc21d5c65b9633784225593c20875776d9135c88a5effa87eeb614361e7808b28742607e3571b366b"
    );
}

#[test]
fn ccf_v2_sample_verifies() {
    let host_data: [u8; 32] =
        hex::decode("4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10").unwrap().try_into().unwrap();
    let v = verify(&ccf_v2_sample(), &NOW).unwrap();
    assert_eq!(v.platform, PlatformId::AzureSnpAci);
    assert_eq!(v.measurement, azure::measurement(&host_data));
    assert_eq!(
        v.tcb,
        tcb(&[("milan.bootloader", 3), ("milan.tee", 0), ("milan.snp", 8), ("milan.microcode", 115), ("uvm_svn", 100)])
    );
    assert_eq!(hex::encode(v.report_data), "7a6a68c0a2b85b8aae00ca04f644831680222f44167e5558a9e072b70c60e958");
    assert_eq!(v.deployment, None);
}

#[test]
fn measurement_is_labeled_sha384_of_host_data() {
    let host_data = [7u8; 32];
    let mut h = sha2::Sha384::new();
    h.update(b"azure-snp-aci");
    h.update(host_data);
    assert_eq!(azure::measurement(&host_data).0, <[u8; 48]>::from(h.finalize()));
}

#[test]
fn endorsement_of_another_uvm_is_refused() {
    let (evidence, _) = aci_sample();
    for other in [
        include_bytes!("data/ccf/uvm_0.2.9.cose").as_slice(),
        include_bytes!("data/ccf/uvm_0.2.10.cose"),
        include_bytes!("data/ccf/rsa_test1.cose"),
    ] {
        assert_rejected(verify(&with_endorsement(&evidence, other), &NOW), "launch measurement does not match");
    }
}

#[test]
fn forged_or_untrusted_endorsement_is_refused() {
    let (evidence, _) = aci_sample();
    let mut forged = include_bytes!("data/aci/body.uvm_reference_info.bin").to_vec();
    let n = forged.len();
    forged[n - 1] ^= 1;
    assert_rejected(verify(&with_endorsement(&evidence, &forged), &NOW), "signature does not verify");
    let conf_aks = include_bytes!("data/ccf/ecdsa_test1.cose");
    assert_rejected(verify(&with_endorsement(&evidence, conf_aks), &NOW), "is not trusted");
    assert_rejected(verify(&with_endorsement(&evidence, b"garbage"), &NOW), "COSE_Sign1");
}

#[test]
fn tampered_report_is_refused() {
    let evidence = ccf_v2_sample();
    assert_rejected(verify(&with_report(&evidence, |r| r[0x50] ^= 1), &NOW), "report signature");
    assert_rejected(verify(&with_report(&evidence, |r| r[0xC0] ^= 1), &NOW), "report signature");
    let debug = with_report(&evidence, |r| r[0x0A] |= 0x08);
    let err = verify(&debug, &NOW).unwrap_err();
    assert!(matches!(err, AttestError::DebugMode));
    assert_eq!(err.code(), seal_proto::ErrorCode::VerificationFailed);
}

#[test]
fn wrong_vcek_is_refused() {
    let (aci, _) = aci_sample();
    let Evidence::AzureSnpAci { vcek_der: aci_vcek, .. } = aci else { unreachable!() };
    let mut evidence = ccf_v2_sample();
    let Evidence::AzureSnpAci { vcek_der, .. } = &mut evidence else { unreachable!() };
    *vcek_der = aci_vcek;
    assert_rejected(verify(&evidence, &NOW), "hwID");
}

#[test]
fn hardware_chain_is_checked_at_time() {
    let evidence = ccf_v2_sample();
    // The v2 VCEK is valid 2026-10-26T00:19:34Z to 2033-10-26T00:19:34Z.
    assert_rejected(verify(&evidence, &TrustedTime::exact(2_100_000_000)), "VCEK not valid");
    assert_rejected(verify(&evidence, &TrustedTime::exact(1_792_900_000)), "VCEK not valid");
    // The uncertain end counts: the interval must lie inside the validity.
    assert_rejected(verify(&evidence, &TrustedTime { now: 1_793_000_000, radius: 30_000 }), "VCEK not valid");
    // The endorsement's own chain expired in 2024; it is checked at its signing time.
    assert!(verify(&evidence, &NOW).is_ok());
}

/// Seal's capture from a confidential container group (Genoa, eastus): the report, the security
/// context's `host-amd-cert-base64` VCEK and either endorsement ACI writes
/// (`reference-info-base64`, legacy; `transparent-reference-info-base64`, CWT).
#[test]
fn aci_genoa_capture_verifies_with_either_endorsement() {
    let b64 = base64::engine::general_purpose::STANDARD;
    let host_certs: serde_json::Value =
        serde_json::from_slice(&b64.decode(include_str!("data/aci-genoa/host-amd-cert-base64").trim()).unwrap())
            .unwrap();
    let vcek =
        x509_cert::Certificate::load_pem_chain(host_certs["vcekCert"].as_str().unwrap().as_bytes()).unwrap().remove(0);
    let policy = b64.decode(include_str!("data/aci-genoa/security-policy-base64").trim()).unwrap();
    let host_data: [u8; 32] = Sha256::digest(&policy).into();
    let captured_at = TrustedTime { now: 1_793_079_784, radius: 10 };
    for endorsement in [
        include_str!("data/aci-genoa/reference-info-base64"),
        include_str!("data/aci-genoa/transparent-reference-info-base64"),
    ] {
        let evidence = Evidence::AzureSnpAci {
            report: include_bytes!("data/aci-genoa/snp_report.bin").to_vec(),
            vcek_der: der::Encode::to_der(&vcek).unwrap(),
            uvm_endorsement: endorsement.trim().to_owned(),
        };
        let verified = verify(&evidence, &captured_at).unwrap();
        assert_eq!(verified.measurement, azure::measurement(&host_data));
        assert_eq!(
            verified.tcb,
            tcb(&[
                ("genoa.bootloader", 10),
                ("genoa.tee", 0),
                ("genoa.snp", 23),
                ("genoa.microcode", 84),
                ("uvm_svn", 104)
            ])
        );
        assert!(verified.tcb.passes(&floor()));
        seal_attest::check_floor(PlatformId::AzureSnpAci, &verified.tcb).unwrap();
        assert_eq!(
            hex::encode(verified.report_data),
            "682c0b3fca09ca8346a9861d9bd2dc917e9c1a007872e197a9d22ebd25516218"
        );
    }
}

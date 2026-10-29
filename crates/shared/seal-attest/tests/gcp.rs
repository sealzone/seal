//! Whole Confidential Space tokens through `seal_attest::verify`, recorded on live VMs (sources
//! in `tests/data/README.md`). Synthetic tokens for each refusal are in `src/gcp/tests.rs`.

use seal_attest::{gcp, verify, AttestError, VerifiedEvidence};
use seal_proto::identity::WorkloadIdentity;
use seal_proto::release::Tcb;
use seal_proto::{Evidence, PlatformId, TrustedTime};

/// 2026-10-27T05:53:20Z: every recorded token is valid.
const NOW: TrustedTime = TrustedTime { now: 1_793_080_400, radius: 1 };

/// `iat` and `nbf` of `tdx.jwt`; it expires an hour later.
const TDX_ISSUED: u64 = 1_793_079_235;
const TDX_EXPIRES: u64 = 1_793_082_835;

/// The image the recording ran (`capture:probe` in `seal-dev-gcp`).
const PROBE_IMAGE: &str = "sha256:58c94f8c38b3cbda5a900479583caad991052559ffdb33d898eb8bf35cfbd6b6";

/// What `seal_tee`'s attestor printed as its own measurement on the VM.
const PROBE_MEASUREMENT: &str =
    "d91f09d90c32808686ebd80865c354d57f13f4bf3bbee1316cfb019f897c0f16c43a83deca8eb445ce69c12a1836a9f7";

fn token(name: &str) -> Evidence {
    let path = format!("{}/tests/data/gcp/{name}", env!("CARGO_MANIFEST_DIR"));
    Evidence::GcpConfidentialSpace { token: std::fs::read_to_string(path).unwrap() }
}

fn at(now: u64, radius: u64) -> TrustedTime {
    TrustedTime { now, radius }
}

#[track_caller]
fn assert_rejected(r: Result<VerifiedEvidence, AttestError>, needle: &str) {
    match r {
        Err(AttestError::Rejected(msg)) => assert!(msg.contains(needle), "{msg:?} does not mention {needle:?}"),
        other => panic!("expected a rejection mentioning {needle:?}, got {other:?}"),
    }
}

#[test]
fn production_tdx_token_verifies() {
    let v = verify(&token("tdx.jwt"), &NOW).unwrap();
    assert_eq!(v.platform, PlatformId::GcpConfidentialSpace);
    assert_eq!(v.measurement, gcp::measurement(PROBE_IMAGE).unwrap());
    assert_eq!(hex::encode(v.measurement.0), PROBE_MEASUREMENT);
    // The attestor's report data, 0..32, as the token's one nonce.
    assert_eq!(v.report_data, std::array::from_fn(|i| i as u8));
    assert_eq!(
        v.tcb,
        Tcb([
            ("cs_stable".to_owned(), 1),
            ("cs_version".to_owned(), 261_000),
            ("tdx_tcb_evaluation_data_number".to_owned(), 19),
            ("tdx_tcb_status".to_owned(), 3),
        ]
        .into())
    );
    seal_attest::check_floor(PlatformId::GcpConfidentialSpace, &v.tcb).unwrap();
    assert_eq!(
        v.deployment,
        Some(WorkloadIdentity::ConfidentialSpace {
            project_number: 118_699_070_563,
            service_account: "seal-dev-gcp@seal-512903.iam.gserviceaccount.com".into(),
        })
    );
}

#[test]
fn production_tdx_token_validity() {
    let e = token("tdx.jwt");
    // Checked the moment it was issued: Roughtime read one second before `nbf` on the VM.
    assert!(verify(&e, &at(TDX_ISSUED - 1, 1)).is_ok());
    assert!(verify(&e, &at(TDX_ISSUED - 60, 0)).is_ok());
    assert_rejected(verify(&e, &at(TDX_ISSUED - 61, 0)), "token not valid");
    assert!(verify(&e, &at(TDX_EXPIRES - 2, 1)).is_ok());
    assert_rejected(verify(&e, &at(TDX_EXPIRES - 1, 1)), "token not valid");
    assert_rejected(verify(&e, &at(TDX_EXPIRES + 86_400, 0)), "token not valid");
    // Past the leaf certificate (2026-12-21T03:31:43Z), whatever the token says.
    assert_rejected(verify(&e, &at(1_800_000_000, 0)), "not valid");
}

#[test]
fn production_tdx_token_tampered() {
    let Evidence::GcpConfidentialSpace { token: t } = token("tdx.jwt") else { unreachable!() };
    let (header, rest) = t.split_once('.').unwrap();
    let (payload, signature) = rest.split_once('.').unwrap();
    let claims = String::from_utf8(seal_proto::codec::from_b64url(payload).unwrap()).unwrap();
    for (from, to) in [
        (PROBE_IMAGE, "sha256:c0b7df5ad53a4c6cb99dbd8d468ce78fa354ef4d584ac13713acee5fd6a6d8e7"),
        ("118699070563", "118699070564"),
        ("000102030405060708090a0b0c0d0e0f", "ff0102030405060708090a0b0c0d0e0f"),
        ("\"exp\":1793082835", "\"exp\":1893082835"),
    ] {
        assert!(claims.contains(from), "{from}");
        let forged = seal_proto::codec::b64url(claims.replace(from, to).as_bytes());
        let evidence = Evidence::GcpConfidentialSpace { token: format!("{header}.{forged}.{signature}") };
        assert_rejected(verify(&evidence, &NOW), "signature does not verify");
    }
}

#[test]
fn production_tokens_without_exactly_one_nonce_refused() {
    assert_rejected(verify(&token("tdx-two-nonces.jwt"), &NOW), "more than one nonce");
    assert_rejected(verify(&token("tdx-no-nonce.jwt"), &NOW), "no nonce");
}

#[test]
fn production_plain_sev_token_refused() {
    assert_rejected(verify(&token("sev.jwt"), &NOW), "hardware model \"GCP_AMD_SEV\"");
}

#[test]
fn debug_image_tokens_refused() {
    for name in ["tdx-debug.jwt", "sev-debug.jwt"] {
        assert!(matches!(verify(&token(name), &NOW), Err(AttestError::DebugMode)), "{name}");
    }
}

#[test]
fn measurement_takes_only_sha256_digests() {
    assert!(gcp::measurement(PROBE_IMAGE).is_ok());
    assert!(gcp::measurement(&PROBE_IMAGE.to_uppercase()).is_err());
    assert!(gcp::measurement(&PROBE_IMAGE[7..]).is_err());
    assert!(gcp::measurement("sha256:").is_err());
    assert_ne!(
        gcp::measurement(PROBE_IMAGE).unwrap(),
        gcp::measurement("sha256:c0b7df5ad53a4c6cb99dbd8d468ce78fa354ef4d584ac13713acee5fd6a6d8e7").unwrap()
    );
}

//! Synthetic tokens signed by the test chains in `tests/data/gcp/test-ca` (one refusal each),
//! and the chain and signature of real debug-image tokens. Whole real tokens through
//! `seal_attest::verify` are in `tests/gcp.rs`; sources in `tests/data/README.md`.

use base64::Engine;
use proptest::prelude::*;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use seal_proto::codec::b64url;
use seal_proto::identity::WorkloadIdentity;
use seal_proto::release::Tcb;
use seal_proto::{PlatformId, TrustedTime};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    baked_root, check_chain, check_claims, decimal, leaf_key, lower_hex, measurement, verify_with_root, AUDIENCE,
    ISSUER, ROOT_PEM,
};
use crate::x509::Cert;
use crate::AttestError;

macro_rules! data {
    ($path:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/gcp/", $path)).as_slice()
    };
}

/// 2026-10-27T05:53:20Z: inside every test certificate's validity except `expired-leaf`, and
/// every recorded token's.
const NOW: u64 = 1_793_080_400;
const AT: TrustedTime = TrustedTime { now: NOW, radius: 10 };

const DIGEST: &str = "sha256:c0b7df5ad53a4c6cb99dbd8d468ce78fa354ef4d584ac13713acee5fd6a6d8e7";
const NONCE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn pem(bytes: &[u8]) -> Cert {
    Cert::parse_pem_chain(bytes, "test").unwrap().remove(0)
}

struct Chain {
    leaf: Cert,
    intermediate: Cert,
    root: Cert,
}

fn chain() -> Chain {
    Chain {
        leaf: pem(data!("test-ca/leaf.pem")),
        intermediate: pem(data!("test-ca/intermediate.pem")),
        root: pem(data!("test-ca/root.pem")),
    }
}

fn test_root() -> Cert {
    pem(data!("test-ca/root.pem"))
}

/// What a production token on TDX says, valid ten minutes around `NOW`.
fn claims() -> Value {
    json!({
        "aud": AUDIENCE,
        "exp": NOW + 300,
        "iat": NOW - 300,
        "iss": ISSUER,
        "nbf": NOW - 300,
        "sub": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/instances/i",
        "eat_nonce": NONCE,
        "secboot": true,
        "oemid": 11129,
        "hwmodel": "GCP_INTEL_TDX",
        "swname": "CONFIDENTIAL_SPACE",
        "swversion": ["261000"],
        "dbgstat": "disabled-since-boot",
        "submods": {
            "confidential_space": {"support_attributes": ["LATEST", "STABLE", "USABLE"]},
            "container": {"image_digest": DIGEST, "restart_policy": "Never"},
            "gce": {"project_id": "p", "project_number": "118699070563", "instance_name": "i"}
        },
        "google_service_accounts": ["sa@p.iam.gserviceaccount.com"],
        "tdx": {
            "gcp_attester_tcb_status": "UpToDate",
            "gcp_attester_tcb_date": "2025-05-14T00:00:00Z",
            "tcb_evaluation_data_number": 19
        }
    })
}

/// The TCB `claims()` yields.
fn tcb() -> Tcb {
    Tcb([
        ("cs_stable".to_owned(), 1),
        ("cs_version".to_owned(), 261_000),
        ("tdx_tcb_evaluation_data_number".to_owned(), 19),
        ("tdx_tcb_status".to_owned(), 3),
    ]
    .into())
}

fn x5c(certs: &[&Cert]) -> Vec<String> {
    certs.iter().map(|c| base64::engine::general_purpose::STANDARD.encode(&c.der)).collect()
}

/// A compact JWS over `payload` with `header`, signed RS256 by the test leaf key.
fn sign_raw(header: &Value, payload: &[u8]) -> String {
    sign_bytes(header.to_string().as_bytes(), payload)
}

/// A compact JWS over `payload` with the header bytes as given, signed RS256 by the test leaf key.
fn sign_bytes(header: &[u8], payload: &[u8]) -> String {
    let key = rsa::RsaPrivateKey::from_pkcs1_der(data!("test-ca/leaf-key.pkcs1.der")).unwrap();
    let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
    let input = format!("{}.{}", b64url(header), b64url(payload));
    let signature = signer.sign(input.as_bytes()).to_vec();
    format!("{input}.{}", b64url(&signature))
}

fn header(certs: &[&Cert]) -> Value {
    json!({"alg": "RS256", "kid": "test-kid", "typ": "JWT", "x5c": x5c(certs)})
}

fn sign_with(certs: &[&Cert], claims: &Value) -> String {
    sign_raw(&header(certs), claims.to_string().as_bytes())
}

fn sign(claims: &Value) -> String {
    let c = chain();
    sign_with(&[&c.leaf, &c.intermediate, &c.root], claims)
}

fn with(f: impl FnOnce(&mut Value)) -> Value {
    let mut c = claims();
    f(&mut c);
    c
}

fn check(token: &str) -> Result<crate::VerifiedEvidence, AttestError> {
    verify_with_root(token, &AT, &test_root())
}

#[track_caller]
fn assert_rejected<T: std::fmt::Debug>(r: Result<T, AttestError>, needle: &str) {
    match r {
        Err(AttestError::Rejected(msg)) => assert!(msg.contains(needle), "{msg:?} does not mention {needle:?}"),
        other => panic!("expected a rejection mentioning {needle:?}, got {other:?}"),
    }
}

// --- the baked root ---

#[test]
fn baked_root_matches_google() {
    assert_eq!(
        hex::encode(Sha256::digest(ROOT_PEM)),
        "1e9f82db6b86371f80913f246049516a9dc333e28fb1bf3e343d3459347e0d11"
    );
    let root = baked_root().unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&root.der)),
        "148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39"
    );
    assert!(root.subject_is_issuer_of(&root));
    root.verify_pkcs1v15(&root).unwrap();
    assert!(root.is_ca().unwrap());
    // 2024-01-19T22:10:50Z to 2034-01-16T22:10:49Z.
    assert_eq!(root.validity(), (1_705_702_250, 2_021_062_249));
    assert!(root.cert.tbs_certificate().subject().to_string().contains("CN=Confidential Space Root CA"));
}

#[test]
fn real_chains_and_signatures_verify() {
    for (name, token) in [
        ("tdx", data!("tdx.jwt")),
        ("sev", data!("sev.jwt")),
        ("tdx-debug", data!("tdx-debug.jwt")),
        ("sev-debug", data!("sev-debug.jwt")),
    ] {
        let token = std::str::from_utf8(token).unwrap();
        let time = AT;
        let header: super::Header =
            serde_json::from_slice(&seal_proto::codec::from_b64url(token.split('.').next().unwrap()).unwrap()).unwrap();
        let leaf = check_chain(&header.x5c, &time, &baked_root().unwrap()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let kid = seal_crypto::jws::peek_header(token).unwrap().kid;
        seal_crypto::jws::verify(token, &leaf_key(&leaf, kid).unwrap(), seal_crypto::jws::JwsAlg::Rs256)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(header.x5c.len(), 3);
        // The real chain is not the test root's.
        if name == "tdx" {
            assert_rejected(verify_with_root(token, &time, &test_root()), "not the Confidential Space root");
        }
    }
}

// --- accepted ---

#[test]
fn synthetic_token_verifies() {
    let v = check(&sign(&claims())).unwrap();
    assert_eq!(v.platform, PlatformId::GcpConfidentialSpace);
    assert_eq!(v.measurement, measurement(DIGEST).unwrap());
    assert_eq!(v.report_data, std::array::from_fn(|i| i as u8));
    assert_eq!(v.tcb, tcb());
    assert_eq!(
        v.deployment,
        Some(WorkloadIdentity::ConfidentialSpace {
            project_number: 118_699_070_563,
            service_account: "sa@p.iam.gserviceaccount.com".into()
        })
    );
}

#[test]
fn tdx_tcb_status_ranks() {
    for (status, rank) in [
        ("UpToDate", 3),
        ("SWHardeningNeeded", 2),
        ("ConfigurationNeeded", 1),
        ("ConfigurationAndSWHardeningNeeded", 1),
        ("OutOfDate", 0),
        ("OutOfDateConfigurationNeeded", 0),
        ("Revoked", 0),
        ("SomethingNew", 0),
    ] {
        let v = check(&sign(&with(|c| c["tdx"]["gcp_attester_tcb_status"] = json!(status)))).unwrap();
        assert_eq!(v.tcb.0["tdx_tcb_status"], rank, "{status}");
        assert_eq!(v.tcb.0["tdx_tcb_evaluation_data_number"], 19);
    }
    let v = check(&sign(&with(|c| c["tdx"]["tcb_evaluation_data_number"] = json!(20)))).unwrap();
    assert_eq!(v.tcb.0["tdx_tcb_evaluation_data_number"], 20);
}

#[test]
fn tdx_tcb_floor() {
    // What a production floor requires: a supported image on an up-to-date TDX module.
    let floor = Tcb([
        ("cs_stable".to_owned(), 1),
        ("tdx_tcb_status".to_owned(), 3),
        ("tdx_tcb_evaluation_data_number".to_owned(), 19),
    ]
    .into());
    assert!(check(&sign(&claims())).unwrap().tcb.meets(&floor));
    let hardening = check(&sign(&with(|c| c["tdx"]["gcp_attester_tcb_status"] = json!("SWHardeningNeeded")))).unwrap();
    assert!(!hardening.tcb.meets(&floor));
    let older = check(&sign(&with(|c| c["tdx"]["tcb_evaluation_data_number"] = json!(18)))).unwrap();
    assert!(!older.tcb.meets(&floor));
    // Without the claim (SEV-SNP, should Google attest it) neither component is there, so the floor refuses.
    let no_tdx = check(&sign(&with(|c| drop(c.as_object_mut().unwrap().remove("tdx"))))).unwrap();
    assert!(!no_tdx.tcb.0.contains_key("tdx_tcb_status"));
    assert!(!no_tdx.tcb.meets(&floor));
}

#[test]
fn accepted_variants() {
    // SEV-SNP, should Google attest it.
    assert!(check(&sign(&with(|c| c["hwmodel"] = json!("GCP_AMD_SEV_SNP")))).is_ok());
    // One-element arrays for aud and eat_nonce.
    assert!(check(&sign(&with(|c| c["aud"] = json!([AUDIENCE])))).is_ok());
    assert!(check(&sign(&with(|c| c["eat_nonce"] = json!([NONCE])))).is_ok());
    // An image Google no longer calls STABLE: cs_stable 0, for min_tcb to decide.
    let v =
        check(&sign(&with(|c| c["submods"]["confidential_space"]["support_attributes"] = json!(["USABLE"])))).unwrap();
    assert_eq!(v.tcb.0["cs_stable"], 0);
    let v = check(&sign(&with(|c| c["submods"]["confidential_space"] = json!({})))).unwrap();
    assert_eq!(v.tcb.0["cs_stable"], 0);
    // Restart policy and overrides are not the verifier's.
    assert!(check(&sign(&with(|c| c["submods"]["container"]["restart_policy"] = json!("Always")))).is_ok());
}

// --- chain ---

#[test]
fn wrong_chain_refused() {
    let c = chain();
    let other_root = pem(data!("test-ca/other-root.pem"));
    let other_intermediate = pem(data!("test-ca/other-intermediate.pem"));
    let not_ca = pem(data!("test-ca/not-ca-intermediate.pem"));
    let claims = claims();
    // Signed by another CA altogether.
    assert_rejected(
        check(&sign_with(&[&c.leaf, &other_intermediate, &other_root], &claims)),
        "not the Confidential Space root",
    );
    // The trusted root last, but an intermediate it never signed.
    assert_rejected(check(&sign_with(&[&c.leaf, &other_intermediate, &c.root], &claims)), "issuer does not match");
    // An intermediate that is not a CA.
    assert_rejected(check(&sign_with(&[&c.leaf, &not_ca, &c.root], &claims)), "not a CA");
    // A CA as the leaf.
    assert_rejected(
        check(&sign_with(&[&c.intermediate, &c.intermediate, &c.root], &claims)),
        "leaf certificate is a CA",
    );
    // Missing or extra certificates.
    assert_rejected(check(&sign_with(&[&c.leaf, &c.intermediate], &claims)), "x5c has 2");
    assert_rejected(check(&sign_with(&[&c.leaf, &c.intermediate, &c.root, &c.root], &claims)), "x5c has 4");
    assert_rejected(
        check(&sign_raw(&json!({"alg": "RS256", "kid": "test-kid"}), claims.to_string().as_bytes())),
        "x5c has 0",
    );
    // The real Google root does not trust the test chain.
    assert_rejected(super::verify(&sign(&claims), &AT), "not the Confidential Space root");
}

#[test]
fn leaf_key_must_have_signed() {
    let c = chain();
    // A valid leaf of the trusted chain, but not the key that signed: the chain passes, the
    // signature does not.
    let other_key = pem(data!("test-ca/other-key-leaf.pem"));
    assert_rejected(check(&sign_with(&[&other_key, &c.intermediate, &c.root], &claims())), "signature does not verify");
    // A header changed after signing.
    let token = sign(&claims());
    let (_, rest) = token.split_once('.').unwrap();
    let mut changed = header(&[&c.leaf, &c.intermediate, &c.root]);
    changed["kid"] = json!("other-kid");
    let swapped = format!("{}.{rest}", b64url(changed.to_string().as_bytes()));
    assert_rejected(check(&swapped), "signature does not verify");
}

#[test]
fn algorithms_other_than_rs256_refused() {
    let c = chain();
    for alg in ["none", "HS256", "ES256", "PS256", "rs256"] {
        let h = json!({"alg": alg, "kid": "test-kid", "x5c": x5c(&[&c.leaf, &c.intermediate, &c.root])});
        assert_rejected(check(&sign_raw(&h, claims().to_string().as_bytes())), "not RS256");
    }
}

// --- time ---

#[test]
fn expired_refused() {
    let c = chain();
    let expired = pem(data!("test-ca/expired-leaf.pem"));
    assert_rejected(check(&sign_with(&[&expired, &c.intermediate, &c.root], &claims())), "leaf certificate not valid");
    assert_rejected(check(&sign(&with(|c| c["exp"] = json!(NOW)))), "token not valid");
    // The latest end of the trusted time must be before `exp`; `nbf` may be up to
    // `NBF_SKEW_SECS` after it.
    assert_rejected(check(&sign(&with(|c| c["exp"] = json!(NOW + 10)))), "token not valid");
    assert!(check(&sign(&with(|c| c["exp"] = json!(NOW + 11)))).is_ok());
    let skew = super::NBF_SKEW_SECS;
    assert!(check(&sign(&with(|c| c["nbf"] = json!(NOW + 10 + skew)))).is_ok());
    assert_rejected(check(&sign(&with(|c| c["nbf"] = json!(NOW + 11 + skew)))), "token not valid");
    // Certificates are checked at the trusted time too.
    let late = TrustedTime { now: 1_830_000_000, radius: 0 };
    assert_rejected(verify_with_root(&sign(&with(|c| c["exp"] = json!(u64::MAX))), &late, &test_root()), "not valid");
    // Non-integer times are refused.
    assert_rejected(check(&sign(&with(|c| c["exp"] = json!(1.8e9)))), "token claims");
}

// --- nonce ---

#[test]
fn wrong_nonce_refused() {
    let upper = NONCE.to_uppercase();
    let short = &NONCE[..62];
    let b64 = base64::engine::general_purpose::STANDARD.encode(std::array::from_fn::<u8, 32, _>(|i| i as u8));
    for nonce in [upper.as_str(), short, &b64, "", &format!("{NONCE}00")] {
        assert_rejected(check(&sign(&with(|c| c["eat_nonce"] = json!(nonce)))), "64 lowercase hex");
    }
    assert_rejected(check(&sign(&with(|c| c["eat_nonce"] = json!(7)))), "token claims");
}

#[test]
fn two_nonces_refused() {
    let other = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    assert_rejected(check(&sign(&with(|c| c["eat_nonce"] = json!([NONCE, other])))), "more than one nonce");
    assert_rejected(check(&sign(&with(|c| c["eat_nonce"] = json!([NONCE, NONCE])))), "more than one nonce");
    assert_rejected(check(&sign(&with(|c| c["eat_nonce"] = json!([])))), "more than one nonce");
    assert_rejected(check(&sign(&with(|c| drop(c.as_object_mut().unwrap().remove("eat_nonce"))))), "no nonce");
}

// --- image and platform ---

#[test]
fn debug_image_refused() {
    assert!(matches!(check(&sign(&with(|c| c["dbgstat"] = json!("enabled")))), Err(AttestError::DebugMode)));
    assert!(matches!(check(&sign(&with(|c| c["dbgstat"] = json!("disabled")))), Err(AttestError::DebugMode)));
    assert_rejected(check(&sign(&with(|c| drop(c.as_object_mut().unwrap().remove("dbgstat"))))), "dbgstat");
    assert_rejected(check(&sign(&with(|c| c["secboot"] = json!(false)))), "secure boot");
}

#[test]
fn wrong_swname_refused() {
    for name in ["GCE", "CONFIDENTIAL_SPACE_DEBUG", "confidential_space", ""] {
        assert_rejected(check(&sign(&with(|c| c["swname"] = json!(name)))), "swname");
    }
}

#[test]
fn plain_sev_and_other_hardware_refused() {
    for model in ["GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_SHIELDED_VM", "GCP_INTEL_TDX "] {
        assert_rejected(check(&sign(&with(|c| c["hwmodel"] = json!(model)))), "hardware model");
    }
}

#[test]
fn wrong_audience_and_issuer_refused() {
    for aud in [json!("https://sts.googleapis.com"), json!("seal"), json!([AUDIENCE, "other"]), json!([])] {
        assert_rejected(check(&sign(&with(|c| c["aud"] = aud.clone()))), "audience");
    }
    for iss in ["https://confidentialcomputing.googleapis.com/", "https://accounts.google.com"] {
        assert_rejected(check(&sign(&with(|c| c["iss"] = json!(iss)))), "issuer");
    }
}

#[test]
fn wrong_image_digest_refused() {
    for digest in [
        "sha512:c0b7df5ad53a4c6cb99dbd8d468ce78fa354ef4d584ac13713acee5fd6a6d8e7",
        "sha256:C0B7DF5AD53A4C6CB99DBD8D468CE78FA354EF4D584AC13713ACEE5FD6A6D8E7",
        "sha256:c0b7df5ad53a4c6cb99dbd8d468ce78fa354ef4d584ac13713acee5fd6a6d8",
        "c0b7df5ad53a4c6cb99dbd8d468ce78fa354ef4d584ac13713acee5fd6a6d8e7",
    ] {
        assert!(
            check(&sign(&with(|c| c["submods"]["container"]["image_digest"] = json!(digest)))).is_err(),
            "{digest}"
        );
    }
    // Another image is another measurement.
    let other = "sha256:58c94f8c38b3cbda5a900479583caad991052559ffdb33d898eb8bf35cfbd6b6";
    let v = check(&sign(&with(|c| c["submods"]["container"]["image_digest"] = json!(other)))).unwrap();
    assert_eq!(v.measurement, measurement(other).unwrap());
    assert_ne!(v.measurement, measurement(DIGEST).unwrap());
}

#[test]
fn measurement_definition() {
    let digest: [u8; 32] = hex::decode(&DIGEST[7..]).unwrap().try_into().unwrap();
    let expected: [u8; 48] =
        sha2::Sha384::new().chain_update(b"gcp-confidential-space").chain_update(digest).finalize().into();
    assert_eq!(measurement(DIGEST).unwrap().0, expected);
}

// --- claims ---

#[test]
fn tampered_claims_refused() {
    let token = sign(&claims());
    let (head, rest) = token.split_once('.').unwrap();
    let (_, signature) = rest.split_once('.').unwrap();
    for f in [
        (|c: &mut Value| {
            c["submods"]["container"]["image_digest"] =
                json!("sha256:58c94f8c38b3cbda5a900479583caad991052559ffdb33d898eb8bf35cfbd6b6")
        }) as fn(&mut Value),
        |c| c["submods"]["gce"]["project_number"] = json!("1"),
        |c| c["google_service_accounts"] = json!(["attacker@p.iam.gserviceaccount.com"]),
        |c| c["eat_nonce"] = json!("ff".repeat(32)),
        |c| c["exp"] = json!(NOW + 86_400),
    ] {
        let payload = with(f);
        let forged = format!("{head}.{}.{signature}", b64url(payload.to_string().as_bytes()));
        assert_rejected(check(&forged), "signature does not verify");
    }
    // A flipped signature bit.
    let mut sig = seal_proto::codec::from_b64url(signature).unwrap();
    sig[0] ^= 1;
    let (signed, _) = token.rsplit_once('.').unwrap();
    assert_rejected(check(&format!("{signed}.{}", b64url(&sig))), "signature does not verify");
}

#[test]
fn malformed_claims_refused() {
    // A repeated claim: refused rather than read either way.
    let text = claims().to_string().replacen('{', &format!("{{\"aud\":\"{AUDIENCE}\","), 1);
    let c = chain();
    assert_rejected(
        check(&sign_raw(&header(&[&c.leaf, &c.intermediate, &c.root]), text.as_bytes())),
        "duplicate field",
    );
    assert_rejected(check(&sign(&with(|c| c["swversion"] = json!(["261000", "260900"])))), "exactly one swversion");
    assert_rejected(check(&sign(&with(|c| c["swversion"] = json!(["26.10"])))), "swversion");
    assert_rejected(check(&sign(&with(|c| c["submods"]["gce"]["project_number"] = json!("-1")))), "project_number");
    assert_rejected(
        check(&sign(&with(|c| c["submods"]["gce"]["project_number"] = json!(118_699_070_563u64)))),
        "token claims",
    );
    assert_rejected(check(&sign(&with(|c| c["google_service_accounts"] = json!([])))), "exactly one service account");
    assert_rejected(
        check(&sign(&with(|c| {
            c["google_service_accounts"] = json!(["a@p.iam.gserviceaccount.com", "b@p.iam.gserviceaccount.com"])
        }))),
        "exactly one service account",
    );
    assert_rejected(
        check(&sign(&with(|c| drop(c.as_object_mut().unwrap().remove("google_service_accounts"))))),
        "service account",
    );
    assert_rejected(
        check(&sign(&with(|c| drop(c["submods"].as_object_mut().unwrap().remove("container"))))),
        "container",
    );
    assert_rejected(check(&sign(&with(|c| c["tdx"]["tcb_evaluation_data_number"] = json!("19")))), "token claims");
    assert_rejected(
        check(&sign(&with(|c| drop(c["tdx"].as_object_mut().unwrap().remove("gcp_attester_tcb_status"))))),
        "token claims",
    );
    assert_rejected(check("not a token"), "token");
    assert_rejected(check("e30.e30.e30.e30"), "token");
}

// --- arbitrary and mutated input ---

/// Up to eight byte overwrites.
fn mutations() -> impl Strategy<Value = Vec<(prop::sample::Index, u8)>> {
    proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8)
}

fn mutate(bytes: &[u8], at: &[(prop::sample::Index, u8)]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (i, b) in at {
        let i = i.index(out.len());
        out[i] = *b;
    }
    out
}

const REAL_TOKENS: [&[u8]; 6] = [
    data!("tdx.jwt"),
    data!("sev.jwt"),
    data!("tdx-debug.jwt"),
    data!("sev-debug.jwt"),
    data!("tdx-no-nonce.jwt"),
    data!("tdx-two-nonces.jwt"),
];

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(
        a in proptest::collection::vec(any::<u8>(), 0..1024),
        b in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let text = String::from_utf8_lossy(&a);
        let _ = check(&text);
        let _ = verify_with_root(&text, &AT, &baked_root().unwrap());
        let _ = check(&format!("{}.{}.{}", b64url(&a), b64url(&b), b64url(&a)));
        let _ = check(&sign_bytes(&a, &b));
        let _ = check_claims(&a, &AT);
        let _ = (measurement(&text), lower_hex::<32>(&text), decimal(&text));
        let x5c = [text.to_string(), base64::engine::general_purpose::STANDARD.encode(&b), text.to_string()];
        let _ = check_chain(&x5c, &AT, &test_root());
    }

    #[test]
    fn mutated_tokens_never_panic(at in mutations(), which in 0..7usize) {
        let token = match REAL_TOKENS.get(which) {
            Some(t) => t.to_vec(),
            None => sign(&claims()).into_bytes(),
        };
        let token = String::from_utf8_lossy(&mutate(&token, &at)).into_owned();
        let _ = check(&token);
        let _ = verify_with_root(&token, &AT, &baked_root().unwrap());
    }

    /// Re-signed after the change, so the claims reach every check and the signature verifies.
    #[test]
    fn mutated_claims_never_panic(at in mutations()) {
        let c = chain();
        let header = header(&[&c.leaf, &c.intermediate, &c.root]);
        let _ = check(&sign_raw(&header, &mutate(claims().to_string().as_bytes(), &at)));
    }

    #[test]
    fn mutated_headers_never_panic(at in mutations()) {
        let c = chain();
        let header = header(&[&c.leaf, &c.intermediate, &c.root]).to_string();
        let _ = check(&sign_bytes(&mutate(header.as_bytes(), &at), claims().to_string().as_bytes()));
    }

    /// A changed certificate in an otherwise valid, signed token.
    #[test]
    fn mutated_chains_never_panic(at in mutations(), entry in 0..3usize) {
        let c = chain();
        let mut x5c = x5c(&[&c.leaf, &c.intermediate, &c.root]);
        let der = base64::engine::general_purpose::STANDARD.decode(&x5c[entry]).unwrap();
        x5c[entry] = base64::engine::general_purpose::STANDARD.encode(mutate(&der, &at));
        let header = json!({"alg": "RS256", "kid": "test-kid", "typ": "JWT", "x5c": x5c});
        let _ = check(&sign_raw(&header, claims().to_string().as_bytes()));
    }
}

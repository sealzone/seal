//! The attestor and clock over a fake NSM that answers as the device does: documents shaped
//! like AWS's (certificates from `seal-attest`'s test chain), echoing the request's
//! `user_data` and `nonce`. Their signatures are not real, so the clock's check here reads the
//! stated fields (`stated`); `seal-attest` tests `verify_timestamp` on signed documents.

use std::sync::Mutex;

use base64::Engine as _;
use ciborium::Value;
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use proptest::prelude::*;
use seal_attest::AttestError;
use seal_proto::{Evidence, TrustedTime};
use tokio::time::Instant;

use super::nsm::{self, Nsm};
use super::{NitroAttestor, NitroClock, Reading, REFRESH};
use crate::TeeError;

macro_rules! ca {
    ($path:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../seal-attest/tests/data/nitro/test-ca/", $path))
    };
}

fn der(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(body).unwrap()
}

/// 2026-10-28T05:39:46.250Z.
const T_MS: u64 = 1_793_165_986_250;

fn pcr(i: u8) -> Vec<u8> {
    vec![i + 1; 48]
}

/// A document as the NSM makes one, with an all-zero signature.
fn document(pcrs: &[Vec<u8>], timestamp_ms: u64, user_data: &Value, nonce: &Value) -> Vec<u8> {
    let pcrs = pcrs.iter().enumerate().map(|(i, v)| (Value::Integer(i.into()), Value::Bytes(v.clone()))).collect();
    let fields = vec![
        (Value::Text("module_id".into()), Value::Text("i-0123456789abcdef0-enc0123456789abcdef".into())),
        (Value::Text("digest".into()), Value::Text("SHA384".into())),
        (Value::Text("timestamp".into()), Value::Integer(timestamp_ms.into())),
        (Value::Text("pcrs".into()), Value::Map(pcrs)),
        (Value::Text("certificate".into()), Value::Bytes(der(ca!("leaf.pem")))),
        (
            Value::Text("cabundle".into()),
            Value::Array(vec![Value::Bytes(der(ca!("root.pem"))), Value::Bytes(der(ca!("intermediate.pem")))]),
        ),
        (Value::Text("public_key".into()), Value::Null),
        (Value::Text("user_data".into()), user_data.clone()),
        (Value::Text("nonce".into()), nonce.clone()),
    ];
    let mut payload = Vec::new();
    ciborium::into_writer(&Value::Map(fields), &mut payload).unwrap();
    CoseSign1Builder::new()
        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ES384).build())
        .payload(payload)
        .signature(vec![0; 96])
        .build()
        .to_tagged_vec()
        .unwrap()
}

fn response(document: Vec<u8>) -> Vec<u8> {
    cbor(&Value::Map(vec![(
        Value::Text("Attestation".into()),
        Value::Map(vec![(Value::Text("document".into()), Value::Bytes(document))]),
    )]))
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

/// What an `Attestation` request asked for: (`user_data`, `nonce`, `public_key`).
fn decode_request(request: &[u8]) -> (Value, Value, Value) {
    let Value::Map(mut outer) = ciborium::from_reader::<Value, _>(request).unwrap() else { panic!("not a map") };
    assert_eq!(outer.len(), 1);
    let (Value::Text(variant), Value::Map(fields)) = outer.remove(0) else { panic!("not a struct variant") };
    assert_eq!(variant, "Attestation");
    let names: Vec<_> = fields.iter().map(|(k, _)| k.as_text().unwrap().to_owned()).collect();
    assert_eq!(names, ["user_data", "nonce", "public_key"]);
    let get = |i: usize| fields[i].1.clone();
    (get(0), get(1), get(2))
}

/// Answers as the NSM does; records every request's `user_data` and `nonce`.
struct FakeNsm {
    pcrs: Mutex<Vec<Vec<u8>>>,
    timestamp_ms: Mutex<u64>,
    /// When set, answered instead of a fresh document.
    canned: Mutex<Option<Vec<u8>>>,
    /// Ignore the request's `user_data` and send this.
    user_data: Mutex<Option<Value>>,
    requests: Mutex<Vec<(Value, Value)>>,
}

impl FakeNsm {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            pcrs: Mutex::new((0..16).map(pcr).collect()),
            timestamp_ms: Mutex::new(T_MS),
            canned: Mutex::new(None),
            user_data: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
        })
    }

    fn nonces(&self) -> Vec<Vec<u8>> {
        self.requests.lock().unwrap().iter().filter_map(|(_, n)| n.as_bytes().cloned()).collect()
    }
}

impl Nsm for FakeNsm {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, TeeError> {
        assert!(request.len() <= nsm::MAX_REQUEST);
        let (user_data, nonce, public_key) = decode_request(request);
        assert_eq!(public_key, Value::Null);
        self.requests.lock().unwrap().push((user_data.clone(), nonce.clone()));
        if let Some(canned) = self.canned.lock().unwrap().clone() {
            return Ok(canned);
        }
        let user_data = self.user_data.lock().unwrap().clone().unwrap_or(user_data);
        let doc = document(&self.pcrs.lock().unwrap(), *self.timestamp_ms.lock().unwrap(), &user_data, &nonce);
        Ok(response(doc))
    }
}

fn unavailable_mentioning<T>(r: Result<T, TeeError>, needle: &str) {
    match r {
        Err(TeeError::Unavailable(msg)) => assert!(msg.contains(needle), "{msg:?} does not mention {needle:?}"),
        Err(e) => panic!("expected Unavailable mentioning {needle:?}, got {e}"),
        Ok(_) => panic!("expected Unavailable mentioning {needle:?}, got Ok"),
    }
}

// ---- the device ----

#[test]
fn the_ioctl_is_nsm_ioctl_raw() {
    assert_eq!(nsm::raw::NSM_IOCTL_RAW, 0xC020_0A00);
    assert_eq!(nsm::raw::iowr(0x0A, 0, 32), 0xC020_0A00);
}

#[test]
fn there_is_no_nsm_on_a_test_host() {
    if std::path::Path::new(nsm::DEVICE).exists() {
        return;
    }
    unavailable_mentioning(nsm::NsmDevice::open(), "/dev/nsm");
    unavailable_mentioning(NitroAttestor::new(), "/dev/nsm");
    unavailable_mentioning(NitroClock::new(), "/dev/nsm");
}

#[test]
fn requests_are_the_nsm_api_encoding() {
    let (user_data, nonce, public_key) = decode_request(&nsm::attestation_request(Some(&[7; 32]), None));
    assert_eq!((user_data, nonce, public_key), (Value::Bytes(vec![7; 32]), Value::Null, Value::Null));
    let (user_data, nonce, _) = decode_request(&nsm::attestation_request(None, Some(&[9; 32])));
    assert_eq!((user_data, nonce), (Value::Null, Value::Bytes(vec![9; 32])));
    // The exact bytes `serde_cbor` gives `Request::Attestation` with nothing set.
    let mut expected = vec![0xa1, 0x6b];
    expected.extend_from_slice(b"Attestation");
    expected.push(0xa3);
    for name in ["user_data", "nonce", "public_key"] {
        expected.push(0x60 + name.len() as u8);
        expected.extend_from_slice(name.as_bytes());
        expected.push(0xf6);
    }
    assert_eq!(nsm::attestation_request(None, None), expected);
}

#[test]
fn responses() {
    assert_eq!(nsm::attestation_document(&response(vec![1, 2, 3])).unwrap(), vec![1, 2, 3]);
    let error = cbor(&Value::Map(vec![(Value::Text("Error".into()), Value::Text("InvalidArgument".into()))]));
    unavailable_mentioning(nsm::attestation_document(&error), "error InvalidArgument");
    let other = cbor(&Value::Map(vec![(Value::Text("DescribeNSM".into()), Value::Map(vec![]))]));
    unavailable_mentioning(nsm::attestation_document(&other), "unexpected DescribeNSM");
    for bad in [
        b"\xff".to_vec(),
        cbor(&Value::Text("Attestation".into())),
        cbor(&Value::Map(vec![])),
        response(vec![]),
        cbor(&Value::Map(vec![(Value::Text("Attestation".into()), Value::Map(vec![]))])),
        cbor(&Value::Map(vec![(
            Value::Text("Attestation".into()),
            Value::Map(vec![
                (Value::Text("document".into()), Value::Bytes(vec![1])),
                (Value::Text("document".into()), Value::Bytes(vec![2])),
            ]),
        )])),
        cbor(&Value::Map(vec![(Value::Integer(1.into()), Value::Null)])),
    ] {
        assert!(matches!(nsm::attestation_document(&bad), Err(TeeError::Unavailable(_))), "{bad:?}");
    }
}

proptest! {
    #[test]
    fn arbitrary_responses_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = nsm::attestation_document(&bytes);
    }
}

// ---- the attestor ----

#[tokio::test]
async fn attests_with_the_report_data_as_user_data() {
    let fake = FakeNsm::new();
    let attestor = NitroAttestor::with(fake.clone()).unwrap();
    let p = |i| -> [u8; 48] { pcr(i).try_into().unwrap() };
    assert_eq!(attestor.measurement(), seal_attest::nitro::measurement(&p(0), &p(1), &p(2)));
    // Construction asked once, with all-zero user data.
    assert_eq!(fake.requests.lock().unwrap()[0], (Value::Bytes(vec![0; 32]), Value::Null));

    let Evidence::AwsNitro { document } = attestor.attest([5; 32]).await.unwrap() else { panic!("not Nitro") };
    let stated = seal_attest::nitro::peek(&document).unwrap();
    assert_eq!(stated.user_data, Some(vec![5; 32]));
    assert_eq!(stated.measurement().unwrap(), attestor.measurement());
    assert_eq!(fake.requests.lock().unwrap()[1], (Value::Bytes(vec![5; 32]), Value::Null));
}

#[tokio::test]
async fn refuses_documents_that_disagree() {
    let fake = FakeNsm::new();
    let attestor = NitroAttestor::with(fake.clone()).unwrap();
    // Other PCRs than at construction.
    fake.pcrs.lock().unwrap()[2] = vec![0x99; 48];
    unavailable_mentioning(attestor.attest([5; 32]).await, "other PCRs");
    fake.pcrs.lock().unwrap()[2] = pcr(2);
    // Not the report data asked for.
    *fake.user_data.lock().unwrap() = Some(Value::Bytes(vec![6; 32]));
    unavailable_mentioning(attestor.attest([5; 32]).await, "report data");
    *fake.user_data.lock().unwrap() = Some(Value::Null);
    unavailable_mentioning(attestor.attest([5; 32]).await, "report data");
    // The NSM refuses.
    *fake.canned.lock().unwrap() =
        Some(cbor(&Value::Map(vec![(Value::Text("Error".into()), Value::Text("InternalError".into()))])));
    unavailable_mentioning(attestor.attest([5; 32]).await, "error InternalError");
}

#[tokio::test]
async fn a_debug_enclave_attests_but_its_evidence_is_refused() {
    let fake = FakeNsm::new();
    for i in 0..3 {
        fake.pcrs.lock().unwrap()[i] = vec![0; 48];
    }
    let attestor = NitroAttestor::with(fake).unwrap();
    assert_eq!(attestor.measurement(), seal_attest::nitro::measurement(&[0; 48], &[0; 48], &[0; 48]));
    let Evidence::AwsNitro { document } = attestor.attest([5; 32]).await.unwrap() else { panic!("not Nitro") };
    assert!(matches!(seal_attest::nitro::peek(&document).unwrap().measurement(), Err(AttestError::DebugMode)));
    // A document without the PCRs the measurement is made of.
    let fake = FakeNsm::new();
    fake.pcrs.lock().unwrap().truncate(2);
    unavailable_mentioning(NitroAttestor::with(fake), "no PCR2");
}

// ---- the clock ----

/// The clock's check for these unsigned documents: the stated timestamp, if the nonce is ours.
fn stated(document: &[u8], nonce: &[u8]) -> Result<u64, AttestError> {
    let d = seal_attest::nitro::peek(document)?;
    d.measurement()?;
    if d.nonce.as_deref() != Some(nonce) {
        return Err(AttestError::Rejected("not our nonce".into()));
    }
    Ok(d.timestamp_ms)
}

#[tokio::test(start_paused = true)]
async fn the_clock_takes_a_document_every_refresh_and_counts_between() {
    let fake = FakeNsm::new();
    let clock = NitroClock::with(fake.clone(), stated);
    let first = clock.now().await.unwrap();
    // 1793165986.25 s, ±1 s, rounded outwards: [1793165985, 1793165988].
    assert_eq!(first, TrustedTime { now: 1_793_165_986, radius: 2 });
    let nonces = fake.nonces();
    assert_eq!(nonces.len(), 1);
    assert_eq!(nonces[0].len(), 32);
    assert_eq!(fake.requests.lock().unwrap()[0].0, Value::Null, "no user data");

    // Within REFRESH: no new document, the monotonic clock advances the reading. The NSM's own
    // time is ignored meanwhile.
    *fake.timestamp_ms.lock().unwrap() = 1;
    tokio::time::advance(std::time::Duration::from_secs(30)).await;
    assert_eq!(clock.now().await.unwrap(), TrustedTime { now: 1_793_166_016, radius: 2 });
    assert_eq!(fake.nonces().len(), 1);

    // At REFRESH: a new document, with a new nonce, and its time.
    *fake.timestamp_ms.lock().unwrap() = T_MS + 3_600_000;
    tokio::time::advance(REFRESH - std::time::Duration::from_secs(30)).await;
    assert_eq!(clock.now().await.unwrap(), TrustedTime { now: 1_793_169_586, radius: 2 });
    let nonces = fake.nonces();
    assert_eq!(nonces.len(), 2);
    assert_ne!(nonces[0], nonces[1]);
}

#[tokio::test(start_paused = true)]
async fn the_clock_fails_closed_and_tries_again() {
    let fake = FakeNsm::new();
    let clock = NitroClock::with(fake.clone(), stated);
    // A replayed document: someone else's nonce.
    let replayed = document(&[pcr(0), pcr(1), pcr(2)], T_MS, &Value::Null, &Value::Bytes(vec![1; 32]));
    *fake.canned.lock().unwrap() = Some(response(replayed));
    unavailable_mentioning(clock.now().await, "clock document");
    // A debug enclave's document.
    *fake.canned.lock().unwrap() =
        Some(response(document(&[vec![0; 48], vec![0; 48], vec![0; 48]], T_MS, &Value::Null, &Value::Null)));
    unavailable_mentioning(clock.now().await, "clock document");
    // The NSM refuses.
    *fake.canned.lock().unwrap() =
        Some(cbor(&Value::Map(vec![(Value::Text("Error".into()), Value::Text("InternalError".into()))])));
    unavailable_mentioning(clock.now().await, "error InternalError");
    // Each failure asked again; the next good document is used at once.
    *fake.canned.lock().unwrap() = None;
    assert_eq!(clock.now().await.unwrap().now, 1_793_165_986);
    assert_eq!(fake.nonces().len(), 4);
}

#[tokio::test]
async fn the_production_check_wants_the_aws_chain() {
    // The fake's documents chain to the test root, so the real check refuses them.
    let clock = NitroClock::with(FakeNsm::new(), seal_attest::nitro::verify_timestamp);
    unavailable_mentioning(clock.now().await, "AWS Nitro root");
}

#[test]
fn readings_round_outwards_and_carry_the_monotonic_clock() {
    let received = Instant::now();
    let ms = std::time::Duration::from_millis;
    let reading = Reading { timestamp_ms: T_MS, in_flight: ms(300), received };
    // [985.25, 987.55] → [985, 988].
    assert_eq!(reading.time_at(received), TrustedTime { now: 1_793_165_986, radius: 2 });
    assert_eq!(reading.time_at(received + ms(30_000)), TrustedTime { now: 1_793_166_016, radius: 2 });
    // An instant before the reading counts as the reading's own.
    assert_eq!(reading.time_at(received - ms(5_000)), reading.time_at(received));
    // On a whole second with no time in flight: [T - 1, T + 1].
    let exact = Reading { timestamp_ms: 1_000_000, in_flight: ms(0), received };
    assert_eq!(exact.time_at(received), TrustedTime { now: 1_000, radius: 1 });
}

proptest! {
    /// The interval always holds `[timestamp + carried - RADIUS, timestamp + carried + in_flight + RADIUS]`.
    #[test]
    fn readings_cover_their_interval(
        timestamp_ms in 2_000u64..4_000_000_000_000,
        in_flight_ms in 0u64..10_000,
        carried_ms in 0u64..120_000,
    ) {
        let received = Instant::now();
        let reading = Reading {
            timestamp_ms,
            in_flight: std::time::Duration::from_millis(in_flight_ms),
            received,
        };
        let t = reading.time_at(received + std::time::Duration::from_millis(carried_ms));
        let base = timestamp_ms + carried_ms;
        prop_assert!(t.earliest() * 1000 <= base - 1000);
        prop_assert!(t.latest() * 1000 >= base + in_flight_ms + 1000);
        // And no wider than the rounding needs.
        prop_assert!(t.latest() - t.earliest() <= (in_flight_ms + 2000) / 1000 + 3);
    }
}

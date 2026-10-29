//! Decoding never panics. Enclaves and guardians decode these types from bytes an attacker
//! chooses (API bodies, control-plane responses, tunnel preambles, guardian requests and
//! responses), as JSON or canonical CBOR, and a panic there would take down a task or the
//! replica. Valid samples are built from the wire vectors (`tests/vectors/wire-v1.json`), so a
//! mutation lands inside nested, tagged and validated fields, not only in the outer framing.

use std::collections::BTreeMap;
use std::str::FromStr;

use proptest::prelude::*;
use seal_proto::api::*;
use seal_proto::blob::Blob;
use seal_proto::codec::{canonical, from_canonical};
use seal_proto::control::{AttestedControlRequest, ControlRequest, SignedControlRequest};
use seal_proto::freshness::{GuardianChallenge, ProofTicket};
use seal_proto::identity::*;
use seal_proto::integrity::*;
use seal_proto::net::Cidr;
use seal_proto::policy::SecretPolicy;
use seal_proto::release::*;
use seal_proto::session::*;
use seal_proto::signed::{Signature, Signed};
use seal_proto::state::*;
use seal_proto::telemetry::*;
use seal_proto::tunnel::{TunnelPreamble, MAGIC};
use seal_proto::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

fn vectors() -> BTreeMap<String, Vec<u8>> {
    let text = include_str!("vectors/wire-v1.json");
    let list: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    list.into_iter()
        .map(|v| (v["name"].as_str().unwrap().to_owned(), hex::decode(v["bytes"].as_str().unwrap()).unwrap()))
        .collect()
}

fn piece<T: DeserializeOwned>(v: &BTreeMap<String, Vec<u8>>, name: &str) -> T {
    from_canonical(&v[name]).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn signed<T>(body: T, sig: &Signature) -> Signed<T> {
    Signed { body, signatures: vec![sig.clone()] }
}

/// Every untrusted top-level value, valid, in canonical CBOR and in JSON, plus the text forms.
fn samples() -> Vec<Vec<u8>> {
    let v = vectors();
    let sig = piece::<Signed<u8>>(&v, "signed/envelope").signatures.remove(0);
    let logged: LoggedState = piece(&v, "state/logged-state");
    let proof = logged.proof.clone();
    let checkpoint = proof.checkpoint.clone();
    let root: TenantRoot = piece(&v, "state/tenant-root-v1");
    let state: TenantState = piece(&v, "state/tenant-state-hosted");
    let evidence: Evidence = piece(&v, "evidence/azure-snp-aci");
    let context: ProofContext = piece(&v, "identity/proof-context");
    let policy: SecretPolicy = piece(&v, "blob/policy");
    let blob = String::from_utf8(v["blob/text"].clone()).unwrap();

    let bundle = TenantBundle {
        root_chain: vec![LoggedRoot { root: signed(root, &sig), proof: proof.clone() }],
        state: signed(state, &sig),
        signals: vec![signed(piece(&v, "integrity/signal"), &sig)],
        ended_sessions: vec![signed(piece(&v, "session/end"), &sig)],
        freshness: vec![signed(piece(&v, "state/freshness"), &sig)],
        wrap_keys: vec![signed(piece(&v, "guardian/tenant-wrap-key"), &sig)],
        states: vec![logged],
        checkpoint: Some(checkpoint.clone()),
        anchors: vec![signed(piece(&v, "state/tenant-anchor"), &sig)],
    };
    let release = ReleaseEvidence {
        manifest: signed(piece(&v, "release/manifest"), &sig),
        included: proof.clone(),
        fresh: checkpoint.clone(),
        auditor: Some(sig.clone()),
    };
    let key_request = KeyRequest {
        protocol_version: GUARDIAN_PROTOCOL_VERSION,
        evidence: evidence.clone(),
        binding: piece(&v, "binding/key-request/tenant"),
        release: release.clone(),
        tenant: Some(bundle.clone()),
        tenant_cosign: Some(signed(piece(&v, "release/cosign"), &sig)),
    };
    let certificate: SignedServiceKeyCertificate = signed(piece(&v, "guardian/service-key-certificate"), &sig);
    let secret = |b: u8| SecretVec::new(vec![b; 32]);
    let released = [
        ReleasedKeys::Service {
            tenant: bundle.state.body.tenant.clone(),
            root_id: TenantRootId([5; 32]),
            service_key_version: ServiceKeyVersion(1),
            token: secret(1),
            ingest: secret(2),
            telemetry: secret(3),
            tls: secret(4),
            ticket: secret(5),
            telemetry_public_keys: vec![(ServiceKeyVersion(1), PublicKey([6; 32]))],
            certificate: certificate.clone(),
        },
        ReleasedKeys::Root { platform: PlatformId::AzureSnpAci, root: secret(7) },
        ReleasedKeys::Tenant {
            tenant: bundle.state.body.tenant.clone(),
            root_id: TenantRootId([5; 32]),
            keys: vec![(TenantKeyVersion(1), secret(8))],
        },
    ];
    let endpoint = EndpointReport {
        artifact: Some(ArtifactHash { name: "executable".into(), sha256: [9; 32] }),
        evidence: vec![EndpointEvidence { provider: "tpm".into(), bytes: vec![10; 16] }],
    };
    let proofs = || {
        [
            IdentityProof::Oidc {
                provider: OidcProvider::GitHub,
                jwt: Bearer::new("eyJhbGciOiJSUzI1NiJ9.e30.c2ln".into()),
            },
            IdentityProof::AwsSigV4 {
                method: "POST".into(),
                url: "https://sts.amazonaws.com/".into(),
                headers: vec![("x-seal-binding".into(), Bearer::new("00".repeat(32)))],
                body: "Action=GetCallerIdentity&Version=2011-06-15".into(),
            },
            IdentityProof::AppKey { key_id: KeyId([11; 32]), signature: vec![12; 64] },
        ]
    };
    let telemetry = [
        signed(piece::<TelemetryBatch>(&v, "telemetry/batch-clear"), &sig),
        signed(piece::<TelemetryBatch>(&v, "telemetry/batch-sealed"), &sig),
    ];
    let control: ControlRequest = piece(&v, "control/request");

    let mut out = Vec::new();
    fn both<T: Serialize>(out: &mut Vec<Vec<u8>>, value: &T) {
        out.push(canonical(value));
        out.push(serde_json::to_vec(value).unwrap());
    }
    both(&mut out, &bundle);
    both(&mut out, &release);
    both(&mut out, &key_request);
    both(&mut out, &KeyResponse { hpke_enc: vec![13; 32], ciphertext: vec![14; 64], signature: sig.clone() });
    for keys in &released {
        both(&mut out, keys);
    }
    both(
        &mut out,
        &SealRequest {
            service_key_version: ServiceKeyVersion(1),
            hpke_enc: vec![15; 32],
            sealed_payload: vec![16; 64],
        },
    );
    both(&mut out, &SealPayload { secret: secret(17), policy });
    for proof in proofs() {
        both(
            &mut out,
            &SessionRequest {
                blob: blob.clone(),
                context: context.clone(),
                proof,
                min_tier: Some(ConsumerTier::Base),
                endpoint: Some(endpoint.clone()),
            },
        );
    }
    for proof in proofs() {
        both(
            &mut out,
            &ExtendRequest {
                token: Bearer::new("sealtok_example".into()),
                endpoint: Some(endpoint.clone()),
                context: context.clone(),
                proof,
            },
        );
    }
    both(&mut out, &EndRequest { token: Bearer::new("sealtok_example".into()) });
    both(
        &mut out,
        &SignalRequest {
            code: "edr-high".into(),
            severity: Severity::High,
            context: Some(context.clone()),
            proof: proofs().into_iter().next(),
            identity: None,
            observed_at: None,
            blob_id: None,
            signatures: Vec::new(),
        },
    );
    both(
        &mut out,
        &SignalRequest {
            code: "edr-high".into(),
            severity: Severity::Critical,
            context: None,
            proof: None,
            identity: Some(WorkloadIdentity::AppKey { key_id: KeyId([18; 32]) }),
            observed_at: Some(1_900_000_000),
            blob_id: Some(BlobId([19; 8])),
            signatures: vec![sig.clone()],
        },
    );
    for batch in &telemetry {
        both(&mut out, batch);
    }
    both(&mut out, &signed(control.clone(), &sig));
    both(&mut out, &AttestedControlRequest { request: control, evidence });
    both(&mut out, &certificate);
    both(&mut out, &piece::<GuardianChallenge>(&v, "freshness/guardian-challenge"));
    both(&mut out, &piece::<ProofTicket>(&v, "freshness/proof-ticket"));
    for name in ["tunnel/connect", "tunnel/extend"] {
        let framed = &v[name];
        out.push(framed[MAGIC.len() + 4..].to_vec());
        out.push(framed.clone());
    }
    out.push(blob.into_bytes());
    out.push(v["text/tenant-pin"].clone());
    out.push(b"2001:db8::/32".to_vec());
    // Every vector as it is: each is a valid encoding of some type.
    out.extend(v.into_values());
    out
}

/// Decodes `bytes` as every untrusted top-level type, in both encodings, and as each text form.
fn decode_everything(bytes: &[u8]) {
    macro_rules! each {
        ($($t:ty),* $(,)?) => {$(
            let _ = from_canonical::<$t>(bytes);
            let _ = serde_json::from_slice::<$t>(bytes);
        )*};
    }
    each!(
        TenantBundle,
        SignedTenantState,
        Signed<TenantRoot>,
        ReleaseEvidence,
        SignedCheckpoint,
        TlogProof,
        KeyRequest,
        KeyResponse,
        ReleasedKeys,
        SealRequest,
        SealPayload,
        SessionRequest,
        ExtendRequest,
        EndRequest,
        SignalRequest,
        TunnelPreamble,
        SignedTelemetryBatch,
        TelemetryEntries,
        Vec<TelemetryEntry>,
        AttestedControlRequest,
        SignedControlRequest,
        SignedServiceKeyCertificate,
        Evidence,
        Blob,
        SecretPolicy,
        GuardianChallenge,
        ProofTicket,
        LogEntry,
    );
    let text = String::from_utf8_lossy(bytes);
    let _ = Blob::from_str(&text);
    let _ = TenantPin::from_str(&text);
    let _ = TenantPin::parse_partial(&text);
    let _ = Cidr::from_str(&text);
    let _ = seal_proto::codec::from_b64url(&text);
    let _ = seal_proto::tunnel::find_local_key(&text);
}

static SAMPLES: std::sync::LazyLock<Vec<Vec<u8>>> = std::sync::LazyLock::new(samples);

#[test]
fn samples_decode() {
    // The seeds are valid, so mutations start from inside the format.
    let s = &*SAMPLES;
    let v = vectors();
    let blob = std::str::from_utf8(&v["blob/text"]).unwrap();
    assert!(Blob::from_str(blob).is_ok());
    assert!(from_canonical::<TenantBundle>(&s[0]).is_ok());
    assert!(serde_json::from_slice::<TenantBundle>(&s[1]).is_ok());
    assert!(from_canonical::<KeyRequest>(&s[4]).is_ok());
    assert!(serde_json::from_slice::<KeyRequest>(&s[5]).is_ok());
}

/// Deep nesting is refused by the decoders' recursion limits, not by overflowing the stack.
#[test]
fn deep_nesting_is_refused() {
    let depth = 100_000;
    let mut cbor = vec![0x81; depth];
    cbor.push(0x00);
    let json = [vec![b'['; depth], vec![b']'; depth]].concat();
    for bytes in [cbor, json] {
        decode_everything(&bytes);
    }
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        decode_everything(&bytes);
    }

    #[test]
    fn mutated_samples_never_panic(
        sample in any::<prop::sample::Index>(),
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
        cut in proptest::option::of(any::<prop::sample::Index>()),
    ) {
        let samples = &*SAMPLES;
        let mut bytes = samples[sample.index(samples.len())].clone();
        for (at, byte) in edits {
            let i = at.index(bytes.len());
            bytes[i] = byte;
        }
        if let Some(cut) = cut {
            bytes.truncate(cut.index(bytes.len()));
        }
        decode_everything(&bytes);
    }
}

//! `Trust::from_json` against the committed example trust.

use seal_proto::{ErrorCode, PlatformId};
use seal_verify::{Trust, TrustError};

const EXAMPLE: &str = include_str!("../../../../deploy/example/trust.json");

fn edited(edit: impl FnOnce(&mut serde_json::Value)) -> Result<Trust, TrustError> {
    let mut value: serde_json::Value = serde_json::from_str(EXAMPLE).unwrap();
    edit(&mut value);
    Trust::from_json(value.to_string().as_bytes())
}

#[test]
fn reads_the_example_trust() {
    let trust = Trust::from_json(EXAMPLE.as_bytes()).unwrap();
    assert_eq!(trust.releases.release_keys.len(), 3);
    assert_eq!(trust.releases.release_threshold, 2);
    assert_eq!(trust.releases.required_auditor, None);
    assert_eq!(trust.releases.time_lock_secs, 60);
    assert_eq!(trust.releases.tlog.origin, "dev.log.seal.zone/v1");
    assert_eq!(trust.releases.tlog.witness_quorum, 2);
    assert_eq!(trust.tenants.registrar_keys.len(), 1);
    assert_eq!(trust.tenants.registrar_threshold, 1);
    assert!(trust.guardians.contains_key(&PlatformId::AzureSnpAci));
    assert!(trust.guardians.contains_key(&PlatformId::GcpConfidentialSpace));
}

#[test]
fn refuses_unknown_fields_and_unmeetable_thresholds() {
    let malformed = |r: Result<Trust, TrustError>| {
        let e = r.expect_err("refused");
        assert_eq!(e.code(), ErrorCode::BadRequest);
        e.to_string()
    };
    malformed(edited(|v| v["extra"] = true.into()));
    malformed(edited(|v| v["releases"]["tlog"]["extra"] = true.into()));
    malformed(edited(|v| v["tenants"]["registrar_keys"][0] = "not hex".into()));
    malformed(edited(|v| {
        v["releases"].as_object_mut().unwrap().remove("time_lock_secs");
    }));
    assert!(malformed(edited(|v| v["releases"]["release_threshold"] = 0.into())).contains("is 0"));
    assert!(malformed(edited(|v| v["releases"]["release_threshold"] = 4.into())).contains("more than its 3 keys"));
    assert!(malformed(edited(|v| v["tenants"]["registrar_threshold"] = 2.into())).contains("registrar_threshold"));
    assert!(malformed(edited(|v| v["tenants"]["tlog"]["witness_quorum"] = 0.into())).contains("witness_quorum"));
    // Guardians are optional: a trust may name none yet.
    assert!(edited(|v| {
        v.as_object_mut().unwrap().remove("guardians");
    })
    .unwrap()
    .guardians
    .is_empty());
}

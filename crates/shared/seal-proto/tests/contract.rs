use seal_proto::{
    api::{ExtendRequest, SealRequest, SessionRequest},
    codec,
    freshness::ProofTicket,
    identity::{IdentityProof, ProofContext, ProofPurpose},
    policy::{HttpPath, HttpRules, Injection, SecretPolicy},
    session::ConsumerTier,
    AppName, KeyId, ServiceKeyVersion, TenantId,
};

fn policy() -> SecretPolicy {
    SecretPolicy::new("https://api.example.com/v1", [AppName::new("checkout").unwrap()]).unwrap()
}

#[test]
fn policy_decoding_cannot_bypass_constructors() {
    let valid = serde_json::to_value(policy()).unwrap();
    let mut empty_apps = valid.clone();
    empty_apps["apps"] = serde_json::json!([]);
    let mut bad_injection = valid.clone();
    bad_injection["injection"]["header"] = serde_json::json!("host");
    let mut bad_template = valid.clone();
    bad_template["injection"]["format"] = serde_json::json!("Bearer \u{0}{key}");
    let mut bad_destination = valid.clone();
    bad_destination["destination"]["host"] = serde_json::json!("");
    for malformed in [empty_apps, bad_injection, bad_template, bad_destination] {
        assert!(serde_json::from_value::<SecretPolicy>(malformed.clone()).is_err());
        // Same invariants must hold over CBOR, not only the human-readable transport.
        assert!(codec::from_canonical::<SecretPolicy>(&codec::canonical(&malformed)).is_err());
    }
    assert_eq!(serde_json::from_value::<SecretPolicy>(valid).unwrap(), policy());
}

#[test]
fn http_options_are_rejected_for_database_targets() {
    let p = SecretPolicy::new("postgres://app@db/orders", [AppName::new("checkout").unwrap()]).unwrap();
    assert!(p.with_http(Injection::default(), HttpRules::default()).is_err());
}

#[test]
fn policy_and_adapter_paths_share_one_unambiguous_representation() {
    for path in ["relative", "/v1/../admin", "/v1/%2fadmin", "/v1//admin", "/v1\\admin", "/v1?q=1", "/v1\0"] {
        assert!(HttpPath::parse(path).is_err(), "{path:?}");
        let rules = HttpRules { methods: Default::default(), deny_path_prefixes: [path.to_owned()].into() };
        assert!(policy().with_http(Injection::default(), rules).is_err());
    }
    assert!(HttpPath::parse("/v1/orders").is_ok());
    let rules = HttpRules { methods: ["get".to_owned()].into(), deny_path_prefixes: Default::default() };
    assert!(policy().with_http(Injection::default(), rules).is_err());
}

fn context() -> ProofContext {
    ProofContext {
        tenant: TenantId::new("acme").unwrap(),
        purpose: ProofPurpose::Session { request_digest: [0; 32] },
        tls_spki_sha256: [1; 32],
        ticket: ProofTicket { value: [2; 32], expires_at: 120, mac: [3; 32] },
    }
}
fn proof() -> IdentityProof {
    IdentityProof::AppKey { key_id: KeyId([4; 32]), signature: vec![5; 64] }
}
fn session() -> SessionRequest {
    SessionRequest { blob: "opaque-blob".into(), context: context(), proof: proof(), min_tier: None, endpoint: None }
}

#[test]
fn session_commitment_covers_every_operation_field() {
    let expected = session().expected_purpose();
    let mut changed = session();
    changed.blob.push('x');
    assert_ne!(expected, changed.expected_purpose());
    let mut changed = session();
    changed.min_tier = Some(ConsumerTier::Hardened);
    assert_ne!(expected, changed.expected_purpose());
    let mut changed = session();
    changed.endpoint = Some(Default::default());
    assert_ne!(expected, changed.expected_purpose());
}

#[test]
fn upload_encryption_precedes_proof_without_a_circular_binding() {
    let mut upload = SealRequest {
        service_key_version: ServiceKeyVersion(1),
        hpke_enc: vec![1],
        sealed_payload: vec![2],
        context: context(),
        proof: proof(),
    };
    let aad = codec::canonical(&upload.ingest_context());
    let expected = upload.expected_purpose();
    upload.sealed_payload.push(3);
    assert_ne!(expected, upload.expected_purpose());
    assert_eq!(aad, codec::canonical(&upload.ingest_context()));
    let expected = upload.expected_purpose();
    upload.hpke_enc.push(4);
    assert_ne!(expected, upload.expected_purpose());
    assert_eq!(aad, codec::canonical(&upload.ingest_context()));
    let expected = upload.expected_purpose();
    upload.service_key_version = ServiceKeyVersion(2);
    assert_ne!(expected, upload.expected_purpose());
    assert_ne!(aad, codec::canonical(&upload.ingest_context()));
}

#[test]
fn outer_proof_context_binds_tenant_server_and_ticket() {
    let original = context();
    let expected = codec::labeled_digest(seal_proto::identity::PROOF_CONTEXT_LABEL, &original);
    let mut tenant = original.clone();
    tenant.tenant = TenantId::new("other").unwrap();
    let mut server = original.clone();
    server.tls_spki_sha256[0] ^= 1;
    let mut ticket = original.clone();
    ticket.ticket.value[0] ^= 1;
    for changed in [tenant, server, ticket] {
        assert_ne!(expected, codec::labeled_digest(seal_proto::identity::PROOF_CONTEXT_LABEL, &changed));
    }
}

#[test]
fn extend_commitment_covers_token_and_endpoint_report() {
    let extend = || ExtendRequest {
        token: seal_proto::Bearer::new("sealtok_a".into()),
        endpoint: None,
        context: context(),
        proof: proof(),
    };
    let expected = extend().expected_purpose();
    let mut changed = extend();
    changed.token = seal_proto::Bearer::new("sealtok_b".into());
    assert_ne!(expected, changed.expected_purpose());
    let mut changed = extend();
    changed.endpoint = Some(Default::default());
    assert_ne!(expected, changed.expected_purpose());
}

#[test]
fn identities_match_on_immutable_ids_not_names() {
    use seal_proto::identity::{GitHubScope, IdentityMatcher, WorkloadIdentity};
    let grant = IdentityMatcher::GitHub {
        repository: "acme/api".into(),
        repository_id: 101,
        repository_owner_id: 7,
        scope: GitHubScope::Environment("prod".into()),
    };
    let caller = |repository: &str, repository_id, repository_owner_id| WorkloadIdentity::GitHub {
        repository: repository.into(),
        repository_id,
        repository_owner_id,
        environment: Some("prod".into()),
        git_ref: "refs/heads/main".into(),
    };
    assert!(grant.matches(&caller("acme/api", 101, 7)));
    // A rename keeps the grant; the same name recreated by someone else does not get it.
    assert!(grant.matches(&caller("acme/api-v2", 101, 7)));
    assert!(!grant.matches(&caller("acme/api", 202, 7)));
    assert!(!grant.matches(&caller("acme/api", 101, 8)));

    let role = IdentityMatcher::AwsRole { role_arn: "arn:aws:iam::1:role/app".into(), role_id: "AROA1".into() };
    let assumed = |role_id: &str| WorkloadIdentity::AwsRole {
        account: "1".into(),
        role_arn: "arn:aws:iam::1:role/app".into(),
        role_id: role_id.into(),
    };
    assert!(role.matches(&assumed("AROA1")));
    assert!(!role.matches(&assumed("AROA2")), "a recreated role keeps its ARN but not its id");
}

#[test]
fn evidence_challenge_binds_the_request_but_not_the_report() {
    let mut request = session();
    let base = request.evidence_challenge();
    // The report is not covered (that is the point: it is computable before the report
    // exists, and using expected_purpose would be circular).
    request.endpoint = Some(Default::default());
    assert_eq!(base, request.evidence_challenge());
    let mut bare = session();
    bare.endpoint = None;
    assert_eq!(base, bare.evidence_challenge());
    // Everything else is covered.
    request.blob.push('x');
    assert_ne!(base, request.evidence_challenge());
    let mut tiered = session();
    tiered.min_tier = Some(ConsumerTier::Hardened);
    assert_ne!(base, tiered.evidence_challenge());
    // With a report present, the proof digest (which covers it) and the challenge differ;
    // with no report they coincide, which is fine — nothing is being protected yet.
    let mut with_report = session();
    with_report.endpoint = Some(Default::default());
    assert_ne!(
        with_report.expected_purpose(),
        ProofPurpose::Session { request_digest: with_report.evidence_challenge() }
    );
    // Extend binds the token.
    let extend = || ExtendRequest {
        token: seal_proto::Bearer::new("sealtok_a".into()),
        endpoint: None,
        context: context(),
        proof: proof(),
    };
    let ebase = extend().evidence_challenge();
    let mut with_report = extend();
    with_report.endpoint = Some(Default::default());
    assert_eq!(ebase, with_report.evidence_challenge());
    let mut other_token = extend();
    other_token.token = seal_proto::Bearer::new("sealtok_b".into());
    assert_ne!(ebase, other_token.evidence_challenge());
}

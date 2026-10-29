//! The SDK against an in-test enclave (`common/fixture.rs`).
#![cfg(feature = "sim")]

include!("common/fixture.rs");

#[tokio::test]
async fn verifies_the_honest_enclave() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let enclave = client.enclave().await.unwrap();
    assert_eq!(enclave.tls_spki_sha256(), &f.enclave.keys.tls.spki_sha256());
    assert_eq!((enclave.tenant(), enclave.root_id()), (&acme(), &ROOT));
    assert_eq!(enclave.measurement(), &MEASUREMENT);
    assert_eq!(enclave.release_version(), "0.1.0");
    // Without a root id, any root of the tenant is accepted.
    Client::builder()
        .endpoints([f.endpoint()])
        .tenant(acme())
        .trust(f.trust.clone())
        .identity(Arc::new(AppKeyIdentity::from_seed(&APP_KEY_SEED)))
        .connect()
        .await
        .unwrap();
}

/// The trust JSON a client is handed (`trust.json`), loaded with `seal::Trust::from_json`.
#[tokio::test]
async fn connects_with_a_trust_read_from_json() {
    let f = Fixture::new().await;
    let tlog = |t: &seal_tlog::TlogTrust| {
        serde_json::json!({
            "origin": t.origin, "log_key": t.log_key, "witness_keys": t.witness_keys, "witness_quorum": t.witness_quorum,
        })
    };
    let r = &f.trust.releases;
    let json = serde_json::json!({
        "releases": {
            "tlog": tlog(&r.tlog), "release_keys": r.release_keys, "release_threshold": r.release_threshold,
            "required_auditor": null, "time_lock_secs": r.time_lock_secs,
        },
        "tenants": {"tlog": tlog(&f.trust.tenants.tlog), "registrar_keys": [], "registrar_threshold": 0},
        "guardians": f.trust.guardians,
    });
    // A threshold no key set can meet is refused before anything is fetched.
    let err = seal::Trust::from_json(json.to_string().as_bytes()).err().unwrap();
    assert_eq!(ClientError::from(err).code(), ErrorCode::BadRequest);
    let mut json = json;
    json["tenants"]["registrar_keys"] = serde_json::json!([f.trust.releases.release_keys[0]]);
    json["tenants"]["registrar_threshold"] = 1.into();
    let trust = seal::Trust::from_json(json.to_string().as_bytes()).unwrap();
    f.builder().trust(trust.clone()).connect().await.unwrap();
    // The same file with another guardian key accepts no enclave.
    json["guardians"]["sim"] = serde_json::json!(f.trust.releases.release_keys[0]);
    let other = seal::Trust::from_json(json.to_string().as_bytes()).unwrap();
    assert!(matches!(f.builder().trust(other).connect().await, Err(ClientError::Verification(_))));
}

#[tokio::test]
async fn refuses_enclaves_that_do_not_verify() {
    let f = Fixture::new().await;
    let cases = [
        (Attest::TamperedMeasurement, "measurement"),
        (Attest::WrongTlsKey, "TLS key"),
        (Attest::UnsignedCertificate, "guardian"),
        (Attest::ForeignGuardian, "guardian"),
        (Attest::NoCertificate, "certificate"),
        (Attest::Stale, "120 s"),
    ];
    for (mode, says) in cases {
        f.attest(mode);
        match f.client_result().await {
            Err(ClientError::Verification(m)) => assert!(m.contains(says), "{mode:?}: {m}"),
            other => panic!("{mode:?}: {:?}", other.map(|_| ())),
        }
    }
    f.attest(Attest::Honest);

    // Another root chain for the same tenant name, or another tenant.
    let err = f.builder().root_id(TenantRootId([9; 32])).connect().await.err().unwrap();
    assert!(matches!(&err, ClientError::Verification(m) if m.contains("root chain")), "{err}");
    let pinned = seal::Client::builder().endpoints([f.endpoint()]).trust(f.trust.clone());
    let err = pinned.tenant(format!("acme@{}", TenantRootId([9; 32]))).connect().await.err().unwrap();
    assert!(matches!(&err, ClientError::Verification(m) if m.contains("root chain")), "a pinned root: {err}");
    let err = f.builder().tenant("globex").connect().await.err().unwrap();
    assert!(matches!(&err, ClientError::Verification(m) if m.contains("tenant")), "{err}");
    assert_eq!(err.code(), ErrorCode::VerificationFailed);

    // Strings are checked before anything is sent.
    let err = f.builder().tenant("Acme").connect().await.err().unwrap();
    assert_eq!(err.code(), ErrorCode::BadRequest, "{err}");
    let err = f.builder().endpoints(["not a url"]).connect().await.err().unwrap();
    assert!(matches!(&err, ClientError::Invalid(m) if m.starts_with("endpoint not a url")), "{err}");

    // A trust without the guardian's key accepts no certificate.
    let mut trust = f.trust.clone();
    trust.guardians.clear();
    assert!(matches!(f.builder().trust(trust).connect().await, Err(ClientError::Verification(_))));
    // Nor a release signed by too few release keys.
    let mut trust = f.trust.clone();
    trust.releases.release_threshold = 3;
    assert!(
        matches!(f.builder().trust(trust).connect().await, Err(ClientError::Verification(m)) if m.contains("release"))
    );
}

#[tokio::test]
async fn fails_over_to_a_replica_that_answers() {
    let f = Fixture::new().await;
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let client = f.builder().endpoints([format!("https://{dead}"), f.endpoint().to_string()]).connect().await.unwrap();
    client.signal("edr-alert", Severity::High).await.unwrap();
    // With no replica reachable, connecting keeps trying (`UNREACHABLE_WAIT_SECS`).
    let only_dead = f.builder().endpoints([format!("https://{dead}")]).connect();
    assert!(tokio::time::timeout(Duration::from_secs(3), only_dead).await.is_err(), "still retrying");
}

/// An address nothing listens on, for a replica started later.
async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap()
}

/// Serves the in-test enclave at `addr` after `delay`, until the handle is aborted.
fn replica_at(enclave: Arc<Enclave>, addr: SocketAddr, delay: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let listener = TcpListener::bind(addr).await.unwrap();
        let tls = tls_config(&enclave.keys);
        serve(enclave, listener, tls).await
    })
}

/// Stops a replica: its listener and every connection close.
async fn stop(replica: tokio::task::JoinHandle<()>) {
    replica.abort();
    let _ = replica.await;
}

#[tokio::test]
async fn waits_for_a_replica_that_is_not_up_yet() {
    let f = Fixture::new().await;
    let addr = free_addr().await;
    // Nothing listens until a second after the client starts connecting, as with a replica
    // restarting or a hosted one cold-starting.
    let replica = replica_at(f.enclave.clone(), addr, Duration::from_secs(1));
    let client = f.builder().endpoints([format!("https://{addr}")]).connect().await.unwrap();
    // It stops and comes back: a call in between waits for it.
    stop(replica).await;
    let replica = replica_at(f.enclave.clone(), addr, Duration::from_secs(1));
    client.signal("edr-alert", Severity::Low).await.unwrap();
    assert_eq!(f.seen(|s| s.signals.clone()), [("edr-alert".to_string(), Severity::Low)]);
    stop(replica).await;
}

#[tokio::test]
async fn the_tunnel_holds_connections_while_its_replica_restarts() {
    let f = Fixture::new().await;
    let addr = free_addr().await;
    let replica = replica_at(f.enclave.clone(), addr, Duration::ZERO);
    let endpoint: url::Url = format!("https://{addr}").parse().unwrap();
    let client = f.builder().endpoints([endpoint]).connect().await.unwrap();
    let s = client.session(&f.blob("https://api.example.com/v1")).http().await.unwrap();
    let tunnel = tunnel_addr(s.url());
    let mut conn = TcpStream::connect(tunnel).await.unwrap();
    assert_eq!(http(&mut conn, "/", s.key()).await.0, "HTTP/1.1 200 OK");
    eventually("a spare", || f.seen(|s| s.tunnel_handshakes == 2)).await;

    // The replica stops, closing the spare, and is back a second later: an app connection
    // made meanwhile is held until it answers.
    stop(replica).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let replica = replica_at(f.enclave.clone(), addr, Duration::from_secs(1));
    let mut conn = TcpStream::connect(tunnel).await.unwrap();
    assert_eq!(http(&mut conn, "/", s.key()).await.0, "HTTP/1.1 200 OK");
    s.close().await.unwrap();
    stop(replica).await;
}

#[tokio::test]
async fn the_tunnel_keeps_a_handshaken_spare() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let s = client.session(&f.blob("https://api.example.com/v1")).http().await.unwrap();
    let addr = tunnel_addr(s.url());
    let mut first = TcpStream::connect(addr).await.unwrap();
    assert_eq!(http(&mut first, "/", s.key()).await.0, "HTTP/1.1 200 OK");
    eventually("a spare after the first connection", || f.seen(|s| s.tunnel_handshakes == 2)).await;
    // The next connection takes the spare, and another spare is opened behind it.
    let mut second = TcpStream::connect(addr).await.unwrap();
    assert_eq!(http(&mut second, "/", s.key()).await.0, "HTTP/1.1 200 OK");
    eventually("the spare replaced", || f.seen(|s| s.tunnel_handshakes == 3)).await;
    assert_eq!(f.seen(|s| s.connects.len()), 2);
    s.close().await.unwrap();
}

#[tokio::test]
async fn seals_to_the_attested_ingest_key() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let blob = client
        .seal(b"sk-live-0123456789", "https://api.example.com/v1", ["checkout"])
        .header("x-api-key")
        .deny("/v1/keys")
        .await
        .unwrap();
    let parsed: Blob = blob.parse().unwrap();
    assert_eq!((parsed.header.tenant.clone(), parsed.header.root_id), (acme(), ROOT));
    let (secret, policy) = f.seen(|s| s.sealed[0].clone());
    assert_eq!(secret, b"sk-live-0123456789");
    assert_eq!(policy.injection().unwrap().header, "x-api-key");
    assert_eq!(parsed.policy, policy);

    // Bad arguments never reach the enclave.
    let err = client.seal(b"x", "http://plain.example.com", ["checkout"]).await.unwrap_err();
    assert!(matches!(err, ClientError::Invalid(_)), "{err}");
    let err = client.seal(b"x", "https://api.example.com", ["Not An App"]).await.unwrap_err();
    assert!(matches!(err, ClientError::Invalid(_)), "{err}");

    // Without a root id the client connects, but never seals: a competing root chain for
    // the tenant's name would be accepted.
    let unpinned = Client::builder()
        .endpoints([f.endpoint()])
        .tenant(acme())
        .trust(f.trust.clone())
        .identity(Arc::new(AppKeyIdentity::from_seed(&APP_KEY_SEED)))
        .connect()
        .await
        .unwrap();
    let err = unpinned.seal(b"x", "https://api.example.com/v1", ["checkout"]).await.unwrap_err();
    assert!(matches!(&err, ClientError::Invalid(m) if m.contains("SEAL_TENANT=acme@<root id>")), "{err}");
    assert_eq!(err.code(), ErrorCode::BadRequest);
    assert_eq!(f.seen(|s| s.sealed.len()), 1);
}

/// Every call that carries a secret, a proof or a token first challenges the connection it goes
/// on; any answer but an honest one for this nonce, this connection and the verified keys is a
/// verification error, and nothing is sent.
#[tokio::test]
async fn challenges_the_connection_before_sending_anything_secret() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let blob = f.blob("https://api.example.com/v1");
    client.seal(b"sk-live-0123456789", "https://api.example.com/v1", ["checkout"]).await.unwrap();
    let mut session = client.session(&blob).http().await.unwrap();
    session.extend().await.unwrap();
    client.signal("edr-alert", Severity::High).await.unwrap();
    let challenges = f.seen(|s| s.challenges.clone());
    assert_eq!(challenges.len(), 4, "seal, session, extend, signal; never the ticket");
    assert!(challenges.iter().all(|e| *e != [0; 32]), "each on a TLS 1.3 connection");
    for (i, e) in challenges.iter().enumerate() {
        assert!(!challenges[..i].contains(e), "each on a connection of its own");
    }

    for mode in [
        Challenge::Unsupported,
        Challenge::Replay,
        Challenge::WrongNonce,
        Challenge::WrongExporter,
        Challenge::WrongSignatureLabel,
        Challenge::WrongEvidenceLabel,
        Challenge::PeriodicEvidence,
        Challenge::OtherBinding,
        Challenge::Stale,
    ] {
        f.challenge(mode);
        let err = client.seal(b"sk-live-0123456789", "https://api.example.com/v1", ["checkout"]).await.unwrap_err();
        assert!(matches!(err, ClientError::Verification(_)), "{mode:?}: {err}");
        assert_eq!(err.code(), ErrorCode::VerificationFailed);
        let Err(err) = client.session(&blob).http().await else { panic!("{mode:?}: a session started") };
        assert!(matches!(err, ClientError::Verification(_)), "{mode:?}: {err}");
        let err = session.extend().await.unwrap_err();
        assert!(matches!(err, ClientError::Verification(_)), "{mode:?}: {err}");
    }
    // A client without a root id accepts any root of the tenant, but not keys other than the
    // ones it verified.
    f.challenge(Challenge::OtherBinding);
    let unpinned = Client::builder()
        .endpoints([f.endpoint()])
        .tenant(acme())
        .trust(f.trust.clone())
        .identity(Arc::new(AppKeyIdentity::from_seed(&APP_KEY_SEED)))
        .connect()
        .await
        .unwrap();
    let Err(err) = unpinned.session(&blob).http().await else { panic!("a session started") };
    assert!(matches!(&err, ClientError::Verification(m) if m.contains("other keys")), "{err}");
    assert_eq!(f.seen(|s| (s.sealed.len(), s.sessions.len(), s.extends.len())), (1, 1, 1), "nothing more was sent");

    // The periodic attestation still verifies: connecting needs no challenge.
    f.client().await;
    f.challenge(Challenge::Honest);
    client.seal(b"sk-live-0123456789", "https://api.example.com/v1", ["checkout"]).await.unwrap();
    assert_eq!(f.seen(|s| s.sealed.len()), 2);
}

/// Every tunnel connection, spares and extensions included, is challenged before its token is
/// sent; a replica whose answer does not verify, or that cannot answer, gets no token and the
/// app's connection is closed.
#[tokio::test]
async fn tunnels_challenge_each_connection_before_the_token() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let mut s = client.session(&f.blob("https://api.example.com/v1")).http().await.unwrap();
    let addr = tunnel_addr(s.url());
    let mut conn = TcpStream::connect(addr).await.unwrap();
    assert_eq!(http(&mut conn, "/", s.key()).await.0, "HTTP/1.1 200 OK");
    eventually("a challenged spare", || f.seen(|s| s.tunnel_challenges.len() == 2)).await;
    s.extend().await.unwrap();
    assert_eq!(f.seen(|s| s.tunnel_extends.len()), 1);
    let challenges = f.seen(|s| s.tunnel_challenges.clone());
    assert_eq!(challenges.len(), 3, "the connection, the spare and the extension");
    assert_eq!(f.seen(|s| s.tunnel_handshakes), 3);
    assert!(challenges.iter().all(|e| *e != [0; 32]), "each on a TLS 1.3 connection");
    assert_eq!(f.seen(|s| s.connects.len()), 1);

    // The spare was verified when it was opened; once it is used, every new connection is
    // challenged under the new mode.
    let refused = |mode| {
        let (f, key) = (&f, s.key().to_string());
        async move {
            f.challenge(mode);
            let mut conn = TcpStream::connect(addr).await.unwrap();
            let request = format!("GET / HTTP/1.1\r\nhost: app\r\nx-api-key: {key}\r\n\r\n");
            conn.write_all(request.as_bytes()).await.unwrap();
            let mut got = [0u8; 64];
            !matches!(conn.read(&mut got).await, Ok(1..))
        }
    };
    assert!(!refused(Challenge::Unsupported).await, "the spare, challenged before");
    let connects = f.seen(|s| s.connects.len());
    for mode in [
        Challenge::Unsupported,
        Challenge::Replay,
        Challenge::WrongNonce,
        Challenge::WrongExporter,
        Challenge::WrongSignatureLabel,
        Challenge::PeriodicEvidence,
        Challenge::OtherBinding,
        Challenge::Stale,
    ] {
        assert!(refused(mode).await, "{mode:?}: the app's connection was served");
    }
    assert_eq!(f.seen(|s| s.connects.len()), connects, "no token was sent");

    f.challenge(Challenge::Honest);
    let mut conn = TcpStream::connect(addr).await.unwrap();
    assert_eq!(http(&mut conn, "/", s.key()).await.0, "HTTP/1.1 200 OK");
    s.close().await.unwrap();
}

#[tokio::test]
async fn signals_about_itself() {
    let f = Fixture::new().await;
    let client = f.client().await;
    client.signal("edr-alert", Severity::Critical).await.unwrap();
    assert_eq!(f.seen(|s| s.signals.clone()), [("edr-alert".to_string(), Severity::Critical)]);
    assert!(matches!(client.signal("Bad Code", Severity::Low).await, Err(ClientError::Invalid(_))));
}

#[tokio::test]
async fn tunnel_session_forwards_extends_and_ends() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let blob = f.blob("https://api.example.com/v1");
    let mut s = client.session(&blob).http().await.unwrap();
    let addr = tunnel_addr(s.url());
    assert!(addr.ip().is_loopback());
    assert_eq!(s.url(), format!("http://{addr}/v1"));
    assert!(s.key().starts_with("seallk_"));
    assert_eq!(s.info().blob_id, blob.parse::<Blob>().unwrap().header.blob_id);
    assert_eq!(f.seen(|s| s.sessions[0].endpoint_artifact.clone()), Some("executable".into()));

    // The app talks plaintext to loopback; the enclave sees the token and the local key's hash.
    let mut conn = TcpStream::connect(addr).await.unwrap();
    assert_eq!(http(&mut conn, "/v1/chat", s.key()).await, ("HTTP/1.1 200 OK".into(), "via sealtok_1".into()));
    let (token, hash) = f.seen(|s| s.connects[0].clone());
    assert_eq!((token.as_str(), hash), ("sealtok_1", <[u8; 32]>::from(Sha256::digest(s.key().as_bytes()))));
    // The local key is worthless without the tunnel's preamble: another key is refused.
    assert_eq!(http(&mut conn, "/v1/chat", "seallk_forged").await.0, "HTTP/1.1 401 Unauthorized");

    // Extend: a fresh proof, then the new token to the replica holding the live connection.
    let expires = s.info().expires_at;
    s.extend().await.unwrap();
    assert_eq!(f.seen(|s| s.extends.clone()), ["sealtok_1"]);
    assert_eq!(f.seen(|s| s.tunnel_extends.clone()), ["sealtok_2"]);
    assert!(s.info().expires_at >= expires);
    assert!(s.key().starts_with("seallk_"), "tunnel keys do not change");
    // The live connection keeps working; new connections carry the new token.
    assert_eq!(http(&mut conn, "/v1/chat", s.key()).await.0, "HTTP/1.1 200 OK");
    let mut conn2 = TcpStream::connect(addr).await.unwrap();
    assert_eq!(http(&mut conn2, "/v1/x", s.key()).await.1, "via sealtok_2");

    s.close().await.unwrap();
    assert_eq!(f.seen(|s| s.ends.clone()), ["sealtok_2"]);
    assert!(TcpStream::connect(addr).await.is_err(), "the tunnel closed");
}

#[tokio::test]
async fn tunnel_extends_by_itself_before_expiry() {
    let f = Fixture::new().await;
    *f.enclave.session_secs.lock().unwrap() = 3;
    let client = f.client().await;
    let s = client.session(&f.blob("https://api.example.com/v1")).http().await.unwrap();
    let mut conn = TcpStream::connect(tunnel_addr(s.url())).await.unwrap();
    assert_eq!(http(&mut conn, "/", s.key()).await.0, "HTTP/1.1 200 OK");
    eventually("an automatic extend", || f.seen(|s| s.extends.len() == 1)).await;
    eventually("the extension reaching the replica", || f.seen(|s| s.tunnel_extends == ["sealtok_2"])).await;
    s.close().await.unwrap();
}

#[tokio::test]
async fn a_session_ended_by_the_server_stops_the_tunnel() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let mut s = client.session(&f.blob("https://api.example.com/v1")).http().await.unwrap();
    let addr = tunnel_addr(s.url());
    *f.enclave.extend_error.lock().unwrap() = Some(ErrorCode::SessionEnded);
    let err = s.extend().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::SessionEnded);
    eventually("the tunnel to stop", || std::net::TcpStream::connect(addr).is_err()).await;
    // Never restarted silently: a second extend fails without asking the enclave.
    assert_eq!(s.extend().await.unwrap_err().code(), ErrorCode::SessionEnded);
    assert_eq!(f.seen(|s| s.extends.len()), 1);
    s.close().await.unwrap();
}

#[tokio::test]
async fn database_sessions_get_a_dsn() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let blob = f.blob("postgres://app@db.example.com/orders");
    assert!(matches!(client.session(&blob).http().await, Err(ClientError::Invalid(_))));
    assert!(f.seen(|s| s.sessions.is_empty()), "the wrong kind fails before anything is sent");

    let db = client.session(&blob).database().await.unwrap();
    assert_eq!(db.protocol(), seal::Protocol::Postgres);
    assert!(db.dsn().starts_with("postgres://app:seallk_"), "{}", db.dsn());
    assert!(db.dsn().contains("@127.0.0.1:") && db.dsn().ends_with("/orders?sslmode=disable"), "{}", db.dsn());
    db.close().await.unwrap();
    let Session::Database(db) = client.session(&blob).await.unwrap() else { panic!("the blob says Postgres") };
    db.close().await.unwrap();
}

#[tokio::test]
async fn reloads_an_expired_blob_and_hands_over_reseals() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let old = f.blob("https://api.example.com/v1");
    let new = f.blob("https://api.example.com/v1");
    let resealed = f.blob("https://api.example.com/v1");
    *f.enclave.expired_blob.lock().unwrap() = Some(old.clone());
    *f.enclave.resealed.lock().unwrap() = Some(resealed.clone());

    let stored = Arc::new(Mutex::new(None));
    let s = client
        .session(&old)
        .reload_with({
            let new = new.clone();
            move || {
                let new = new.clone();
                async move { Ok(new) }
            }
        })
        .on_reseal({
            let stored = stored.clone();
            move |blob| {
                let stored = stored.clone();
                async move {
                    *stored.lock().unwrap() = Some(blob);
                }
            }
        })
        .http()
        .await
        .unwrap();
    assert_eq!(f.seen(|s| s.sessions.iter().map(|r| r.blob.clone()).collect::<Vec<_>>()), [old.clone(), new.clone()]);
    assert_eq!(stored.lock().unwrap().as_deref(), Some(resealed.as_str()));
    assert_eq!(s.info().blob_id, new.parse::<Blob>().unwrap().header.blob_id);
    s.close().await.unwrap();

    // Without reload_with, Expired is the answer.
    let err = client.session(&old).http().await.err().unwrap();
    assert_eq!(err.code(), ErrorCode::Expired);
}

#[tokio::test]
async fn a_dropped_session_ends_in_the_background() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let s = client.session(&f.blob("https://api.example.com/v1")).http().await.unwrap();
    drop(s);
    eventually("the background end", || f.seen(|s| s.ends == ["sealtok_1"])).await;
}

#[tokio::test]
async fn a_failed_close_can_be_retried() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let s = client.session(&f.blob("https://api.example.com/v1")).http().await.unwrap();
    let addr = tunnel_addr(s.url());

    // The replica ended the session but could not publish the end: close fails, the tunnel closes anyway.
    *f.enclave.end_error.lock().unwrap() = Some(ErrorCode::Unavailable);
    fn send<T: Send>(t: T) -> T {
        t
    }
    let err = send(s.close()).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(TcpStream::connect(addr).await.is_err(), "the tunnel closed");
    assert_eq!(f.seen(|s| s.ends.clone()), ["sealtok_1"]);

    // Closing again resends the end, which the replica republishes; then there is nothing left to send.
    *f.enclave.end_error.lock().unwrap() = None;
    s.close().await.unwrap();
    s.close().await.unwrap();
    assert_eq!(f.seen(|s| s.ends.clone()), ["sealtok_1", "sealtok_1"]);
    drop(s);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(f.seen(|s| s.ends.len()), 2, "a closed session sends nothing on drop");

    // A closed session is not extended, even when its end failed.
    *f.enclave.end_error.lock().unwrap() = Some(ErrorCode::Unavailable);
    let mut d = client.session(&f.blob("https://api.example.com/v1")).http().await.unwrap();
    assert!(d.close().await.is_err());
    assert_eq!(d.extend().await.unwrap_err().code(), ErrorCode::SessionEnded);
    assert!(f.seen(|s| s.extends.is_empty()));
    // Dropped after a failed close: one more end in the background.
    *f.enclave.end_error.lock().unwrap() = None;
    drop(d);
    eventually("the background end", || f.seen(|s| s.ends[2..] == ["sealtok_2", "sealtok_2"])).await;
}

#[tokio::test]
async fn keeps_telemetry_receipts() {
    let f = Fixture::new().await;
    let client = f.client().await;
    let (blob, receipt) =
        client.seal(b"sk-live-0123456789", "https://api.example.com/v1", ["checkout"]).with_receipt().await.unwrap();
    assert!(blob.starts_with("seal1."));
    assert_eq!(receipt, seal::TelemetryReceipt { stream: [1; 16], entry: 1 });

    // A session's start, then its restart after the token expired.
    let blob = f.blob("https://api.example.com/v1");
    let mut s = client.session(&blob).http().await.unwrap();
    let start = seal::TelemetryReceipt { stream: [2; 16], entry: 1 };
    assert_eq!(s.receipts(), [start]);
    *f.enclave.extend_error.lock().unwrap() = Some(ErrorCode::SessionExpired);
    s.extend().await.unwrap();
    let restart = seal::TelemetryReceipt { stream: [2; 16], entry: 2 };
    assert_eq!(s.receipts(), [start, restart]);
    s.close().await.unwrap();

    // Kept as JSON lines.
    let dir = TempDir::new();
    let file = dir.0.join("receipts.jsonl");
    seal::receipts::append(&file, &[receipt]).unwrap();
    seal::receipts::append(&file, &s.receipts()).unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    let kept: Vec<TelemetryReceipt> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(kept, [receipt, start, restart]);
}

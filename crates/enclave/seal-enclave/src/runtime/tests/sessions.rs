//! Seal, sessions and the data plane through tunnels, extend and end, live sessions
//! ending on state changes, and failing closed.

use sha2::{Digest, Sha256};

use super::*;
use seal_proto::session::{SessionEnd, SESSION_END_LABEL, SESSION_TOKEN_SECS};
use seal_proto::telemetry::{Operation, Outcome, RefusalContext};
use seal_proto::tunnel::TunnelConnect;

/// A destination no adapter of the image speaks is refused when sealing, not when connecting.
#[tokio::test]
async fn sealing_needs_an_adapter_for_the_destination() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let postgres = |_| SecretPolicy::new("postgres://app@db.example.com/orders", [checkout()]).unwrap();
    let refused = h.seal_with(postgres).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::BadRequest);
    assert!(refused.detail.contains("no adapter for Postgres"), "{}", refused.detail);
}

#[tokio::test]
async fn seal_session_request_extend_end() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let sealed = h.seal().await.unwrap();
    let blob: seal_proto::blob::Blob = sealed.blob.parse().unwrap();
    assert_eq!(blob.header.tenant, acme());
    assert_eq!(blob.header.root_id, h.world.root_id);
    assert!(!sealed.blob.contains(SECRET));

    let session = h.start(CONSUMER, &sealed.blob, None).await.unwrap();
    assert_eq!(session.info.app, checkout());
    assert_eq!(session.info.blob_id, sealed.blob_id);
    assert!(session.info.expires_at.abs_diff(wall() + SESSION_TOKEN_SECS) <= 2);
    assert!(session.resealed.is_none());
    let token = session.token.duplicate();

    // A request with the local key reaches the upstream with the secret instead.
    let mut conn = h.connect(&token).await;
    let (status, body) = get(&mut conn, "/v1/chat", LOCAL_KEY).await;
    assert_eq!((status, body.as_str()), (200, "ok"));
    let seen = h.seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(seen.path, "/v1/chat");
    assert_eq!(seen.headers["authorization"], format!("Bearer {SECRET}"));
    assert!(!format!("{:?}", seen.headers).contains(LOCAL_KEY));
    let session_id = session.info.session_id;
    assert_eq!(h.live(&session_id).len(), 1);

    // Extend: a new token for the same session, which the tunnel hands the replica.
    let extended = h.extend(CONSUMER, &token, None).await.unwrap();
    assert_ne!(extended.token.expose(), token.expose());
    assert_eq!(h.extend_preamble(&extended.token).await, Some(seal_proto::tunnel::EXTEND_OK));
    let (status, _) = get(&mut conn, "/v1/models", LOCAL_KEY).await;
    assert_eq!(status, 200);
    // Another caller cannot extend it.
    let other = h.extend(STRANGER, &token, None).await.unwrap_err();
    assert_eq!(other.code, ErrorCode::NotAllowed);

    // End: the live connection ends at once and the end is published.
    h.end(&extended.token).await.unwrap();
    assert_eq!(h.ended(&session_id).await, ErrorCode::SessionEnded);
    let ends = h.stores.ends.lock().unwrap().clone();
    assert_eq!(ends.len(), 1);
    assert_eq!((ends[0].body.session_id, ends[0].body.reason), (session_id, ErrorCode::SessionEnded));
    let served = tokio::time::timeout(Duration::from_secs(5), conn.served).await.unwrap().unwrap();
    assert_eq!(served.unwrap_err().code, ErrorCode::SessionEnded);
    // Ending is idempotent: the same end is published again; tokens are refused from now on.
    h.end(&token).await.unwrap();
    assert_eq!(h.stores.ends.lock().unwrap()[1], ends[0]);
    assert_eq!(h.extend(CONSUMER, &extended.token, None).await.unwrap_err().code, ErrorCode::SessionEnded);
    let mut conn = h.connect(&extended.token).await;
    let (status, body) = get(&mut conn, "/v1/chat", LOCAL_KEY).await;
    assert_eq!((status, seal_error(&body)), (401, ErrorCode::SessionEnded));

    // Telemetry: one entry per operation and request, attributed to the caller.
    let events = h.events();
    assert!(matches!(
        &events[0],
        TelemetryEvent::Seal { blob_id, apps, .. } if *blob_id == sealed.blob_id && apps.contains(&checkout())
    ));
    assert!(matches!(
        &events[1],
        TelemetryEvent::Session { session_id: s, .. } if *s == session_id
    ));
    let requests: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            TelemetryEvent::Request { completion, session_id: s, .. } if *s == session_id => {
                Some(completion.outcome.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(requests, [Outcome::Allowed, Outcome::Allowed]);
    assert!(events.iter().any(|e| matches!(e, TelemetryEvent::Extend { session_id: s, .. } if *s == session_id)));
    assert!(events.iter().any(|e| matches!(
        e,
        TelemetryEvent::Refused { operation: Operation::Extend, code: ErrorCode::NotAllowed, .. }
    )));
    assert_eq!(events.iter().filter(|e| matches!(e, TelemetryEvent::End { .. })).count(), 1);
    let entries = h.telemetry.entries.lock().unwrap().clone();
    assert_eq!(entries[0].identity, None, "sealing is open: no identity");
    assert_eq!(entries[1].identity, Some(app_identity(CONSUMER)));
    assert!(entries.iter().all(|e| e.tenant == acme() && e.at.abs_diff(wall()) <= 5));
    assert!(!format!("{entries:?}").contains(SECRET));
}

#[tokio::test]
async fn refuses_callers_without_grants() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    // Anyone may seal; a stranger cannot start sessions.
    let blob = h.seal().await.unwrap().blob;
    assert_eq!(h.start(STRANGER, &blob, None).await.unwrap_err().code, ErrorCode::NotAllowed);
    let events = h.events();
    assert!(matches!(events[0], TelemetryEvent::Seal { .. }));
    let TelemetryEvent::Refused { operation: Operation::Session, code: ErrorCode::NotAllowed, context } =
        events.last().unwrap()
    else {
        panic!("{events:?}")
    };
    // The tenant learns why: an app key that no grant names.
    let WorkloadIdentity::AppKey { key_id } = app_identity(STRANGER) else { unreachable!() };
    assert_eq!(context, &Some(RefusalContext::UnknownAppKey { key_id }));
}

#[tokio::test]
async fn a_blob_without_a_wrap_for_this_platform_needs_a_reseal() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let mut blob: seal_proto::blob::Blob = h.seal().await.unwrap().blob.parse().unwrap();
    // As if sealed while the tenant enabled only Azure.
    for wrap in &mut blob.wraps {
        let seal_proto::blob::DekWrap::Hpke { platform, .. } = wrap;
        *platform = PlatformId::AzureSnpAci;
    }
    let refused = h.start(CONSUMER, &blob.to_string(), None).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::ResealRequired);
    assert!(matches!(
        h.events().last().unwrap(),
        TelemetryEvent::Refused {
            operation: Operation::Session,
            code: ErrorCode::ResealRequired,
            context: Some(RefusalContext::NotSealedForPlatform { platform: PlatformId::Sim }),
        }
    ));
}

#[tokio::test]
async fn tunnel_preamble_and_extend_preamble() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let session = h.sealed_session().await;
    let session_id = session.info.session_id;
    let mut conn = h.connect(&session.token).await;
    let (status, body) = get(&mut conn, "/v1/chat", LOCAL_KEY).await;
    assert_eq!((status, body.as_str()), (200, "ok"));
    assert_eq!(h.seen.lock().unwrap().last().unwrap().headers["authorization"], format!("Bearer {SECRET}"));

    // The session token itself is no credential an app presents.
    let mut other = h.connect(&session.token).await;
    let (status, body) = get(&mut other, "/v1/chat", session.token.expose()).await;
    assert_eq!((status, seal_error(&body)), (403, ErrorCode::NotAllowed));

    // Extend, then the Extend preamble moves the live connection's expiry.
    let before = h.live(&session_id)[0].expires_at();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let extended = h.extend(CONSUMER, &session.token, None).await.unwrap();
    assert!(extended.expires_at > before);
    assert_eq!(h.extend_preamble(&extended.token).await, Some(seal_proto::tunnel::EXTEND_OK));
    assert_eq!(h.live(&session_id)[0].expires_at(), extended.expires_at);
    // An older token does not move it back, and a forged one gets no answer.
    assert_eq!(h.extend_preamble(&session.token).await, Some(seal_proto::tunnel::EXTEND_OK));
    assert_eq!(h.live(&session_id)[0].expires_at(), extended.expires_at);
    assert_eq!(h.extend_preamble(&Bearer::new("sealtok_AAAA".into())).await, None);
    // The connection keeps working.
    let (status, _) = get(&mut conn, "/v1/chat", LOCAL_KEY).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn refuses_a_local_key_that_is_not_the_tunnels() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let session = h.sealed_session().await;
    let connect = TunnelPreamble::Connect(TunnelConnect {
        token: session.token.duplicate(),
        local_key_sha256: Sha256::digest(b"seallk_the-real-one").into(),
    });
    let mut conn = h.connect_with(&connect).await;
    let (status, body) = get(&mut conn, "/v1/chat", "seallk_another-one").await;
    assert_eq!((status, seal_error(&body)), (403, ErrorCode::NotAllowed));
    // Bytes that are not a tunnel preamble are refused before any adapter runs.
    let (mut tls, served) = h.tls(None).await;
    tls.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").await.unwrap();
    assert_eq!(served.await.unwrap().unwrap_err().code, ErrorCode::BadRequest);
    assert!(h.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_grant_removal_ends_live_sessions() {
    let mut h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let session = h.sealed_session().await;
    let session_id = session.info.session_id;
    let mut conn = h.connect(&session.token).await;
    assert_eq!(get(&mut conn, "/v1/chat", LOCAL_KEY).await.0, 200);
    assert!(h.still_live(&session_id).await);

    let bundle = h.world.publish(|s| {
        s.apps.insert(checkout(), Default::default());
    });
    h.reload(bundle).await;
    assert_eq!(h.ended(&session_id).await, ErrorCode::NotAllowed);
    let served = tokio::time::timeout(Duration::from_secs(5), conn.served).await.unwrap().unwrap();
    assert_eq!(served.unwrap_err().code, ErrorCode::NotAllowed);
    assert_eq!(h.extend(CONSUMER, &session.token, None).await.unwrap_err().code, ErrorCode::NotAllowed);
}

#[tokio::test]
async fn a_session_end_from_another_replica_ends_live_sessions() {
    let mut h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let session = h.sealed_session().await;
    let session_id = session.info.session_id;
    let mut conn = h.connect(&session.token).await;
    assert_eq!(get(&mut conn, "/v1/chat", LOCAL_KEY).await.0, 200);

    // Another replica of the tenant (same telemetry key) ended it and published the end.
    let end = SessionEnd { tenant: acme(), session_id, reason: ErrorCode::SessionEnded, ended_at: wall() };
    let signed = service_keys(&h.world.root_id).telemetry.signer().sign_into(SESSION_END_LABEL, end);
    let mut bundle = h.world.publish(|_| {});
    bundle.ended_sessions.push(signed);
    h.reload(bundle).await;
    assert_eq!(h.ended(&session_id).await, ErrorCode::SessionEnded);
}

#[tokio::test]
async fn a_suspending_self_signal_ends_the_callers_sessions() {
    let h = Boot::with_state(|s| {
        s.integrity.actions.insert(Severity::High, seal_proto::integrity::IntegrityAction::Suspend { secs: None });
    })
    .start()
    .await
    .map_err(|(e, _)| e)
    .unwrap();
    let session = h.sealed_session().await;
    let session_id = session.info.session_id;
    let mut conn = h.connect(&session.token).await;
    assert_eq!(get(&mut conn, "/v1/chat", LOCAL_KEY).await.0, 200);

    // A low signal is only logged; a high one suspends at once and is published.
    h.self_signal(CONSUMER, "edr-low", Severity::Low).await.unwrap();
    assert!(h.still_live(&session_id).await);
    assert!(h.stores.signals.lock().unwrap().is_empty());
    h.self_signal(CONSUMER, "edr-high", Severity::High).await.unwrap();
    assert_eq!(h.ended(&session_id).await, ErrorCode::IntegrityFailed);
    let published = h.stores.signals.lock().unwrap().clone();
    assert_eq!(published.len(), 1);
    assert_eq!(
        (published[0].body.identity.clone(), published[0].body.code.as_str()),
        (app_identity(CONSUMER), "edr-high")
    );
    // Suspended: no new session, no extend; sealing is unaffected.
    let blob = h.seal().await.unwrap().blob;
    assert_eq!(h.start(CONSUMER, &blob, None).await.unwrap_err().code, ErrorCode::IntegrityFailed);
    assert_eq!(h.extend(CONSUMER, &session.token, None).await.unwrap_err().code, ErrorCode::IntegrityFailed);
    let integrity: Vec<_> = h
        .events()
        .into_iter()
        .filter_map(|e| match e {
            TelemetryEvent::Integrity { code, action, .. } => Some((code, action)),
            _ => None,
        })
        .collect();
    assert_eq!(integrity.len(), 2);
    assert_eq!(integrity[0], ("edr-low".into(), seal_proto::integrity::IntegrityAction::LogOnly));
}

#[tokio::test]
async fn a_cut_transfer_is_recorded_as_aborted() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let session = h.sealed_session().await;
    let mut conn = h.connect(&session.token).await;
    let request = hyper::Request::get("/v1/hang")
        .header("host", TLS_NAME)
        .header("authorization", format!("Bearer {LOCAL_KEY}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = conn.sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(&first[..], b"first");

    h.end(&session.token).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), body.collect()).await;
    let aborted = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let found = h.events().into_iter().any(|e| {
                matches!(
                    e,
                    TelemetryEvent::Request { completion, .. }
                        if completion.outcome == Outcome::Aborted && completion.action == "GET /v1/hang"
                )
            });
            if found {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(aborted.is_ok(), "no Aborted entry: {:?}", h.events());
}

#[tokio::test]
async fn fails_closed_once_the_state_is_past_fresh_until() {
    // The freshness statement runs out four seconds after boot.
    let mut boot = Boot::new();
    boot.bundle = boot.world.publish_fresh_at(wall() - DAY + 4, |_| {});
    let h = boot.start().await.map_err(|(e, _)| e).unwrap();
    let session = h.sealed_session().await;
    let session_id = session.info.session_id;
    let mut conn = h.connect(&session.token).await;
    assert_eq!(get(&mut conn, "/v1/chat", LOCAL_KEY).await.0, 200);

    let ended = tokio::time::timeout(Duration::from_secs(10), h.live(&session_id)[0].ended()).await.unwrap();
    assert_eq!(ended, ErrorCode::Unavailable);
    // Live sessions end on the estimate's latest end, up to a second before a clock reading does.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(h.service.ticket().await.unwrap_err().code, ErrorCode::Unavailable);
    assert_eq!(h.end(&session.token).await.unwrap_err().code, ErrorCode::Unavailable);
    assert!(h
        .events()
        .iter()
        .any(|e| matches!(e, TelemetryEvent::Refused { operation: Operation::End, code: ErrorCode::Unavailable, .. })));
    assert_eq!(h.service.admits_tunnel().unwrap_err().code, ErrorCode::Unavailable);
    // A stale bundle does not revive it; a fresh one does.
    assert!(h.service.runtime.reload().await.is_err());
    let mut h = h;
    let bundle = h.world.publish(|_| {});
    h.reload(bundle).await;
    h.service.ticket().await.unwrap();
}

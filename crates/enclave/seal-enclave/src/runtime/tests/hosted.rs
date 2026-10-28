//! What the deployment entries let a replica serve: a deployment the tenant stops listing, and
//! the idle exit of hosted replicas.

use seal_proto::identity::HostedMode;

use super::*;

/// How long the tests let a hosted replica idle.
const IDLE: Duration = Duration::from_millis(300);

/// Why the replica refuses a tunnel before its TLS handshake.
fn closed_unanswered(h: &Harness) -> ErrorCode {
    h.service.admits_tunnel().unwrap_err().code
}

#[tokio::test]
async fn a_deployment_no_longer_listed_serves_nothing() {
    let mut h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    let session = h.sealed_session().await;
    let mut conn = h.connect(&session.token).await;
    assert_eq!(get(&mut conn, "/v1/chat", LOCAL_KEY).await.0, 200);

    let bundle = h.world.publish(|s| s.deployments.clear());
    h.reload(bundle).await;
    assert_eq!(h.ended(&session.info.session_id).await, ErrorCode::NotAllowed);
    assert_eq!(h.service.ticket().await.unwrap_err().code, ErrorCode::NotAllowed);
    assert_eq!(closed_unanswered(&h), ErrorCode::NotAllowed);
    // Attestation and ends keep working.
    h.attestation().await;
    h.end(&session.token).await.unwrap();
}

#[tokio::test]
async fn a_hosted_replica_exits_when_idle_and_then_starts_nothing() {
    let sessions = |s: &mut TenantState| s.deployments = [hosted_matcher(Some(HostedMode::Sessions))].into();
    let h = Boot::with_state(sessions).start().await.map_err(|(e, _)| e).unwrap();
    let session = h.sealed_session().await;

    // A live session connection keeps it up, however long it is quiet.
    let mut conn = h.connect(&session.token).await;
    assert_eq!(get(&mut conn, "/v1/chat", LOCAL_KEY).await.0, 200);
    assert!(tokio::time::timeout(IDLE * 4, h.service.idle_exit(IDLE)).await.is_err(), "a live connection");

    // Once the connection is gone and nothing else runs: it exits after the idle period.
    drop(conn);
    let started = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(5), h.service.idle_exit(IDLE)).await.expect("idle exit");
    assert!(started.elapsed() >= IDLE);

    // Draining: nothing new starts.
    assert_eq!(h.seal().await.unwrap_err().code, ErrorCode::Unavailable);
    assert_eq!(h.extend(CONSUMER, &session.token, None).await.unwrap_err().code, ErrorCode::Unavailable);
    assert_eq!(closed_unanswered(&h), ErrorCode::Unavailable);
    h.attestation().await;
}

#[tokio::test]
async fn requests_by_authenticated_callers_keep_it_up_and_others_do_not() {
    let sessions = |s: &mut TenantState| s.deployments = [hosted_matcher(Some(HostedMode::Sessions))].into();
    let h = Boot::with_state(sessions).start().await.map_err(|(e, _)| e).unwrap();
    let idle = Duration::from_millis(800);
    let exit = h.service.idle_exit(idle);
    tokio::pin!(exit);
    let blob = h.seal().await.unwrap().blob;
    // A session start every half period: never idle.
    for _ in 0..4 {
        assert!(tokio::time::timeout(idle / 2, &mut exit).await.is_err());
        h.start(CONSUMER, &blob, None).await.unwrap();
    }
    // Tickets, seals and refused proofs are anyone's: they do not count.
    let stranger = async {
        loop {
            let _ = h.service.ticket().await;
            let _ = h.seal().await;
            let _ = h.start(STRANGER, &blob, None).await;
            tokio::time::sleep(idle / 8).await;
        }
    };
    tokio::select! {
        _ = &mut exit => {}
        _ = stranger => unreachable!(),
        _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("unauthenticated requests kept it up"),
    }
}

#[tokio::test]
async fn customer_replicas_never_idle_out() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    assert!(tokio::time::timeout(IDLE * 5, h.service.idle_exit(IDLE)).await.is_err());
    h.seal().await.unwrap();
}

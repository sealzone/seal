//! End to end against a scripted upstream: a raw-protocol client on an in-memory pipe, the
//! adapter, and a plain local SCRAM server reached through `TestUpstream`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use postgres_protocol::message::frontend;

use common::{
    connect, connect_through, connect_to, contains, error_field, extended_msgs, message, query_msg, startup_packet,
    FakeAuth, FakeUpstream,
};
use seal_adapter::testing::{claims, FixedResolver, TestUpstream};
use seal_adapter::{AdapterError, Outcome, UpstreamErrorKind, Verdict};
use seal_proto::policy::{Destination, Protocol};
use seal_proto::telemetry::Sqlstate;
use seal_proto::ErrorCode;

const SECRET: &str = "pg-secret-Xy9";
const TOKEN: &str = "seallk_test1";
const HOST: &str = "db.test";

struct Setup {
    resolver: Arc<FixedResolver>,
    upstream: Arc<TestUpstream>,
    fake: FakeUpstream,
}

async fn setup(auth: FakeAuth) -> Setup {
    let fake = FakeUpstream::start(SECRET, auth).await;
    let resolver = FixedResolver::new();
    resolver
        .insert(TOKEN, claims(Destination::parse("postgres://app@db.test:5432/orders").unwrap(), SECRET.as_bytes()));
    let upstream = TestUpstream::new();
    upstream.route(HOST, fake.addr);
    Setup { resolver, upstream, fake }
}

impl Setup {
    fn client(&self) -> (common::PgClient, tokio::task::JoinHandle<Result<(), AdapterError>>) {
        connect(self.resolver.clone(), self.upstream.clone())
    }
}

fn sqlstate(m: &(u8, Vec<u8>)) -> String {
    assert_eq!(m.0, b'E', "an ErrorResponse");
    error_field(&m.1, b'C').unwrap()
}

fn types(msgs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    msgs.iter().map(|m| m.0).collect()
}

const LOGIN: &[(&str, &str)] = &[("user", "someone"), ("database", "postgres")];

#[tokio::test]
async fn relays_as_the_destination_identity() {
    let s = setup(FakeAuth::Scram).await;
    let (mut c, task) = s.client();
    let params = [
        ("user", "root"),
        ("database", "postgres"),
        ("options", "-c role=admin"),
        ("application_name", "orders-api"),
        ("replication", "false"),
        ("client_encoding", "SJIS"),
        ("search_path", "evil"),
    ];
    let greeting = c.login(&params, TOKEN).await;
    assert_eq!(types(&greeting), b"RSSKZ");
    assert_eq!(greeting[0].1, 0i32.to_be_bytes(), "AuthenticationOk");
    let key = &greeting[3].1;
    assert_ne!(key[..], [4242i32.to_be_bytes(), 777i32.to_be_bytes()].concat(), "never the upstream's key");
    assert!(contains(&greeting[2].1, b"pw=*************"), "ParameterStatus scrubbed in place");

    let reply = c.query("SELECT 1").await;
    assert_eq!(types(&reply), b"CZ");

    {
        let log = s.fake.log.lock().unwrap();
        let startup: Vec<(&str, &str)> = log.startup.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_eq!(
            startup,
            [("user", "app"), ("database", "orders"), ("client_encoding", "UTF8"), ("application_name", "orders-api")]
        );
        assert_eq!(log.queries, ["SELECT 1"]);
    }
    let observed = s.resolver.take_observations();
    assert_eq!(observed.len(), 1);
    let o = &observed[0];
    assert_eq!((o.protocol, o.action.as_str(), &o.content[..]), (Protocol::Postgres, "QUERY", &b"SELECT 1"[..]));

    c.send(&message(b'X', b"")).await;
    assert!(c.drain().await.is_empty());
    task.await.unwrap().unwrap();
    let done = s.resolver.take_completions();
    assert_eq!(done.len(), 1);
    assert_eq!((done[0].action.as_str(), &done[0].outcome), ("QUERY", &Outcome::Allowed));
    assert_eq!(done[0].bytes_up, 5 + 9);
    let reply_bytes: usize = reply.iter().map(|m| 5 + m.1.len()).sum();
    assert_eq!(done[0].bytes_down, reply_bytes as u64);
    assert!(!contains(&c.received, SECRET.as_bytes()));
    assert!(contains(&s.fake.log.lock().unwrap().raw, b"SELECT 1"));
}

#[tokio::test]
async fn the_secret_never_reaches_the_client() {
    let s = setup(FakeAuth::Scram).await;
    let (mut c, _task) = s.client();
    c.login(LOGIN, TOKEN).await;

    let leak = c.query("SELECT leak").await;
    assert_eq!(types(&leak), b"TDCZ");
    assert!(contains(&leak[1].1, b"key=*************"));

    let error = c.query("SELECT error").await;
    assert_eq!(types(&error), b"EZ");
    assert_eq!(error_field(&error[0].1, b'M').unwrap(), "bad key *************", "upstream SQL errors relay, scrubbed");

    let big = c.query("SELECT big").await;
    assert_eq!(types(&big), b"TDCZ");
    let row = &big[1].1;
    assert_eq!(row.len(), 2 + 4 + 200_000 + SECRET.len(), "a streamed row keeps its length");
    assert!(contains(row, format!("a{}b", "*".repeat(SECRET.len())).as_bytes()), "masked across stream chunks");

    assert!(!contains(&c.received, SECRET.as_bytes()));
    let done = s.resolver.take_completions();
    let outcomes: Vec<&Outcome> = done.iter().map(|d| &d.outcome).collect();
    let error = Outcome::UpstreamError(UpstreamErrorKind::Sqlstate(Sqlstate::new(*b"42000").unwrap()));
    assert_eq!(outcomes, [&Outcome::Allowed, &error, &Outcome::Allowed], "SQL errors keep their SQLSTATE");
}

/// The key of a `BackendKeyData` body.
fn key_of(greeting: &[(u8, Vec<u8>)]) -> (i32, i32) {
    let body = &greeting.iter().find(|m| m.0 == b'K').expect("BackendKeyData").1;
    (i32::from_be_bytes(body[..4].try_into().unwrap()), i32::from_be_bytes(body[4..].try_into().unwrap()))
}

fn cancel_packet((pid, key): (i32, i32)) -> Vec<u8> {
    [&16u32.to_be_bytes()[..], &80_877_102i32.to_be_bytes(), &pid.to_be_bytes(), &key.to_be_bytes()].concat()
}

#[tokio::test]
async fn cancel_requests_reach_only_their_own_connection() {
    let s = setup(FakeAuth::Scram).await;
    let adapter = Arc::new(seal_adapter_pg::PostgresAdapter::default());
    let client = || connect_to(adapter.clone(), s.resolver.clone(), s.upstream.clone());
    let (mut a, _a) = client();
    let (mut b, b_task) = client();
    let key_a = key_of(&a.login(LOGIN, TOKEN).await);
    let key_b = key_of(&b.login(LOGIN, TOKEN).await);
    assert_ne!(key_a, key_b);
    assert!(key_a.0 > 0 && key_b.0 > 0, "process IDs are positive");

    // A's key: the upstream gets a cancel for A's upstream connection, with its own key.
    let (mut c, task) = client();
    c.send(&cancel_packet(key_a)).await;
    assert!(c.drain().await.is_empty(), "no reply, as Postgres");
    task.await.unwrap().unwrap();
    assert_eq!(s.fake.log.lock().unwrap().cancels, [(4242, 777)]);
    let done = s.resolver.take_completions();
    assert_eq!((done[0].action.as_str(), &done[0].outcome, done[0].bytes_up), ("CANCEL", &Outcome::Allowed, 16));
    assert_eq!(s.resolver.take_observations()[0].action, "CANCEL");

    // A key no live connection was given goes nowhere: a guess, the upstream's own key, or a
    // key once its connection closed.
    b.send(&message(b'X', b"")).await;
    b.drain().await;
    b_task.await.unwrap().unwrap();
    for key in [(key_a.0, key_a.1.wrapping_add(1)), (4242, 777), key_b] {
        let (mut c, task) = client();
        c.send(&cancel_packet(key)).await;
        assert!(c.drain().await.is_empty());
        assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::NotAllowed))), "{key:?}");
    }
    assert_eq!(s.fake.log.lock().unwrap().cancels.len(), 1);

    // Through a tunnel of another session, A's key cancels nothing.
    let (mut c, task) = connect_through(adapter.clone(), s.resolver.clone(), s.upstream.clone(), "sealtok_other");
    c.send(&cancel_packet(key_a)).await;
    assert!(c.drain().await.is_empty());
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::NotAllowed))));
    assert_eq!(s.fake.log.lock().unwrap().cancels.len(), 1);

    // Another adapter (another replica) does not know A's key either.
    let (mut c, task) = s.client();
    c.send(&cancel_packet(key_a)).await;
    assert!(c.drain().await.is_empty());
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::NotAllowed))));

    // The integrity policy may refuse a cancel like any request.
    s.resolver.set_verdict(Verdict::Refuse(ErrorCode::PolicyDenied));
    let (mut c, task) = client();
    c.send(&cancel_packet(key_a)).await;
    assert!(c.drain().await.is_empty());
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::PolicyDenied))));
    assert_eq!(s.fake.log.lock().unwrap().cancels.len(), 1);
    drop(a);
}

#[tokio::test]
async fn extended_protocol_cycles() {
    let s = setup(FakeAuth::Scram).await;
    let (mut c, _task) = s.client();
    c.login(LOGIN, TOKEN).await;

    c.send(&extended_msgs("SELECT $1")).await;
    assert_eq!(types(&c.until_ready().await), b"12nCZ");
    // A prepared statement executed again: no Parse in the cycle.
    let execute = [message(b'B', &[0; 8]), message(b'E', &[0, 0, 0, 0, 0]), message(b'S', b"")].concat();
    c.send(&execute).await;
    assert_eq!(types(&c.until_ready().await), b"2CZ");
    // Pipelined: two cycles before reading either answer.
    c.send(&[extended_msgs("SELECT 2"), extended_msgs("SELECT 3")].concat()).await;
    assert_eq!(types(&c.until_ready().await), b"12nCZ");
    assert_eq!(types(&c.until_ready().await), b"12nCZ");
    // A query after an unsynced Parse and Flush: one ReadyForQuery answers both.
    let mut parse_flush = BytesMut::new();
    frontend::parse("s1", "SELECT 4", [], &mut parse_flush).unwrap();
    frontend::flush(&mut parse_flush);
    c.send(&[&parse_flush[..], &query_msg("SELECT 5")].concat()).await;
    assert_eq!(types(&c.until_ready().await), b"1CZ");

    let observed: Vec<(String, Vec<u8>)> =
        s.resolver.take_observations().into_iter().map(|o| (o.action, o.content)).collect();
    assert_eq!(
        observed,
        [
            ("PARSE".into(), b"SELECT $1".to_vec()),
            ("PARSE".into(), b"SELECT 2".to_vec()),
            ("PARSE".into(), b"SELECT 3".to_vec()),
            ("PARSE".into(), b"SELECT 4".to_vec()),
            ("QUERY".into(), b"SELECT 5".to_vec())
        ]
    );
    let done: Vec<(String, Outcome)> =
        s.resolver.take_completions().into_iter().map(|d| (d.action, d.outcome)).collect();
    assert_eq!(
        done,
        [
            ("PARSE".into(), Outcome::Allowed),
            ("EXECUTE".into(), Outcome::Allowed),
            ("PARSE".into(), Outcome::Allowed),
            ("PARSE".into(), Outcome::Allowed),
            ("QUERY".into(), Outcome::Allowed)
        ]
    );
}

#[tokio::test]
async fn refused_credentials_never_reach_the_upstream() {
    let s = setup(FakeAuth::Scram).await;
    for password in ["seallk_wrong", "hunter2", ""] {
        let (mut c, task) = s.client();
        let reply = c.login(LOGIN, password).await;
        assert_eq!(reply.len(), 1);
        assert_eq!(sqlstate(&reply[0]), "28P01");
        assert_eq!(error_field(&reply[0].1, b'S').unwrap(), "FATAL");
        assert!(error_field(&reply[0].1, b'M').unwrap().starts_with("seal: "));
        assert!(c.drain().await.is_empty());
        assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::NotAllowed))));
    }
    assert_eq!(s.fake.log.lock().unwrap().connections, 0);
    assert!(s.resolver.take_completions().is_empty());
}

#[tokio::test]
async fn blob_for_another_protocol_is_refused() {
    let s = setup(FakeAuth::Scram).await;
    s.resolver
        .insert("seallk_https", claims(Destination::parse("https://api.example.com").unwrap(), SECRET.as_bytes()));
    let (mut c, task) = s.client();
    let reply = c.login(LOGIN, "seallk_https").await;
    assert_eq!(sqlstate(&reply[0]), "28000");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::PolicyDenied))));
    assert_eq!(s.fake.log.lock().unwrap().connections, 0);
    let done = s.resolver.take_completions();
    assert_eq!((done[0].action.as_str(), &done[0].outcome), ("CONNECT", &Outcome::Denied(ErrorCode::PolicyDenied)));
}

#[tokio::test]
async fn negotiation_cancel_replication_and_versions() {
    let s = setup(FakeAuth::Scram).await;

    // TLS and GSS encryption are declined inside the core's TLS; the client continues.
    let (mut c, _task) = s.client();
    c.send(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30]).await;
    assert_eq!(c.read_byte().await, Some(b'N'));
    c.send(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]).await;
    assert_eq!(c.read_byte().await, Some(b'N'));
    assert_eq!(types(&c.login(LOGIN, TOKEN).await), b"RSSKZ");

    // A CancelRequest for no connection: closed without a reply.
    let (mut c, task) = s.client();
    c.send(&[0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0x10, 0x92, 0, 0, 0, 0]).await;
    assert!(c.drain().await.is_empty());
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::NotAllowed))));

    // Replication.
    for value in ["database", "true", "on"] {
        let (mut c, task) = s.client();
        c.send(&startup_packet(&[("user", "x"), ("replication", value)])).await;
        let reply = c.drain().await;
        assert_eq!(sqlstate(&reply[0]), "0A000");
        assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::PolicyDenied))));
    }

    // Protocol 2.0 is refused.
    let (mut c, task) = s.client();
    let mut v2 = startup_packet(&[("user", "x")]);
    v2[4..8].copy_from_slice(&0x0002_0000i32.to_be_bytes());
    c.send(&v2).await;
    assert_eq!(sqlstate(&c.drain().await[0]), "0A000");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Client(_))));

    // Protocol 3.2 with an option: negotiated down to 3.0.
    let (mut c, _task) = s.client();
    let mut v32 = startup_packet(&[("user", "x"), ("_pq_.test_option", "1")]);
    v32[4..8].copy_from_slice(&0x0003_0002i32.to_be_bytes());
    c.send(&v32).await;
    let (ty, body) = c.read_msg().await.unwrap();
    assert_eq!(ty, b'v');
    assert_eq!(body, [&0i32.to_be_bytes()[..], &1i32.to_be_bytes(), b"_pq_.test_option\0"].concat());

    // A startup packet over 10 000 bytes is refused before it is read.
    let (mut c, task) = s.client();
    c.send(&10_001u32.to_be_bytes()).await;
    assert_eq!(sqlstate(&c.drain().await[0]), "08P01");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Client(_))));
    assert!(s.fake.log.lock().unwrap().startup.iter().all(|(k, _)| k != "replication"));
}

#[tokio::test]
async fn only_scram_reaches_the_secret() {
    for auth in [FakeAuth::Md5, FakeAuth::Cleartext, FakeAuth::Trust] {
        let s = setup(auth).await;
        let (mut c, task) = s.client();
        let reply = c.login(LOGIN, TOKEN).await;
        assert_eq!(sqlstate(&reply[0]), "08004", "{auth:?}");
        assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::PolicyDenied))));
        assert!(!contains(&s.fake.log.lock().unwrap().raw, SECRET.as_bytes()), "{auth:?}: the secret is never sent");
        let done = s.resolver.take_completions();
        assert_eq!((done[0].action.as_str(), &done[0].outcome), ("CONNECT", &Outcome::Denied(ErrorCode::PolicyDenied)));
    }
}

#[tokio::test]
async fn upstream_login_failure_shows_no_upstream_text() {
    let s = setup(FakeAuth::Scram).await;
    let dest = Destination::parse("postgres://app@db.test/orders").unwrap();
    s.resolver.insert("seallk_stale", claims(dest, b"rotated-away"));
    let (mut c, task) = s.client();
    let reply = c.login(LOGIN, "seallk_stale").await;
    assert_eq!(sqlstate(&reply[0]), "08004", "never 28P01: the client's own credential was fine");
    assert!(!contains(&c.received, b"password authentication failed"));
    assert!(!contains(&c.received, SECRET.as_bytes()));
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Upstream(UpstreamErrorKind::AuthRejected))));
    let done = s.resolver.take_completions();
    assert_eq!(done[0].outcome, Outcome::UpstreamError(UpstreamErrorKind::AuthRejected));
}

#[tokio::test]
async fn unreachable_upstream() {
    let s = setup(FakeAuth::Scram).await;
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    s.upstream.route(HOST, closed.local_addr().unwrap());
    drop(closed);
    let (mut c, task) = s.client();
    let reply = c.login(LOGIN, TOKEN).await;
    assert_eq!(sqlstate(&reply[0]), "08001");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Upstream(UpstreamErrorKind::Connect))));
    assert_eq!(s.resolver.take_completions()[0].outcome, Outcome::UpstreamError(UpstreamErrorKind::Connect));
}

#[tokio::test]
async fn refusals_in_band_when_idle() {
    let s = setup(FakeAuth::Scram).await;
    let (mut c, _task) = s.client();
    c.login(LOGIN, TOKEN).await;

    s.resolver.set_verdict(Verdict::Refuse(ErrorCode::PolicyDenied));
    let reply = c.query("DROP TABLE orders").await;
    assert_eq!(types(&reply), b"EZ");
    assert_eq!(sqlstate(&reply[0]), "42501");
    assert_eq!(error_field(&reply[0].1, b'S').unwrap(), "ERROR");
    assert_eq!(reply[1].1, b"I");

    c.send(&[extended_msgs("DELETE FROM orders"), query_msg("SELECT after")].concat()).await;
    assert_eq!(types(&c.until_ready().await), b"EZ", "the cycle is discarded up to its Sync");
    assert_eq!(types(&c.until_ready().await), b"EZ", "the next query is observed (and refused) on its own");

    // FunctionCall is never forwarded.
    s.resolver.set_verdict(Verdict::Forward);
    c.send(&message(b'F', &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])).await;
    let reply = c.until_ready().await;
    assert_eq!(types(&reply), b"EZ");
    assert_eq!(sqlstate(&reply[0]), "42501");

    assert_eq!(types(&c.query("SELECT 1").await), b"CZ", "the connection stays usable");
    let log = s.fake.log.lock().unwrap();
    assert_eq!(log.queries, ["SELECT 1"]);
    assert_eq!(log.types, b"Q");
    drop(log);

    let done: Vec<(String, Outcome)> =
        s.resolver.take_completions().into_iter().map(|d| (d.action, d.outcome)).collect();
    let denied = Outcome::Denied(ErrorCode::PolicyDenied);
    assert_eq!(
        done,
        [
            ("QUERY".into(), denied.clone()),
            ("PARSE".into(), denied.clone()),
            ("QUERY".into(), denied.clone()),
            ("FUNCTION_CALL".into(), denied),
            ("QUERY".into(), Outcome::Allowed)
        ]
    );
}

#[tokio::test]
async fn refusal_inside_a_transaction_closes() {
    let s = setup(FakeAuth::Scram).await;
    let (mut c, task) = s.client();
    c.login(LOGIN, TOKEN).await;
    assert_eq!(c.query("BEGIN").await[1].1, b"T");
    s.resolver.set_verdict(Verdict::Refuse(ErrorCode::PolicyDenied));
    c.send(&query_msg("DELETE FROM orders")).await;
    let reply = c.drain().await;
    assert_eq!(types(&reply), b"E");
    assert_eq!(error_field(&reply[0].1, b'S').unwrap(), "FATAL", "closing rolls the transaction back");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::PolicyDenied))));
    assert_eq!(s.fake.log.lock().unwrap().queries, ["BEGIN"]);
}

#[tokio::test]
async fn verdict_end_closes() {
    let s = setup(FakeAuth::Scram).await;
    let (mut c, task) = s.client();
    c.login(LOGIN, TOKEN).await;
    s.resolver.set_verdict(Verdict::End(ErrorCode::IntegrityFailed));
    c.send(&query_msg("SELECT 1")).await;
    let reply = c.drain().await;
    assert_eq!(sqlstate(&reply[0]), "57P01");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::IntegrityFailed))));
    let done = s.resolver.take_completions();
    assert_eq!(done[0].outcome, Outcome::Denied(ErrorCode::IntegrityFailed));
}

#[tokio::test]
async fn session_end_cuts_the_connection() {
    let s = setup(FakeAuth::Scram).await;
    let (mut c, task) = s.client();
    c.login(LOGIN, TOKEN).await;
    c.send(&query_msg("SELECT hang")).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.resolver.end_all(ErrorCode::SessionEnded);
    let reply = c.drain().await;
    assert_eq!(types(&reply), b"E");
    assert_eq!(sqlstate(&reply[0]), "57P01");
    assert!(error_field(&reply[0].1, b'M').unwrap().contains("session_ended"));
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Denied(ErrorCode::SessionEnded))));
    let done = s.resolver.take_completions();
    assert_eq!(done.len(), 1);
    assert_eq!((done[0].action.as_str(), &done[0].outcome), ("QUERY", &Outcome::Aborted));
}

#[tokio::test]
async fn client_going_away_aborts_the_cycle() {
    let s = setup(FakeAuth::Scram).await;
    let (mut c, task) = s.client();
    c.login(LOGIN, TOKEN).await;
    c.send(&query_msg("SELECT hang")).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(c);
    task.await.unwrap().unwrap();
    assert_eq!(s.resolver.take_completions()[0].outcome, Outcome::Aborted);
}

#[tokio::test]
async fn malformed_and_oversized_messages_close() {
    let s = setup(FakeAuth::Scram).await;

    let (mut c, task) = s.client();
    c.login(LOGIN, TOKEN).await;
    let too_long = (seal_adapter_pg::MAX_SQL_BODY as u32 + 5).to_be_bytes();
    c.send(&[b'Q', too_long[0], too_long[1], too_long[2], too_long[3]]).await;
    assert_eq!(sqlstate(&c.drain().await[0]), "54000");
    assert!(matches!(task.await.unwrap(), Err(AdapterError::Client(_))));

    for bad in [message(b'w', b""), message(b'Q', b"no terminator"), vec![b'Q', 0, 0, 0, 2]] {
        let (mut c, task) = s.client();
        c.login(LOGIN, TOKEN).await;
        c.send(&bad).await;
        assert_eq!(sqlstate(&c.drain().await[0]), "08P01");
        assert!(matches!(task.await.unwrap(), Err(AdapterError::Client(_))));
    }
    assert!(s.fake.log.lock().unwrap().queries.is_empty());
}

//! The adapter against a scripted in-process upstream reached through `TestUpstream` (plain
//! TCP): login, handshake, policy, ordering, scrubbing and session end, without Docker.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use common::{bulk, connect, TestClient};
use seal_adapter::testing::{claims, FixedResolver, TestClaims, TestUpstream};
use seal_adapter::{AdapterCtx, AdapterError, Outcome, UpstreamErrorKind, Verdict};
use seal_adapter_redis::resp::CommandReader;
use seal_proto::policy::{Destination, Protocol};
use seal_proto::ErrorCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SECRET: &str = "sk-redis-secret";
const TOKEN: &str = "seallk_redis1";
const HOST: &str = "cache.example.com";

/// A tiny Redis: enough commands to see what the adapter sends and how it relays.
#[derive(Default)]
struct Fake {
    /// Every command received, per connection, as text.
    seen: Mutex<Vec<Vec<String>>>,
    password: Mutex<String>,
}

impl Fake {
    fn seen(&self) -> Vec<Vec<String>> {
        self.seen.lock().unwrap().clone()
    }

    fn answer(
        &self,
        args: &[Vec<u8>],
        data: &mut HashMap<Vec<u8>, Vec<u8>>,
        multi: &mut Option<Vec<Vec<Vec<u8>>>>,
    ) -> Option<Vec<u8>> {
        let name = String::from_utf8_lossy(&args[0]).to_ascii_uppercase();
        let ok = || Some(b"+OK\r\n".to_vec());
        let bulk = |v: &[u8]| {
            let mut out = format!("${}\r\n", v.len()).into_bytes();
            out.extend_from_slice(v);
            out.extend_from_slice(b"\r\n");
            Some(out)
        };
        if let Some(queued) = multi {
            match name.as_str() {
                "EXEC" => {
                    let queued = multi.take().unwrap();
                    let mut out = format!("*{}\r\n", queued.len()).into_bytes();
                    for command in queued {
                        out.extend(self.answer(&command, data, &mut None)?);
                    }
                    return Some(out);
                }
                "DISCARD" => {
                    *multi = None;
                    return ok();
                }
                _ => {
                    queued.push(args.to_vec());
                    return Some(b"+QUEUED\r\n".to_vec());
                }
            }
        }
        let password = self.password.lock().unwrap().clone();
        match name.as_str() {
            "AUTH" if args.last().unwrap() == password.as_bytes() => ok(),
            "AUTH" => Some(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n".to_vec()),
            "HELLO" if args.get(4).map(Vec::as_slice) == Some(password.as_bytes()) => {
                Some(b"%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n".to_vec())
            }
            "HELLO" => Some(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n".to_vec()),
            "SELECT" => ok(),
            "SET" => {
                data.insert(args[1].clone(), args[2].clone());
                ok()
            }
            "GET" => match data.get(&args[1]) {
                Some(v) => bulk(v),
                None => Some(b"$-1\r\n".to_vec()),
            },
            "ECHO" => bulk(&args[1]),
            "PING" => Some(b"+PONG\r\n".to_vec()),
            "MULTI" => {
                *multi = Some(Vec::new());
                ok()
            }
            "LEAK" => Some(format!("-ERR invalid password {password}\r\n").into_bytes()),
            "BLPOP" => None,
            _ => Some(b"-ERR unknown command\r\n".to_vec()),
        }
    }
}

async fn start_fake(fake: Arc<Fake>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let fake = fake.clone();
            tokio::spawn(async move {
                let index = {
                    let mut seen = fake.seen.lock().unwrap();
                    seen.push(Vec::new());
                    seen.len() - 1
                };
                let (mut reader, mut buf, mut data, mut multi) =
                    (CommandReader::default(), BytesMut::new(), HashMap::new(), None);
                loop {
                    while let Ok(Some(args)) = reader.next(&mut buf) {
                        let line =
                            args.iter().map(|a| String::from_utf8_lossy(a).into_owned()).collect::<Vec<_>>().join(" ");
                        fake.seen.lock().unwrap()[index].push(line);
                        if let Some(reply) = fake.answer(&args, &mut data, &mut multi) {
                            if stream.write_all(&reply).await.is_err() {
                                return;
                            }
                        }
                    }
                    match stream.read_buf(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    addr
}

struct Harness {
    resolver: Arc<FixedResolver>,
    fake: Arc<Fake>,
    ctx: AdapterCtx,
}

impl Harness {
    async fn new(claims: TestClaims) -> Self {
        let fake = Arc::new(Fake::default());
        *fake.password.lock().unwrap() = SECRET.to_string();
        let addr = start_fake(fake.clone()).await;
        let connector = TestUpstream::new();
        connector.route(HOST, addr);
        let resolver = FixedResolver::new();
        resolver.insert(TOKEN, claims);
        let ctx = AdapterCtx { resolver: resolver.clone(), upstream: connector };
        Self { resolver, fake, ctx }
    }

    async fn default() -> Self {
        Self::new(redis_claims(&format!("rediss://app@{HOST}:6380/2"))).await
    }

    /// A client logged in with `AUTH`; observations and completions so far are dropped.
    async fn login(&self) -> TestClient {
        let mut c = connect(&self.ctx);
        assert_eq!(c.call(&format!("AUTH whoever {TOKEN}")).await, "+OK\r\n");
        self.resolver.take_completions();
        self.resolver.take_observations();
        c
    }
}

fn redis_claims(to: &str) -> TestClaims {
    claims(Destination::parse(to).unwrap(), SECRET.as_bytes())
}

#[tokio::test]
async fn auth_is_replaced_with_the_destination_user_and_secret() {
    let h = Harness::default().await;
    let mut c = connect(&h.ctx);
    assert_eq!(c.call(&format!("AUTH someone {TOKEN}")).await, "+OK\r\n");
    assert_eq!(c.call("SET k v").await, "+OK\r\n");
    assert_eq!(c.call("GET k").await, bulk("v"));
    assert_eq!(
        h.fake.seen(),
        vec![vec![format!("AUTH app {SECRET}"), "SELECT 2".into(), "SET k v".into(), "GET k".into()]]
    );

    let observed = h.resolver.take_observations();
    let actions: Vec<_> = observed.iter().map(|o| (o.action.as_str(), o.content.as_slice())).collect();
    assert_eq!(actions, vec![("AUTH", &b"AUTH"[..]), ("SET", b"SET k v"), ("GET", b"GET k")]);
    assert!(observed.iter().all(|o| o.protocol == Protocol::Redis));
    let completions = h.resolver.take_completions();
    let summary: Vec<_> = completions.iter().map(|c| (c.action.as_str(), c.outcome.clone(), c.bytes_down)).collect();
    assert_eq!(
        summary,
        vec![("AUTH", Outcome::Allowed, 5), ("SET", Outcome::Allowed, 5), ("GET", Outcome::Allowed, 7)]
    );
    assert_eq!(completions[1].bytes_up, "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n".len() as u64);
}

#[tokio::test]
async fn hello_auth_is_replaced_and_the_reply_relayed() {
    let h = Harness::default().await;
    let mut c = connect(&h.ctx);
    let reply = c.call(&format!("HELLO 3 AUTH x {TOKEN} SETNAME worker")).await;
    assert_eq!(reply, "%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n");
    assert_eq!(c.call("PING").await, "+PONG\r\n");
    assert_eq!(h.fake.seen()[0][..2], [format!("HELLO 3 AUTH app {SECRET} SETNAME worker"), "SELECT 2".into()]);
    assert_eq!(h.resolver.take_completions()[0].action, "HELLO");
}

#[tokio::test]
async fn destination_without_user_or_db() {
    let h = Harness::new(redis_claims(&format!("rediss://{HOST}"))).await;
    let mut c = connect(&h.ctx);
    assert_eq!(c.call(&format!("AUTH {TOKEN}")).await, "+OK\r\n");
    assert_eq!(c.call("PING").await, "+PONG\r\n");
    assert_eq!(h.fake.seen(), vec![vec![format!("AUTH {SECRET}"), "PING".into()]]);
}

#[tokio::test]
async fn commands_pipelined_behind_auth_are_relayed() {
    let h = Harness::default().await;
    let mut c = connect(&h.ctx);
    let mut pipeline = seal_adapter_redis::resp::encode_command(&["AUTH", TOKEN]);
    pipeline.extend(seal_adapter_redis::resp::encode_command(&["ECHO", "x"]));
    c.raw(&pipeline).await;
    assert_eq!(c.text().await, "+OK\r\n");
    assert_eq!(c.text().await, bulk("x"));
}

#[tokio::test]
async fn commands_before_login_are_refused() {
    let h = Harness::default().await;
    let mut c = connect(&h.ctx);
    assert_eq!(c.call("GET k").await, "-NOAUTH Authentication required.\r\n");
    assert!(c.call("HELLO 3").await.starts_with("-NOAUTH HELLO must be called"));
    assert_eq!(c.call("AUTH a b c").await, "-ERR wrong number of arguments for 'auth' command\r\n");
    assert_eq!(c.call("QUIT").await, "+OK\r\n");
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "");
    assert!(result.is_ok());
    assert!(h.fake.seen().is_empty(), "nothing reaches the upstream before login");
}

#[tokio::test]
async fn wrong_credential_closes() {
    let h = Harness::default().await;
    for password in ["seallk_wrong", "hunter2"] {
        let mut c = connect(&h.ctx);
        c.send(&format!("AUTH {password}")).await;
        let (rest, result) = c.closed().await;
        assert!(rest.starts_with("-WRONGPASS seal not_allowed: "), "{rest}");
        assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::NotAllowed))), "{result:?}");
    }
    assert!(h.fake.seen().is_empty());
}

#[tokio::test]
async fn blob_for_another_protocol_is_refused() {
    let h = Harness::new(claims(Destination::parse("https://api.example.com").unwrap(), SECRET.as_bytes())).await;
    let mut c = connect(&h.ctx);
    c.send(&format!("AUTH {TOKEN}")).await;
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR seal policy_denied: the blob is not for a Redis destination\r\n");
    assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::PolicyDenied))));
}

#[tokio::test]
async fn refusals_keep_pipeline_order() {
    let h = Harness::default().await;
    let mut c = h.login().await;
    let mut pipeline = Vec::new();
    for line in
        ["SET a 1", "CONFIG GET requirepass", "GET a", "SELECT 0", "SELECT 2", "AUTH x", "HELLO 3 AUTH u p", "GET a"]
    {
        pipeline.extend(seal_adapter_redis::resp::encode_command(&common::words(line)));
    }
    c.raw(&pipeline).await;
    let mut replies = Vec::new();
    for _ in 0..8 {
        replies.push(c.text().await);
    }
    assert_eq!(replies[0], "+OK\r\n");
    assert_eq!(replies[1], "-NOPERM seal policy_denied: server administration is not allowed through Seal\r\n");
    assert_eq!(replies[2], bulk("1"));
    assert_eq!(replies[3], "-NOPERM seal policy_denied: the command reaches beyond the destination's database\r\n");
    assert_eq!(replies[4], "+OK\r\n");
    assert!(replies[5].starts_with("-NOPERM seal policy_denied: the connection is already authenticated"));
    assert!(replies[6].starts_with("-NOPERM"));
    assert_eq!(replies[7], bulk("1"));
    let seen = &h.fake.seen()[0][2..];
    assert_eq!(seen, ["SET a 1", "GET a", "SELECT 2", "GET a"]);

    let completions = h.resolver.take_completions();
    let outcomes: Vec<_> = completions.iter().map(|c| (c.action.as_str(), c.outcome.clone())).collect();
    let denied = Outcome::Denied(ErrorCode::PolicyDenied);
    for (action, outcome) in [("CONFIG", &denied), ("SELECT", &denied), ("AUTH", &denied), ("HELLO", &denied)] {
        assert!(outcomes.contains(&(action, outcome.clone())), "{action}: {outcomes:?}");
    }
    assert_eq!(outcomes.iter().filter(|(_, o)| *o == Outcome::Allowed).count(), 4);
    assert_eq!(h.resolver.take_observations().len(), 4, "only forwarded commands are observed");
}

#[tokio::test]
async fn inline_commands_are_forwarded_as_arrays() {
    let h = Harness::default().await;
    let mut c = h.login().await;
    c.raw(b"ECHO  hi\r\nPING\n").await;
    assert_eq!(c.text().await, bulk("hi"));
    assert_eq!(c.text().await, "+PONG\r\n");
    c.raw(b"ECHO \"a b\"\r\n").await;
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR Protocol error: quoted inline commands are not supported, use RESP\r\n");
    assert!(matches!(result, Err(AdapterError::Client(_))));
}

#[tokio::test]
async fn malformed_command_is_a_protocol_error() {
    let h = Harness::default().await;
    let mut c = h.login().await;
    c.raw(b"*1\r\n:5\r\n").await;
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR Protocol error: expected '$'\r\n");
    assert!(matches!(result, Err(AdapterError::Client("expected '$'"))));
}

#[tokio::test]
async fn secret_in_replies_is_masked() {
    let h = Harness::default().await;
    let mut c = h.login().await;
    assert_eq!(c.call(&format!("ECHO {SECRET}")).await, bulk(&"*".repeat(SECRET.len())));
    assert_eq!(c.call(&format!("SET k xx{SECRET}yy")).await, "+OK\r\n");
    assert_eq!(c.call("GET k").await, bulk(&format!("xx{}yy", "*".repeat(SECRET.len()))));
    assert_eq!(c.call("LEAK").await, format!("-ERR invalid password {}\r\n", "*".repeat(SECRET.len())));
}

#[tokio::test]
async fn large_replies_stream() {
    let h = Harness::default().await;
    let mut c = h.login().await;
    let big = "v".repeat(300_000) + SECRET;
    assert_eq!(c.call(&format!("SET big {big}")).await, "+OK\r\n");
    let reply = c.call("GET big").await;
    assert_eq!(reply.len(), bulk(&big).len());
    assert!(reply.ends_with(&format!("{}\r\n", "*".repeat(SECRET.len()))));
    let done = h.resolver.take_completions().pop().unwrap();
    assert_eq!(done.bytes_down, reply.len() as u64);
}

#[tokio::test]
async fn refused_command_in_multi_aborts_exec() {
    let h = Harness::default().await;
    let mut c = h.login().await;
    assert_eq!(c.call("MULTI").await, "+OK\r\n");
    assert_eq!(c.call("SET a 1").await, "+QUEUED\r\n");
    assert!(c.call("FLUSHALL").await.starts_with("-NOPERM"));
    assert_eq!(c.call("EXEC").await, "-EXECABORT Transaction discarded because of previous errors.\r\n");
    assert_eq!(c.call("GET a").await, "$-1\r\n");
    assert_eq!(c.call("MULTI").await, "+OK\r\n");
    assert_eq!(c.call("SET a 2").await, "+QUEUED\r\n");
    assert_eq!(c.call("EXEC").await, "*1\r\n+OK\r\n");
    assert_eq!(c.call("GET a").await, bulk("2"));
    assert_eq!(&h.fake.seen()[0][2..7], ["MULTI", "SET a 1", "DISCARD", "GET a", "MULTI"]);
    let exec = h.resolver.take_completions().into_iter().find(|c| c.action == "EXEC").unwrap();
    assert_eq!(exec.outcome, Outcome::Denied(ErrorCode::PolicyDenied));
}

#[tokio::test]
async fn upstream_refusing_the_secret_is_a_fixed_error() {
    let h = Harness::default().await;
    *h.fake.password.lock().unwrap() = "rotated".into();
    let mut c = connect(&h.ctx);
    c.send(&format!("AUTH {TOKEN}")).await;
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR seal unavailable: the upstream refused the sealed credential\r\n");
    assert!(matches!(result, Err(AdapterError::Upstream(UpstreamErrorKind::AuthRejected))));
    let done = h.resolver.take_completions();
    assert_eq!(done[0].outcome, Outcome::UpstreamError(UpstreamErrorKind::AuthRejected));
}

#[tokio::test]
async fn unreachable_upstream() {
    let resolver = FixedResolver::new();
    resolver.insert(TOKEN, redis_claims(&format!("rediss://{HOST}")));
    let ctx = AdapterCtx { resolver: resolver.clone(), upstream: TestUpstream::new() };
    let mut c = connect(&ctx);
    c.send(&format!("AUTH {TOKEN}")).await;
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR seal unavailable: the upstream could not be reached\r\n");
    assert!(matches!(result, Err(AdapterError::Upstream(UpstreamErrorKind::Connect))));
    assert_eq!(resolver.take_completions()[0].outcome, Outcome::UpstreamError(UpstreamErrorKind::Connect));
}

#[tokio::test]
async fn session_end_cuts_a_blocked_command() {
    let h = Harness::default().await;
    let mut c = h.login().await;
    c.send("BLPOP q 0").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.resolver.end_all(ErrorCode::SessionEnded);
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR seal session_ended: the session has ended\r\n");
    assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::SessionEnded))), "{result:?}");
    let done = h.resolver.take_completions();
    assert_eq!((done[0].action.as_str(), done[0].outcome.clone()), ("BLPOP", Outcome::Aborted));
}

#[tokio::test]
async fn session_end_closes_an_idle_connection() {
    let h = Harness::default().await;
    let c = h.login().await;
    h.resolver.end_all(ErrorCode::Expired);
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR seal expired: the session has ended\r\n");
    assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::Expired))));
    assert!(h.resolver.take_completions().is_empty());
}

#[tokio::test]
async fn verdicts() {
    let h = Harness::default().await;
    let mut c = h.login().await;
    h.resolver.set_verdict(Verdict::Refuse(ErrorCode::BudgetExceeded));
    assert_eq!(
        c.call("GET a").await,
        "-ERR seal budget_exceeded: the command was refused by the tenant's integrity policy\r\n"
    );
    h.resolver.set_verdict(Verdict::Forward);
    assert_eq!(c.call("PING").await, "+PONG\r\n");
    h.resolver.set_verdict(Verdict::End(ErrorCode::IntegrityFailed));
    c.send("PING").await;
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR seal integrity_failed: the session was ended by the tenant's integrity policy\r\n");
    assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::IntegrityFailed))));
    let outcomes: Vec<_> = h.resolver.take_completions().into_iter().map(|c| c.outcome).collect();
    assert_eq!(
        outcomes,
        vec![Outcome::Denied(ErrorCode::BudgetExceeded), Outcome::Allowed, Outcome::Denied(ErrorCode::IntegrityFailed)]
    );
    assert_eq!(h.fake.seen()[0].len(), 3, "AUTH, SELECT and the one forwarded PING");
}

#[tokio::test]
async fn login_verdict_refuses() {
    let h = Harness::default().await;
    h.resolver.set_verdict(Verdict::Refuse(ErrorCode::IntegrityFailed));
    let mut c = connect(&h.ctx);
    c.send(&format!("AUTH {TOKEN}")).await;
    let (rest, result) = c.closed().await;
    assert!(rest.starts_with("-ERR seal integrity_failed: "));
    assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::IntegrityFailed))));
    assert!(h.fake.seen().is_empty());
}

#[tokio::test]
async fn client_close_ends_quietly() {
    let h = Harness::default().await;
    let mut c = h.login().await;
    assert_eq!(c.call("PING").await, "+PONG\r\n");
    let result = c.hang_up().await;
    assert!(result.is_ok(), "{result:?}");
}

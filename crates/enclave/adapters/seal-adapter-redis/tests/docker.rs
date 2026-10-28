//! End to end against a real Redis 7 in Docker: TLS with a test CA (trusted through
//! `BakedRootsConnector::with_extra_roots`), an ACL user holding the secret, the default user
//! off. Each test starts its own container and skips when Docker is not available (or
//! `SEAL_SKIP_DOCKER` is set).

mod common;

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use common::{bulk, connect, pki, TestClient};
use seal_adapter::testing::{claims, FixedResolver};
use seal_adapter::{AdapterCtx, AdapterError, Outcome, UpstreamConnector, UpstreamErrorKind};
use seal_net::{BakedRootsConnector, BoxStream, Dialer, NetError};
use seal_proto::policy::Destination;
use seal_proto::ErrorCode;

const IMAGE: &str = "redis:7-alpine";
const HOST: &str = "redis.seal.test";
const SECRET: &str = "sk-redis-e2e-secret";
const TOKEN: &str = "seallk_e2e";

/// A Redis container, removed on drop.
struct Redis {
    id: String,
    addr: SocketAddr,
    ca_pem: String,
}

impl Drop for Redis {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

fn docker_available() -> bool {
    std::env::var_os("SEAL_SKIP_DOCKER").is_none()
        && Command::new("docker")
            .args(["info", "--format", "{{.ServerVersion}}"])
            .output()
            .is_ok_and(|o| o.status.success())
}

impl Redis {
    fn start() -> Option<Redis> {
        if !docker_available() {
            eprintln!("skipping: Docker is not available");
            return None;
        }
        let tls = pki::issue(&[HOST]);
        let conf = format!(
            "port 0\ntls-port 6379\ntls-cert-file /tls/cert.pem\ntls-key-file /tls/key.pem\n\
             tls-ca-cert-file /tls/ca.pem\ntls-auth-clients no\nsave \"\"\nappendonly no\n\
             user default off\nuser app on >{SECRET} ~* &* +@all\n"
        );
        let script =
            "mkdir -p /tls && printf '%s' \"$TLS_CERT\" > /tls/cert.pem && printf '%s' \"$TLS_KEY\" > /tls/key.pem \
                      && printf '%s' \"$TLS_CA\" > /tls/ca.pem && printf '%s' \"$REDIS_CONF\" > /tls/redis.conf \
                      && exec redis-server /tls/redis.conf";
        let env = |name: &str, value: &str| format!("{name}={value}");
        let out = Command::new("docker")
            .args(["run", "-d", "--rm", "-p", "127.0.0.1::6379"])
            .args(["-e", &env("TLS_CERT", &tls.cert_pem), "-e", &env("TLS_KEY", &tls.key_pem)])
            .args(["-e", &env("TLS_CA", &tls.ca_pem), "-e", &env("REDIS_CONF", &conf)])
            .args([IMAGE, "sh", "-c", script])
            .output()
            .expect("docker run");
        assert!(out.status.success(), "docker run: {}", String::from_utf8_lossy(&out.stderr));
        let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let port = Command::new("docker").args(["port", &id, "6379/tcp"]).output().expect("docker port");
        let mapped = String::from_utf8(port.stdout).unwrap();
        let addr = mapped.lines().find_map(|l| l.trim().parse().ok());
        let redis =
            Redis { id, addr: addr.unwrap_or_else(|| panic!("no mapped port in {mapped:?}")), ca_pem: tls.ca_pem };
        Some(redis)
    }
}

/// Dials one address whatever the host, so the certificate is still checked for `HOST`.
struct FixedDialer(SocketAddr);

#[async_trait]
impl Dialer for FixedDialer {
    async fn dial(&self, _host: &str, _port: u16) -> Result<BoxStream, NetError> {
        let stream = tokio::net::TcpStream::connect(self.0).await.map_err(|e| NetError::Connect {
            host: self.0.to_string(),
            port: self.0.port(),
            reason: e.to_string(),
        })?;
        Ok(Box::new(stream))
    }
}

struct Env {
    _redis: Redis,
    resolver: Arc<FixedResolver>,
    ctx: AdapterCtx,
}

fn destination() -> Destination {
    Destination::parse(&format!("rediss://app@{HOST}:6379/2")).unwrap()
}

async fn env() -> Option<Env> {
    let redis = Redis::start()?;
    let connector = Arc::new(
        BakedRootsConnector::with_extra_roots(Arc::new(FixedDialer(redis.addr)), redis.ca_pem.as_bytes()).unwrap(),
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while connector.connect(&destination(), &Default::default()).await.is_err() {
        assert!(tokio::time::Instant::now() < deadline, "Redis did not start");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let resolver = FixedResolver::new();
    resolver.insert(TOKEN, claims(destination(), SECRET.as_bytes()));
    let ctx = AdapterCtx { resolver: resolver.clone(), upstream: connector };
    Some(Env { _redis: redis, resolver, ctx })
}

impl Env {
    async fn login(&self) -> TestClient {
        let mut c = connect(&self.ctx);
        assert_eq!(c.call(&format!("AUTH {TOKEN}")).await, "+OK\r\n");
        c
    }

    async fn login3(&self) -> TestClient {
        let mut c = connect(&self.ctx);
        let hello = c.call(&format!("HELLO 3 AUTH default {TOKEN}")).await;
        assert!(hello.starts_with('%') && hello.contains("redis"), "{hello}");
        c
    }

    /// (action, outcome) of every completion so far, in order.
    fn outcomes(&self) -> Vec<(String, Outcome)> {
        self.resolver.take_completions().into_iter().map(|c| (c.action, c.outcome)).collect()
    }
}

fn allowed(action: &str) -> (String, Outcome) {
    (action.to_string(), Outcome::Allowed)
}

#[tokio::test]
async fn get_set_as_the_destination_user_and_db() {
    let Some(e) = env().await else { return };
    let mut c = e.login().await;
    assert_eq!(c.call("SET k v").await, "+OK\r\n");
    assert_eq!(c.call("GET k").await, bulk("v"));
    let info = c.call("CLIENT INFO").await;
    assert!(info.contains(" db=2 ") && info.contains(" user=app "), "{info}");
    assert_eq!(c.call("SELECT 2").await, "+OK\r\n");
    assert_eq!(c.call("DBSIZE").await, ":1\r\n");
    assert_eq!(e.outcomes(), ["AUTH", "SET", "GET", "CLIENT", "SELECT", "DBSIZE"].map(allowed).to_vec());
    assert!(c.hang_up().await.is_ok());
}

#[tokio::test]
async fn resp3_through_hello() {
    let Some(e) = env().await else { return };
    let mut c = e.login3().await;
    assert_eq!(c.call("HSET h a 1").await, ":1\r\n");
    assert_eq!(c.call("HGETALL h").await, format!("%1\r\n{}{}", bulk("a"), bulk("1")));
    assert_eq!(c.call("GET missing").await, "_\r\n");
    assert_eq!(e.outcomes()[0], allowed("HELLO"));
}

#[tokio::test]
async fn refused_commands_never_reach_redis() {
    let Some(e) = env().await else { return };
    let mut c = e.login().await;
    for line in
        ["CONFIG GET requirepass", "SELECT 0", "ACL WHOAMI", "AUTH app x", "SWAPDB 0 2", "FLUSHALL", "CLIENT KILL ID 1"]
    {
        let reply = c.call(line).await;
        assert!(reply.starts_with("-NOPERM seal policy_denied: "), "{line}: {reply}");
    }
    assert_eq!(c.call("SET still connected").await, "+OK\r\n");
    let outcomes = e.outcomes();
    assert_eq!(outcomes.iter().filter(|(_, o)| *o == Outcome::Denied(ErrorCode::PolicyDenied)).count(), 7);
}

#[tokio::test]
async fn wrong_credential_is_refused() {
    let Some(e) = env().await else { return };
    let mut c = connect(&e.ctx);
    c.send("AUTH seallk_nope").await;
    let (rest, result) = c.closed().await;
    assert!(rest.starts_with("-WRONGPASS seal not_allowed: "), "{rest}");
    assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::NotAllowed))));
}

#[tokio::test]
async fn wrong_secret_is_refused_by_redis() {
    let Some(e) = env().await else { return };
    e.resolver.insert("seallk_stale", claims(destination(), b"an-old-password"));
    let mut c = connect(&e.ctx);
    c.send("AUTH seallk_stale").await;
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR seal unavailable: the upstream refused the sealed credential\r\n");
    assert!(matches!(result, Err(AdapterError::Upstream(UpstreamErrorKind::AuthRejected))));
}

#[tokio::test]
async fn pipelined_replies_keep_order() {
    let Some(e) = env().await else { return };
    let mut c = e.login().await;
    let mut pipeline = Vec::new();
    for i in 0..200 {
        let line = if i % 10 == 9 { "CONFIG SET x y".to_string() } else { "INCR n".to_string() };
        pipeline.extend(seal_adapter_redis::resp::encode_command(&common::words(&line)));
    }
    c.raw(&pipeline).await;
    let mut n = 0;
    for i in 0..200 {
        let reply = c.text().await;
        if i % 10 == 9 {
            assert!(reply.starts_with("-NOPERM"), "{i}: {reply}");
        } else {
            n += 1;
            assert_eq!(reply, format!(":{n}\r\n"), "{i}");
        }
    }
    let outcomes = e.outcomes();
    assert_eq!(outcomes.len(), 201);
}

#[tokio::test]
async fn pubsub_resp2() {
    let Some(e) = env().await else { return };
    let mut sub = e.login().await;
    let mut publisher = e.login().await;
    let frame = |kind: &str, ch: &str, n: i64| format!("*3\r\n{}{}:{n}\r\n", bulk(kind), bulk(ch));
    sub.send("SUBSCRIBE a b").await;
    assert_eq!(sub.text().await, frame("subscribe", "a", 1));
    assert_eq!(sub.text().await, frame("subscribe", "b", 2));
    assert_eq!(publisher.call("PUBLISH a hello").await, ":1\r\n");
    assert_eq!(sub.text().await, format!("*3\r\n{}{}{}", bulk("message"), bulk("a"), bulk("hello")));
    assert_eq!(sub.call("PING").await, format!("*2\r\n{}$0\r\n\r\n", bulk("pong")));
    assert_eq!(sub.call("PSUBSCRIBE p*").await, frame("psubscribe", "p*", 3));
    assert_eq!(publisher.call(&format!("PUBLISH pq {SECRET}")).await, ":1\r\n");
    let masked = "*".repeat(SECRET.len());
    assert_eq!(sub.text().await, format!("*4\r\n{}{}{}{}", bulk("pmessage"), bulk("p*"), bulk("pq"), bulk(&masked)));
    // Without channels: one confirmation per subscribed channel.
    sub.send("UNSUBSCRIBE").await;
    let (first, second) = (sub.text().await, sub.text().await);
    assert!(first.starts_with(&format!("*3\r\n{}", bulk("unsubscribe"))) && first.ends_with(":2\r\n"), "{first}");
    assert!(second.ends_with(":1\r\n"), "{second}");
    assert_eq!(sub.call("PUNSUBSCRIBE").await, frame("punsubscribe", "p*", 0));
    // No longer subscribed: an ordinary command again.
    assert_eq!(sub.call("GET k").await, "$-1\r\n");

    let mut outcomes = e.outcomes();
    outcomes.retain(|(a, _)| a != "AUTH" && a != "PUBLISH");
    assert_eq!(
        outcomes,
        ["SUBSCRIBE", "PING", "PSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE", "GET"].map(allowed).to_vec()
    );
}

#[tokio::test]
async fn pubsub_resp3() {
    let Some(e) = env().await else { return };
    let mut sub = e.login3().await;
    let mut publisher = e.login().await;
    assert_eq!(sub.call("SUBSCRIBE a").await, format!(">3\r\n{}{}:1\r\n", bulk("subscribe"), bulk("a")));
    // RESP3 allows ordinary commands while subscribed.
    assert_eq!(sub.call("SET k v").await, "+OK\r\n");
    assert_eq!(publisher.call("PUBLISH a hi").await, ":1\r\n");
    assert_eq!(sub.text().await, format!(">3\r\n{}{}{}", bulk("message"), bulk("a"), bulk("hi")));
    assert_eq!(sub.call("GET k").await, bulk("v"));
    assert_eq!(sub.call("UNSUBSCRIBE a").await, format!(">3\r\n{}{}:0\r\n", bulk("unsubscribe"), bulk("a")));
    let mut outcomes = e.outcomes();
    outcomes.retain(|(a, _)| a != "AUTH" && a != "PUBLISH" && a != "HELLO");
    assert_eq!(outcomes, ["SUBSCRIBE", "SET", "GET", "UNSUBSCRIBE"].map(allowed).to_vec());
}

#[tokio::test]
async fn multi_exec() {
    let Some(e) = env().await else { return };
    let mut c = e.login().await;
    assert_eq!(c.call("MULTI").await, "+OK\r\n");
    assert_eq!(c.call("SET a 1").await, "+QUEUED\r\n");
    assert_eq!(c.call("INCR a").await, "+QUEUED\r\n");
    assert_eq!(c.call("EXEC").await, "*2\r\n+OK\r\n:2\r\n");
    assert_eq!(c.call("MULTI").await, "+OK\r\n");
    assert_eq!(c.call("SET b 1").await, "+QUEUED\r\n");
    assert!(c.call("MOVE b 0").await.starts_with("-NOPERM"));
    assert_eq!(c.call("EXEC").await, "-EXECABORT Transaction discarded because of previous errors.\r\n");
    assert_eq!(c.call("GET b").await, "$-1\r\n");
    assert_eq!(c.call("GET a").await, bulk("2"));
}

#[tokio::test]
async fn secret_stored_and_read_back_is_masked() {
    let Some(e) = env().await else { return };
    let mut c = e.login().await;
    let masked = "*".repeat(SECRET.len());
    assert_eq!(c.call(&format!("SET k {SECRET}")).await, "+OK\r\n");
    assert_eq!(c.call("GET k").await, bulk(&masked));
    assert_eq!(c.call(&format!("RPUSH l x {SECRET} y")).await, ":3\r\n");
    assert_eq!(c.call("LRANGE l 0 -1").await, format!("*3\r\n{}{}{}", bulk("x"), bulk(&masked), bulk("y")));
    let big = format!("{}{SECRET}", "v".repeat(500_000));
    assert_eq!(c.call(&format!("SET big {big}")).await, "+OK\r\n");
    let reply = c.call("GET big").await;
    assert_eq!(reply.len(), bulk(&big).len());
    assert!(!reply.contains(SECRET));
    assert!(reply.ends_with(&format!("{masked}\r\n")));
}

#[tokio::test]
async fn session_end_cuts_a_blocked_command() {
    let Some(e) = env().await else { return };
    let mut c = e.login().await;
    c.send("BLPOP queue 0").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    e.resolver.end_all(ErrorCode::SessionEnded);
    let (rest, result) = c.closed().await;
    assert_eq!(rest, "-ERR seal session_ended: the session has ended\r\n");
    assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::SessionEnded))));
    let outcomes = e.outcomes();
    assert_eq!(outcomes.last().unwrap(), &("BLPOP".to_string(), Outcome::Aborted));
}

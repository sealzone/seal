//! Test helpers: a raw-protocol Postgres client on an in-memory pipe, the adapter serving the
//! other end, and a scripted SCRAM upstream reached through `TestUpstream`.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::BytesMut;
use hmac::{Hmac, KeyInit, Mac};
use postgres_protocol::message::frontend;
use seal_adapter::{Adapter, AdapterCtx, AdapterError, ConnMeta, SessionResolver, UpstreamConnector};
use seal_adapter_pg::PostgresAdapter;
use seal_proto::policy::Protocol;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

pub type Msg = (u8, Vec<u8>);

/// The client end of a connection to the adapter. Keeps every byte it received.
pub struct PgClient {
    s: DuplexStream,
    pub received: Vec<u8>,
}

/// Starts a new adapter on one end of a pipe; returns the client end and the `serve` task.
pub fn connect(
    resolver: Arc<dyn SessionResolver>,
    upstream: Arc<dyn UpstreamConnector>,
) -> (PgClient, JoinHandle<Result<(), AdapterError>>) {
    connect_to(Arc::default(), resolver, upstream)
}

/// As `connect`, to `adapter`: connections to one adapter can cancel each other's queries.
pub fn connect_to(
    adapter: Arc<PostgresAdapter>,
    resolver: Arc<dyn SessionResolver>,
    upstream: Arc<dyn UpstreamConnector>,
) -> (PgClient, JoinHandle<Result<(), AdapterError>>) {
    connect_through(adapter, resolver, upstream, seal_adapter::testing::TUNNEL_TOKEN)
}

/// As `connect_to`, through a tunnel whose preamble carries `token`.
pub fn connect_through(
    adapter: Arc<PostgresAdapter>,
    resolver: Arc<dyn SessionResolver>,
    upstream: Arc<dyn UpstreamConnector>,
    token: &str,
) -> (PgClient, JoinHandle<Result<(), AdapterError>>) {
    let (client, server) = tokio::io::duplex(1 << 20);
    let ctx = AdapterCtx { resolver, upstream };
    let meta = ConnMeta {
        connection_id: 7,
        protocol: Protocol::Postgres,
        peer: None,
        tunnel: seal_proto::tunnel::TunnelConnect {
            token: seal_proto::Bearer::new(token.into()),
            local_key_sha256: [0; 32],
        },
    };
    let task = tokio::spawn(async move { adapter.serve(Box::new(server), meta, ctx).await });
    (PgClient { s: client, received: Vec::new() }, task)
}

pub fn message(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![ty];
    out.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn startup_packet(params: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    frontend::startup_message(params.iter().copied(), &mut buf).unwrap();
    buf.to_vec()
}

pub fn query_msg(sql: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    frontend::query(sql, &mut buf).unwrap();
    buf.to_vec()
}

/// `Parse` (unnamed), `Bind`, `Describe` portal, `Execute`, `Sync`.
pub fn extended_msgs(sql: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    frontend::parse("", sql, [], &mut buf).unwrap();
    // Unnamed portal and statement, no parameters, no result formats.
    buf.extend_from_slice(&message(b'B', &[0, 0, 0, 0, 0, 0, 0, 0]));
    frontend::describe(b'P', "", &mut buf).unwrap();
    frontend::execute("", 0, &mut buf).unwrap();
    frontend::sync(&mut buf);
    buf.to_vec()
}

/// The `M` field of an `ErrorResponse` body.
pub fn error_field(body: &[u8], code: u8) -> Option<String> {
    let mut rest = body;
    while let Some((&c, after)) = rest.split_first() {
        if c == 0 {
            return None;
        }
        let nul = after.iter().position(|&b| b == 0)?;
        if c == code {
            return Some(String::from_utf8_lossy(&after[..nul]).into_owned());
        }
        rest = &after[nul + 1..];
    }
    None
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

impl PgClient {
    pub async fn send(&mut self, bytes: &[u8]) {
        self.s.write_all(bytes).await.unwrap();
    }

    /// One whole message; `None` at end of stream.
    pub async fn read_msg(&mut self) -> Option<Msg> {
        read_msg(&mut self.s, &mut self.received).await
    }

    pub async fn read_byte(&mut self) -> Option<u8> {
        let mut b = [0u8; 1];
        self.s.read_exact(&mut b).await.ok()?;
        self.received.push(b[0]);
        Some(b[0])
    }

    /// Messages up to and including the next `ReadyForQuery`, or up to the end of stream.
    pub async fn until_ready(&mut self) -> Vec<Msg> {
        let mut out = Vec::new();
        while let Some(m) = self.read_msg().await {
            let done = m.0 == b'Z';
            out.push(m);
            if done {
                break;
            }
        }
        out
    }

    /// Startup with `params`, then the password; returns everything up to `ReadyForQuery` (or
    /// the refusal).
    pub async fn login(&mut self, params: &[(&str, &str)], password: &str) -> Vec<Msg> {
        self.send(&startup_packet(params)).await;
        let mut first = Vec::new();
        loop {
            let m = self.read_msg().await.expect("an authentication request");
            if m.0 == b'R' {
                assert_eq!(m.1, 3i32.to_be_bytes(), "cleartext password requested");
                break;
            }
            first.push(m);
        }
        let mut buf = BytesMut::new();
        frontend::password_message(password.as_bytes(), &mut buf).unwrap();
        self.send(&buf).await;
        first.extend(self.until_ready().await);
        first
    }

    pub async fn query(&mut self, sql: &str) -> Vec<Msg> {
        self.send(&query_msg(sql)).await;
        self.until_ready().await
    }

    /// Reads to the end of stream; returns what arrived.
    pub async fn drain(&mut self) -> Vec<Msg> {
        let mut out = Vec::new();
        while let Some(m) = self.read_msg().await {
            out.push(m);
        }
        out
    }
}

pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R, log: &mut Vec<u8>) -> Option<Msg> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header).await.ok()?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut body = vec![0u8; len - 4];
    r.read_exact(&mut body).await.ok()?;
    log.extend_from_slice(&header);
    log.extend_from_slice(&body);
    Some((header[0], body))
}

/// How the fake upstream authenticates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeAuth {
    Scram,
    Md5,
    Cleartext,
    Trust,
}

/// What the fake upstream saw.
#[derive(Default)]
pub struct FakeLog {
    pub startup: Vec<(String, String)>,
    /// Message types received after authentication, in order.
    pub types: Vec<u8>,
    pub queries: Vec<String>,
    /// Every byte received, for "the secret was never sent in clear" checks.
    pub raw: Vec<u8>,
    pub connections: usize,
    /// `CancelRequest`s received: process ID and key.
    pub cancels: Vec<(i32, i32)>,
}

/// A scripted Postgres server speaking plain TCP (TLS is the connector's job, tested with Docker).
/// It authenticates with SCRAM-SHA-256 against `password`, reports a `ParameterStatus` and
/// error texts carrying the password, and answers:
/// - `SELECT leak`: one row whose value contains the password;
/// - `SELECT big`: one 200 KiB row with the password in the middle;
/// - `SELECT error`: an `ERROR` whose message contains the password;
/// - `SELECT hang`: nothing, ever;
/// - `BEGIN`/`COMMIT`: transaction status `T`/`I`;
/// - anything else: `SELECT 0`. Extended-protocol messages get their usual replies.
pub struct FakeUpstream {
    pub addr: std::net::SocketAddr,
    pub log: Arc<Mutex<FakeLog>>,
}

impl FakeUpstream {
    pub async fn start(password: &'static str, auth: FakeAuth) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Mutex::new(FakeLog::default()));
        let l = log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else { return };
                l.lock().unwrap().connections += 1;
                let l = l.clone();
                tokio::spawn(async move {
                    let _ = fake_conn(s, password, auth, l).await;
                });
            }
        });
        Self { addr, log }
    }
}

struct Logged<'a> {
    s: TcpStream,
    log: &'a Mutex<FakeLog>,
}

impl Logged<'_> {
    async fn read_msg(&mut self) -> Option<Msg> {
        let mut raw = Vec::new();
        let m = read_msg(&mut self.s, &mut raw).await;
        self.log.lock().unwrap().raw.extend(raw);
        m
    }
    async fn send(&mut self, bytes: &[u8]) -> Option<()> {
        self.s.write_all(bytes).await.ok()
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hi(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut prev = hmac(password, &[salt, &[0, 0, 0, 1]].concat());
    let mut out = prev;
    for _ in 1..iterations {
        prev = hmac(password, &prev);
        out.iter_mut().zip(prev).for_each(|(o, p)| *o ^= p);
    }
    out
}

fn auth(code: i32, data: &[u8]) -> Vec<u8> {
    message(b'R', &[&code.to_be_bytes()[..], data].concat())
}

pub fn error_body(severity: &str, code: &str, text: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (c, v) in [(b'S', severity), (b'V', severity), (b'C', code), (b'M', text)] {
        body.push(c);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    body
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// Body of a `p` message after the mechanism name and length: the SASL data.
fn sasl_data(body: &[u8], initial: bool) -> Vec<u8> {
    if !initial {
        return body.to_vec();
    }
    let nul = body.iter().position(|&b| b == 0).unwrap();
    body[nul + 5..].to_vec()
}

async fn fake_conn(s: TcpStream, password: &str, mode: FakeAuth, log: Arc<Mutex<FakeLog>>) -> Option<()> {
    let mut c = Logged { s, log: &log };
    let mut len = [0u8; 4];
    c.s.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize - 4];
    c.s.read_exact(&mut body).await.ok()?;
    if body.len() == 12 && body[..4] == 80_877_102i32.to_be_bytes() {
        let word = |at: usize| i32::from_be_bytes(body[at..at + 4].try_into().unwrap());
        log.lock().unwrap().cancels.push((word(4), word(8)));
        return None;
    }
    let mut rest = &body[4..];
    let mut startup = Vec::new();
    while rest.first() != Some(&0) {
        let k = rest.iter().position(|&b| b == 0)?;
        let name = String::from_utf8_lossy(&rest[..k]).into_owned();
        rest = &rest[k + 1..];
        let v = rest.iter().position(|&b| b == 0)?;
        startup.push((name, String::from_utf8_lossy(&rest[..v]).into_owned()));
        rest = &rest[v + 1..];
    }
    log.lock().unwrap().startup = startup;

    match mode {
        FakeAuth::Md5 => {
            c.send(&auth(5, b"salt")).await?;
            c.read_msg().await?;
            return None;
        }
        FakeAuth::Cleartext => {
            c.send(&auth(3, b"")).await?;
            c.read_msg().await?;
            return None;
        }
        FakeAuth::Trust => {}
        FakeAuth::Scram => {
            c.send(&auth(10, b"SCRAM-SHA-256\0\0")).await?;
            let (_, first) = c.read_msg().await?;
            let client_first = String::from_utf8(sasl_data(&first, true)).ok()?;
            let bare = client_first.strip_prefix("n,,")?.to_string();
            let client_nonce = bare.split("r=").nth(1)?.to_string();
            let salt = b"seal-test-salt";
            let server_first = format!("r={client_nonce}SERVERNONCE,s={},i=4096", STANDARD.encode(salt));
            c.send(&auth(11, server_first.as_bytes())).await?;
            let (_, fin) = c.read_msg().await?;
            let client_final = String::from_utf8(sasl_data(&fin, false)).ok()?;
            let (without_proof, proof) = client_final.rsplit_once(",p=")?;
            let salted = hi(password.as_bytes(), salt, 4096);
            let client_key = hmac(&salted, b"Client Key");
            let stored: [u8; 32] = Sha256::digest(client_key).into();
            let auth_message = format!("{bare},{server_first},{without_proof}");
            let signature = hmac(&stored, auth_message.as_bytes());
            let expected: Vec<u8> = client_key.iter().zip(signature).map(|(k, s)| k ^ s).collect();
            if STANDARD.decode(proof).ok()? != expected {
                let text = format!("password authentication failed; expected {password}");
                c.send(&message(b'E', &error_body("FATAL", "28P01", &text))).await?;
                return None;
            }
            let server_sig = hmac(&hmac(&salted, b"Server Key"), auth_message.as_bytes());
            c.send(&auth(12, format!("v={}", STANDARD.encode(server_sig)).as_bytes())).await?;
        }
    }
    c.send(&auth(0, b"")).await?;
    c.send(&message(b'S', &[cstr("server_version"), cstr("16.4")].concat())).await?;
    c.send(&message(b'S', &[cstr("leak"), cstr(&format!("pw={password}"))].concat())).await?;
    c.send(&message(b'K', &[4242i32.to_be_bytes(), 777i32.to_be_bytes()].concat())).await?;
    c.send(&message(b'Z', b"I")).await?;

    let mut status = b'I';
    loop {
        let (ty, body) = c.read_msg().await?;
        log.lock().unwrap().types.push(ty);
        let mut reply = Vec::new();
        match ty {
            b'Q' => {
                let sql = String::from_utf8_lossy(&body[..body.len() - 1]).into_owned();
                log.lock().unwrap().queries.push(sql.clone());
                match sql.as_str() {
                    "SELECT leak" | "SELECT big" => {
                        let value = if sql == "SELECT big" {
                            format!("{}{password}{}", "a".repeat(100_000), "b".repeat(100_000))
                        } else {
                            format!("key={password}")
                        };
                        let mut desc = 1i16.to_be_bytes().to_vec();
                        desc.extend(cstr("v"));
                        desc.extend([0u8; 6]);
                        desc.extend(25i32.to_be_bytes());
                        desc.extend((-1i16).to_be_bytes());
                        desc.extend((-1i32).to_be_bytes());
                        desc.extend(0i16.to_be_bytes());
                        reply.extend(message(b'T', &desc));
                        let mut row = 1i16.to_be_bytes().to_vec();
                        row.extend((value.len() as i32).to_be_bytes());
                        row.extend(value.as_bytes());
                        reply.extend(message(b'D', &row));
                        reply.extend(message(b'C', &cstr("SELECT 1")));
                    }
                    "SELECT error" => {
                        reply.extend(message(b'E', &error_body("ERROR", "42000", &format!("bad key {password}"))));
                    }
                    "SELECT hang" => {
                        std::future::pending::<()>().await;
                    }
                    "BEGIN" => {
                        status = b'T';
                        reply.extend(message(b'C', &cstr("BEGIN")));
                    }
                    "COMMIT" => {
                        status = b'I';
                        reply.extend(message(b'C', &cstr("COMMIT")));
                    }
                    _ => reply.extend(message(b'C', &cstr("SELECT 0"))),
                }
                reply.extend(message(b'Z', &[status]));
            }
            b'P' => {
                let nul = body.iter().position(|&b| b == 0)?;
                let sql = &body[nul + 1..];
                let end = sql.iter().position(|&b| b == 0)?;
                log.lock().unwrap().queries.push(String::from_utf8_lossy(&sql[..end]).into_owned());
                reply.extend(message(b'1', b""));
            }
            b'B' => reply.extend(message(b'2', b"")),
            b'D' => reply.extend(message(b'n', b"")),
            b'E' => reply.extend(message(b'C', &cstr("SELECT 0"))),
            b'C' => reply.extend(message(b'3', b"")),
            b'S' => reply.extend(message(b'Z', &[status])),
            b'X' => return None,
            _ => {}
        }
        c.send(&reply).await?;
    }
}

//! Redis (RESP2/3): AUTH/HELLO interception, upstream TLS AUTH and `SELECT` of the
//! destination's db, then a relay that checks every command and scrubs every reply.
//!
//! **Login.** The client's first command must authenticate: `AUTH <credential>`,
//! `AUTH <user> <credential>` or `HELLO <2|3> AUTH <user> <credential> [SETNAME <name>]`. The
//! local key is found in the password with `find_local_key` (the client's user is ignored)
//! and resolved; the session must be for a `rediss://` destination. Other commands before
//! that are answered `-NOAUTH`, `QUIT` closes, and the client has `LOGIN_TIMEOUT`. A refused
//! credential is answered `-WRONGPASS` and closes the connection. The login is observed
//! (content `AUTH` or `HELLO <v>`, never the credential); a refusing verdict closes too.
//!
//! **Upstream.** `UpstreamConnector::connect` (verified TLS), then the client's own form with
//! the destination's user and the secret: `AUTH [<user>] <secret>` or
//! `HELLO <v> AUTH <user or default> <secret> [SETNAME <name>]`, then `SELECT <db>` unless the
//! db is 0, all within `HANDSHAKE_TIMEOUT`. The client gets `+OK`, or the upstream's HELLO
//! reply (scrubbed; it carries no credential). A failure is answered with a fixed `-ERR` and
//! closes the connection; upstream text is never relayed or recorded.
//!
//! **Relay.** Every command is re-encoded as a RESP array before it is forwarded, so the
//! upstream runs exactly what was checked. Refused with `-NOPERM`, the connection staying open:
//! - `AUTH` and `HELLO … AUTH`: the connection's upstream identity is the destination's.
//! - Reaching outside the destination's db: `SELECT` of any other db, `SWAPDB`, `MOVE`,
//!   `COPY … DB` of another db, `FLUSHALL`, and `MIGRATE` (which also sends keys, and any
//!   credentials it is given, to another server).
//! - Connection modes the relay depends on not changing: `RESET` (drops the upstream
//!   authentication and db), `CLIENT REPLY OFF|SKIP` (replies would stop matching commands),
//!   and `MONITOR`, `SYNC`, `PSYNC`, `REPLCONF` (they turn the connection into a stream that
//!   answers no command).
//! - Server administration no application needs, which acts beyond this session: `ACL`,
//!   `CONFIG` (`CONFIG GET` returns passwords), `MODULE`, `DEBUG`, `SHUTDOWN`, `REPLICAOF`,
//!   `SLAVEOF`, `FAILOVER`, and `CLIENT KILL|PAUSE|UNPAUSE` (they act on other connections,
//!   other sessions' included).
//!
//! Everything else is left to the upstream user's ACL, which is what really limits a session:
//! scripts and functions (`EVAL`, `FCALL`) run commands inside Redis that the adapter never sees.
//!
//! Each command that passes is observed (`Observation::action` = the upper-cased command name,
//! `content` = the command line, see `policy::content`) and the verdict obeyed: `Refuse`
//! answers `-ERR` and keeps the connection, `End` ends it as below. Each command gets one
//! `Session::complete`: `Denied` when refused, `Allowed` once its reply is relayed
//! (`UpstreamError(AuthRejected)` for a `-NOPERM` reply), `Aborted` when cut. Byte counts are
//! the command as forwarded and the reply as relayed.
//!
//! Pipelined commands are forwarded without waiting, and replies keep command order with
//! the adapter's own refusals in place. Pub/sub works in RESP2 and RESP3: a
//! `(P|S)(UN)SUBSCRIBE` completes once every confirmation arrived, messages and other pushes
//! are relayed as they come. In `MULTI`, a refused command makes `EXEC` fail with
//! `-EXECABORT` (the upstream's queue is discarded), as Redis does for a command that fails
//! while queuing. Cluster redirects (`-MOVED`, `-ASK`) are relayed, not followed.
//!
//! Every relayed reply passes the `Scrubber` (needle: the secret), flushed at each reply's
//! end. Masking keeps lengths, so framing stays intact, unless the secret itself looks like
//! framing (all digits, CRLF): then a reply may be corrupted, never leaked.
//!
//! When `Session::ended` fires, commands in flight are completed `Aborted`, the client gets
//! `-ERR seal <code>: …` unless a reply is half relayed, and the connection closes; `serve`
//! returns `AdapterError::Denied(code)`. Seal's errors read `-<PREFIX> seal <code>: <text>`
//! with fixed text. Framing limits: `resp`.
#![forbid(unsafe_code)]

mod policy;
mod relay;
pub mod resp;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use seal_adapter::scrub::Scrubber;
use seal_adapter::{
    Adapter, AdapterCtx, AdapterError, BoxStream, ConnMeta, Observation, Outcome, Session, UpstreamErrorKind,
    UpstreamStream, Verdict,
};
use seal_proto::policy::{Destination, Protocol};
use seal_proto::tunnel::find_local_key;
use seal_proto::ErrorCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use zeroize::{Zeroize, Zeroizing};

use relay::{complete, Down, DownEnd, Up, UpEnd, MAX_PIPELINE};
use resp::{encode_into, CommandReader, FrameError, FrameInfo, ReplyScanner};

/// Time a client has to authenticate.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// Time the upstream has to answer `AUTH`/`HELLO` and `SELECT`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// After the client closes (or sends a malformed command), how long replies still in flight
/// may take before they are cut.
const CLOSE_GRACE: Duration = Duration::from_secs(1);
/// Largest upstream handshake reply (the HELLO map).
const HANDSHAKE_REPLY_MAX: usize = 64 << 10;

const NOAUTH_HELLO: &[u8] = b"-NOAUTH HELLO must be called with the client already authenticated, otherwise the \
HELLO <proto> AUTH <user> <pass> option can be used to authenticate the client and select the RESP protocol version \
at the same time\r\n";
const SESSION_ENDED: &str = "the session has ended";
const INTEGRITY_ENDED: &str = "the session was ended by the tenant's integrity policy";

#[derive(Debug, Default)]
pub struct RedisAdapter;

#[async_trait]
impl Adapter for RedisAdapter {
    fn protocol(&self) -> Protocol {
        Protocol::Redis
    }

    /// Serves until the client or the upstream closes (`Ok`), the session ends or a refusal
    /// closes the connection (`Denied`), the upstream fails (`Upstream`), or the client sends a
    /// malformed command (`Client`).
    async fn serve(&self, inbound: BoxStream, meta: ConnMeta, ctx: AdapterCtx) -> Result<(), AdapterError> {
        let (reader, writer) = tokio::io::split(inbound);
        let mut client = Client { reader, writer, buf: BytesMut::new(), commands: CommandReader::default() };
        let login = match tokio::time::timeout(LOGIN_TIMEOUT, login(&mut client, &meta, &ctx)).await {
            Ok(login) => login?,
            Err(_) => {
                client.close(None).await;
                return Err(AdapterError::Client("no AUTH in time"));
            }
        };
        let Some(login) = login else {
            client.close(None).await;
            return Ok(());
        };
        let session = login.session.clone();
        let upstream = tokio::select! {
            upstream = open_upstream(&ctx, &login) => upstream,
            code = session.ended() => {
                complete(&*session, login.action, Outcome::Aborted, 0, 0);
                client.close(Some(&error_reply("ERR", code, SESSION_ENDED))).await;
                return Err(AdapterError::Denied(code));
            }
        };
        match upstream {
            Ok(upstream) => relay(client, upstream, login).await,
            Err(failure) => {
                complete(&*session, login.action, Outcome::UpstreamError(failure.kind), 0, 0);
                client.close(Some(&error_reply("ERR", failure.code, failure.message))).await;
                Err(AdapterError::Upstream(failure.kind))
            }
        }
    }
}

/// ASCII upper case.
fn upper(name: &[u8]) -> Vec<u8> {
    name.to_ascii_uppercase()
}

/// `-<prefix> seal <code>: <message>`.
fn error_reply(prefix: &str, code: ErrorCode, message: &str) -> Vec<u8> {
    format!("-{prefix} seal {}: {message}\r\n", code.as_str()).into_bytes()
}

/// The inbound connection before the relay.
struct Client {
    reader: ReadHalf<BoxStream>,
    writer: WriteHalf<BoxStream>,
    buf: BytesMut,
    commands: CommandReader,
}

impl Client {
    /// The next command; `None` when the client closed.
    async fn command(&mut self) -> Result<Option<Vec<Vec<u8>>>, FrameError> {
        loop {
            if let Some(command) = self.commands.next(&mut self.buf)? {
                return Ok(Some(command));
            }
            match self.reader.read_buf(&mut self.buf).await {
                Ok(0) | Err(_) => return Ok(None),
                Ok(_) => {}
            }
        }
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), AdapterError> {
        self.writer.write_all(bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn close(&mut self, last: Option<&[u8]>) {
        if let Some(bytes) = last {
            let _ = self.writer.write_all(bytes).await;
        }
        let _ = self.writer.flush().await;
        let _ = self.writer.shutdown().await;
    }
}

struct Login {
    session: Arc<dyn Session>,
    /// `None`: the client logged in with `AUTH` (RESP2).
    hello: Option<Hello>,
    action: &'static str,
}

#[derive(Debug)]
struct Hello {
    proto: u8,
    setname: Option<Vec<u8>>,
}

/// Reads commands until one authenticates; `None` when the client quits first.
async fn login(client: &mut Client, meta: &ConnMeta, ctx: &AdapterCtx) -> Result<Option<Login>, AdapterError> {
    loop {
        let mut args = match client.command().await {
            Ok(Some(args)) => args,
            Ok(None) => return Ok(None),
            Err(FrameError(reason)) => {
                client.close(Some(format!("-ERR Protocol error: {reason}\r\n").as_bytes())).await;
                return Err(AdapterError::Client(reason));
            }
        };
        let attempt = match upper(&args[0]).as_slice() {
            b"AUTH" if matches!(args.len(), 2 | 3) => Ok((args.len() - 1, None)),
            b"AUTH" => Err(&b"-ERR wrong number of arguments for 'auth' command\r\n"[..]),
            b"HELLO" => parse_hello(&args),
            b"QUIT" => {
                client.write(b"+OK\r\n").await?;
                return Ok(None);
            }
            _ => Err(&b"-NOAUTH Authentication required.\r\n"[..]),
        };
        match attempt {
            Err(reply) => client.write(reply).await?,
            Ok((password, hello)) => {
                let result = authenticate(client, &args[password], hello, meta, ctx).await;
                args.iter_mut().for_each(|a| a.zeroize());
                return result.map(Some);
            }
        }
    }
}

/// `HELLO <2|3> [AUTH <user> <pass>] [SETNAME <name>]` → the password's index and the options,
/// or the reply that refuses it (the connection stays unauthenticated).
fn parse_hello(args: &[Vec<u8>]) -> Result<(usize, Option<Hello>), &'static [u8]> {
    let proto = match args.get(1).map(Vec::as_slice) {
        None => return Err(NOAUTH_HELLO),
        Some(b"2") => 2,
        Some(b"3") => 3,
        Some(_) => return Err(b"-NOPROTO unsupported protocol version\r\n"),
    };
    let (mut password, mut setname, mut i) = (None, None, 2);
    while i < args.len() {
        let opt = &args[i];
        if opt.eq_ignore_ascii_case(b"AUTH") && i + 2 < args.len() {
            password = Some(i + 2);
            i += 3;
        } else if opt.eq_ignore_ascii_case(b"SETNAME") && i + 1 < args.len() {
            setname = Some(args[i + 1].clone());
            i += 2;
        } else {
            return Err(b"-ERR Syntax error in HELLO option\r\n");
        }
    }
    let password = password.ok_or(NOAUTH_HELLO)?;
    Ok((password, Some(Hello { proto, setname })))
}

/// Resolves the credential in `password` into a session for a Redis destination.
async fn authenticate(
    client: &mut Client,
    password: &[u8],
    hello: Option<Hello>,
    meta: &ConnMeta,
    ctx: &AdapterCtx,
) -> Result<Login, AdapterError> {
    let text = Zeroizing::new(String::from_utf8_lossy(password).into_owned());
    let Some(credential) = find_local_key(&text) else {
        let code = ErrorCode::NotAllowed;
        client.close(Some(&error_reply("WRONGPASS", code, "the password is not a Seal credential"))).await;
        return Err(AdapterError::Denied(code));
    };
    let session = match ctx.resolver.resolve(credential, meta).await {
        Ok(session) => session,
        Err(code) => {
            client.close(Some(&error_reply("WRONGPASS", code, "the Seal credential was refused"))).await;
            return Err(AdapterError::Denied(code));
        }
    };
    if !matches!(session.policy().destination(), Destination::Redis { .. }) {
        let code = ErrorCode::PolicyDenied;
        client.close(Some(&error_reply("ERR", code, "the blob is not for a Redis destination"))).await;
        return Err(AdapterError::Denied(code));
    }
    let (action, content) = match &hello {
        None => ("AUTH", b"AUTH".to_vec()),
        Some(h) => ("HELLO", format!("HELLO {}", h.proto).into_bytes()),
    };
    match session.observe(&Observation { protocol: Protocol::Redis, action, content: &content }) {
        Verdict::Forward => {}
        Verdict::Refuse(code) | Verdict::End(code) => {
            complete(&*session, action, Outcome::Denied(code), 0, 0);
            let message = "the connection was refused by the tenant's integrity policy";
            client.close(Some(&error_reply("ERR", code, message))).await;
            return Err(AdapterError::Denied(code));
        }
    }
    Ok(Login { session, hello, action })
}

/// An authenticated upstream connection.
struct Upstream {
    reader: ReadHalf<UpstreamStream>,
    writer: WriteHalf<UpstreamStream>,
    buf: BytesMut,
    /// The upstream's reply to `HELLO`, for the client.
    hello_reply: Option<Vec<u8>>,
}

/// Why the upstream could not be used: telemetry kind, public code, fixed text.
struct Failure {
    kind: UpstreamErrorKind,
    code: ErrorCode,
    message: &'static str,
}

impl Failure {
    fn new(kind: UpstreamErrorKind, message: &'static str) -> Self {
        Self { kind, code: ErrorCode::Unavailable, message }
    }
}

async fn open_upstream(ctx: &AdapterCtx, login: &Login) -> Result<Upstream, Failure> {
    let policy = login.session.policy();
    let Destination::Redis { user, db, .. } = policy.destination() else {
        return Err(Failure::new(UpstreamErrorKind::Protocol, "the blob is not for a Redis destination"));
    };
    let stream = ctx.upstream.connect(policy.destination(), policy.pins()).await.map_err(|e| {
        // TLS, missing TLS and pin failures are the policy-denied ones.
        let code = e.code();
        if code == ErrorCode::PolicyDenied {
            Failure { kind: UpstreamErrorKind::Tls, code, message: "the upstream's certificate was refused" }
        } else {
            Failure { kind: UpstreamErrorKind::Connect, code, message: "the upstream could not be reached" }
        }
    })?;
    let (reader, writer) = tokio::io::split(stream);
    let mut upstream = Upstream { reader, writer, buf: BytesMut::new(), hello_reply: None };
    let handshake = handshake(&mut upstream, login, user.as_deref(), *db);
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Ok(result) => result?,
        Err(_) => return Err(Failure::new(UpstreamErrorKind::Timeout, "the upstream did not answer in time")),
    }
    Ok(upstream)
}

/// Authenticates as the destination's user with the secret and selects its db.
async fn handshake(up: &mut Upstream, login: &Login, user: Option<&str>, db: u8) -> Result<(), Failure> {
    const FAILED: &str = "the upstream handshake failed";
    let secret = login.session.secret();
    let mut out = Zeroizing::new(Vec::new());
    match (&login.hello, user) {
        (None, None) => encode_into(&mut out, &[&b"AUTH"[..], secret]),
        (None, Some(user)) => encode_into(&mut out, &[&b"AUTH"[..], user.as_bytes(), secret]),
        (Some(hello), user) => {
            let proto = hello.proto.to_string();
            let user = user.unwrap_or("default");
            let mut args: Vec<&[u8]> = vec![b"HELLO", proto.as_bytes(), b"AUTH", user.as_bytes(), secret];
            if let Some(name) = &hello.setname {
                args.extend([&b"SETNAME"[..], name]);
            }
            encode_into(&mut out, &args);
        }
    }
    if db != 0 {
        encode_into(&mut out, &[&b"SELECT"[..], db.to_string().as_bytes()]);
    }
    let sent = async {
        up.writer.write_all(&out).await?;
        up.writer.flush().await
    };
    sent.await.map_err(|_| Failure::new(UpstreamErrorKind::Closed, FAILED))?;
    drop(out);

    let mut scanner = ReplyScanner::default();
    let (reply, info) = read_reply(up, &mut scanner).await?;
    if info.is_error() {
        return Err(Failure::new(UpstreamErrorKind::AuthRejected, "the upstream refused the sealed credential"));
    }
    if login.hello.is_none() && reply != b"+OK\r\n" {
        return Err(Failure::new(UpstreamErrorKind::Protocol, FAILED));
    }
    if db != 0 {
        let (selected, _) = read_reply(up, &mut scanner).await?;
        if selected != b"+OK\r\n" {
            return Err(Failure::new(
                UpstreamErrorKind::Protocol,
                "the upstream refused to select the destination's db",
            ));
        }
    }
    if login.hello.is_some() {
        up.hello_reply = Some(reply);
    }
    Ok(())
}

/// One whole handshake reply.
async fn read_reply(up: &mut Upstream, scanner: &mut ReplyScanner) -> Result<(Vec<u8>, FrameInfo), Failure> {
    let protocol = || Failure::new(UpstreamErrorKind::Protocol, "the upstream handshake failed");
    let mut frame = Vec::new();
    loop {
        while !up.buf.is_empty() {
            let (n, done) = scanner.feed(&up.buf).map_err(|_| protocol())?;
            frame.extend_from_slice(&up.buf.split_to(n));
            if frame.len() > HANDSHAKE_REPLY_MAX {
                return Err(protocol());
            }
            if let Some(info) = done {
                return Ok((frame, info));
            }
        }
        match up.reader.read_buf(&mut up.buf).await {
            Ok(0) | Err(_) => return Err(Failure::new(UpstreamErrorKind::Closed, "the upstream handshake failed")),
            Ok(_) => {}
        }
    }
}

/// How the relay stopped.
enum Stop {
    /// The session ended (or a verdict ended it): cut everything.
    Cut(ErrorCode, &'static str),
    Down(DownEnd),
}

async fn relay(client: Client, upstream: Upstream, login: Login) -> Result<(), AdapterError> {
    let Login { session, hello, action } = login;
    let mut scrubber = Scrubber::new(vec![Zeroizing::new(session.secret().to_vec())]);
    let reply = match &upstream.hello_reply {
        Some(hello_reply) => {
            let mut out = scrubber.push(hello_reply);
            out.extend(scrubber.flush());
            out
        }
        None => b"+OK\r\n".to_vec(),
    };
    let Client { reader, writer, buf, commands } = client;
    let mut writer = BufWriter::new(writer);
    if writer.write_all(&reply).await.is_err() || writer.flush().await.is_err() {
        complete(&*session, action, Outcome::Aborted, 0, 0);
        return Ok(());
    }
    complete(&*session, action, Outcome::Allowed, 0, reply.len() as u64);

    let db = match session.policy().destination() {
        Destination::Redis { db, .. } => *db,
        _ => 0,
    };
    let (tx, rx) = mpsc::channel(MAX_PIPELINE);
    let up = Up {
        reader,
        buf,
        commands,
        upstream: BufWriter::new(upstream.writer),
        session: session.clone(),
        db,
        tx,
        multi: false,
        multi_refused: None,
    };
    let proto = hello.as_ref().map_or(2, |h| h.proto);
    let mut down = Down::new(upstream.reader, upstream.buf, writer, rx, session.clone(), scrubber, proto);

    let mut up_end = None;
    let stop = {
        let up = up.run();
        let down_run = down.run();
        let ended = session.ended();
        let grace = tokio::time::sleep(Duration::ZERO);
        tokio::pin!(up, down_run, ended, grace);
        loop {
            tokio::select! {
                code = &mut ended => break Stop::Cut(code, SESSION_ENDED),
                end = &mut up, if up_end.is_none() => match end {
                    UpEnd::End(code) => break Stop::Cut(code, INTEGRITY_ENDED),
                    UpEnd::Upstream => break Stop::Down(DownEnd::UpstreamClosed),
                    other => {
                        up_end = Some(other);
                        grace.as_mut().reset(tokio::time::Instant::now() + CLOSE_GRACE);
                    }
                },
                end = &mut down_run => break Stop::Down(end),
                () = &mut grace, if up_end.is_some() => break Stop::Down(DownEnd::ClientGone),
            }
        }
    };

    match stop {
        Stop::Cut(code, message) => {
            down.abort_all(Outcome::Aborted);
            down.close_with(Some(&error_reply("ERR", code, message))).await;
            Err(AdapterError::Denied(code))
        }
        Stop::Down(end @ (DownEnd::UpstreamClosed | DownEnd::UpstreamProtocol)) => {
            let kind =
                if end == DownEnd::UpstreamClosed { UpstreamErrorKind::Closed } else { UpstreamErrorKind::Protocol };
            let waiting = down.abort_all(Outcome::UpstreamError(kind));
            if waiting == 0 && kind == UpstreamErrorKind::Closed {
                // The upstream closed between commands (`QUIT`, its idle timeout).
                down.close_with(None).await;
                return Ok(());
            }
            let message = error_reply("ERR", ErrorCode::Unavailable, "the upstream connection failed");
            down.close_with(Some(&message)).await;
            Err(AdapterError::Upstream(kind))
        }
        Stop::Down(DownEnd::Done | DownEnd::ClientGone) => {
            down.abort_all(Outcome::Aborted);
            down.close_with(None).await;
            match up_end {
                Some(UpEnd::Client(reason)) => Err(AdapterError::Client(reason)),
                _ => Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<Vec<u8>> {
        line.split(' ').map(|a| a.as_bytes().to_vec()).collect()
    }

    #[test]
    fn hello_forms() {
        let (i, h) = parse_hello(&args("HELLO 3 AUTH u p")).unwrap();
        assert_eq!((i, h.as_ref().map(|h| h.proto)), (4, Some(3)));
        let (i, h) = parse_hello(&args("hello 2 setname app auth u p")).unwrap();
        assert_eq!(i, 6);
        assert_eq!(h.unwrap().setname.as_deref(), Some(&b"app"[..]));
        assert_eq!(parse_hello(&args("HELLO")).err(), Some(NOAUTH_HELLO));
        assert_eq!(parse_hello(&args("HELLO 3")).err(), Some(NOAUTH_HELLO));
        assert!(parse_hello(&args("HELLO 4 AUTH u p")).unwrap_err().starts_with(b"-NOPROTO"));
        assert!(parse_hello(&args("HELLO 3 AUTH u")).unwrap_err().starts_with(b"-ERR Syntax"));
        assert!(parse_hello(&args("HELLO 3 FOO")).unwrap_err().starts_with(b"-ERR Syntax"));
    }
}

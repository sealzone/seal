//! The relay after both handshakes: client messages framed, observed and forwarded; upstream
//! messages scrubbed and returned; one `Completion` per simple query or extended-protocol cycle.

use std::collections::VecDeque;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

use seal_adapter::scrub::Scrubber;
use seal_adapter::{AdapterError, Completion, Observation, Outcome, Session, UpstreamErrorKind, Verdict};
use seal_proto::policy::Protocol;
use seal_proto::telemetry::Sqlstate;
use seal_proto::ErrorCode;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use zeroize::Zeroizing;

use crate::wire::{self, Severity, WireError};
use crate::{refusal_text, sqlstate_for};

/// `Query` and `Parse` are read whole to be observed; longer ones close the connection.
pub const MAX_SQL_BODY: usize = 16 << 20;
/// Upstream messages up to this size are read whole; longer ones (big rows, `CopyData`)
/// stream through the scrubber.
const MAX_BUFFERED_BODY: usize = 64 << 10;
/// Streaming copies at most this much per step.
const CHUNK: usize = 16 << 10;
/// How much of a streamed `ErrorResponse` is kept to find its SQLSTATE.
const ERROR_HEAD: usize = 512;
/// Recorded for an `ErrorResponse` without a well-formed SQLSTATE (`XX000`, internal error).
const UNKNOWN_SQLSTATE: Sqlstate = match Sqlstate::new(*b"XX000") {
    Some(state) => state,
    None => unreachable!(),
};
/// Time allowed to write a closing `ErrorResponse` to a client that is not reading.
const END_GRACE: Duration = Duration::from_secs(1);

pub const QUERY: &str = "QUERY";
pub const PARSE: &str = "PARSE";
/// An extended-protocol cycle without a `Parse` (executing prepared statements).
pub const EXECUTE: &str = "EXECUTE";
pub const FUNCTION_CALL: &str = "FUNCTION_CALL";

/// The client connection's write side, buffered. Only one message is written at a time.
pub struct ClientOut<W> {
    w: BufWriter<W>,
    /// A message is partly written, so nothing else may be written to this connection.
    mid_message: bool,
}

impl<W: AsyncWrite + Unpin> ClientOut<W> {
    pub fn new(w: W) -> Self {
        Self { w: BufWriter::new(w), mid_message: false }
    }

    pub async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.w.write_all(bytes).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.w.flush().await
    }

    /// Writes a `FATAL` `ErrorResponse` with the adapter's own text, unless a message is cut
    /// mid-way, then closes the write side. Never waits longer than `END_GRACE`. Returns `err`.
    pub async fn refuse(&mut self, sqlstate: &[u8; 5], message: &str, err: AdapterError) -> AdapterError {
        let write = async {
            if !self.mid_message {
                self.w.write_all(&wire::error_response(Severity::Fatal, sqlstate, message)).await?;
            }
            self.w.flush().await?;
            self.w.shutdown().await
        };
        let _ = tokio::time::timeout(END_GRACE, write).await;
        err
    }
}

/// One simple query or extended-protocol cycle forwarded upstream and not yet answered by
/// its `ReadyForQuery`.
struct Cycle {
    action: &'static str,
    bytes_up: u64,
    bytes_down: u64,
    /// The cycle's last message (`Query` or `Sync`) has been forwarded.
    closed: bool,
    /// Refused part-way: reported with this code, whatever happens to the rest.
    denied: Option<ErrorCode>,
    /// The SQLSTATE of the first `ErrorResponse` the upstream answered it with.
    error: Option<Sqlstate>,
}

impl Cycle {
    fn new(action: &'static str, bytes_up: u64, closed: bool) -> Self {
        Self { action, bytes_up, bytes_down: 0, closed, denied: None, error: None }
    }

    /// How the cycle ended once answered: denied, else the upstream's error, else allowed.
    fn outcome(&self) -> Outcome {
        match (self.denied, self.error) {
            (Some(code), _) => Outcome::Denied(code),
            (None, Some(state)) => Outcome::UpstreamError(UpstreamErrorKind::Sqlstate(state)),
            (None, None) => Outcome::Allowed,
        }
    }
}

/// A request refused by the adapter itself, in band: its messages are read and dropped up to
/// the next `Sync`, which the adapter answers with `ReadyForQuery`.
struct Refused {
    action: &'static str,
    code: ErrorCode,
    bytes_up: u64,
    bytes_down: u64,
}

#[derive(Default)]
struct State {
    /// Forwarded cycles in order; upstream responses belong to the front one.
    cycles: VecDeque<Cycle>,
    /// The back cycle is an extended-protocol cycle still open (no `Sync` yet).
    open: bool,
    refused: Option<Refused>,
    /// The upstream's transaction status as of the last `ReadyForQuery`.
    status: u8,
    /// A client message is partly written upstream.
    upstream_mid_message: bool,
}

/// Why the relay stopped.
enum Stop {
    /// The client sent `Terminate`, closed, or stopped being writable.
    Client,
    /// The upstream closed or failed.
    Upstream(UpstreamErrorKind),
    /// The adapter refused and closed (its `ErrorResponse` is already written).
    Refused(AdapterError),
    /// `Session::ended`.
    Ended(ErrorCode),
}

pub struct Relay<'a, W> {
    session: &'a dyn Session,
    out: tokio::sync::Mutex<ClientOut<W>>,
    state: Mutex<State>,
    /// The `BackendKeyData` the client was given, in place of any the upstream sends.
    client_key: (i32, i32),
}

impl<'a, W: AsyncWrite + Unpin> Relay<'a, W> {
    pub fn new(session: &'a dyn Session, out: ClientOut<W>, status: u8, client_key: (i32, i32)) -> Self {
        let state = Mutex::new(State { status, ..State::default() });
        Self { session, out: tokio::sync::Mutex::new(out), state, client_key }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn complete(&self, action: &str, outcome: Outcome, bytes_up: u64, bytes_down: u64) {
        self.session.complete(Completion {
            protocol: Protocol::Postgres,
            action: action.to_string(),
            outcome,
            bytes_up,
            bytes_down,
        });
    }

    /// Relays until either side closes or the session ends; then reports every cycle still in
    /// flight (`Aborted` when the client went away or the session ended, `UpstreamError` when
    /// the upstream did) and closes both sides.
    pub async fn run<CR, UR, UW>(
        self,
        client: &mut BufReader<CR>,
        upstream_r: &mut BufReader<UR>,
        upstream_w: &mut BufWriter<UW>,
    ) -> Result<(), AdapterError>
    where
        CR: AsyncRead + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let stop = {
            let up = self.client_to_upstream(client, upstream_w);
            let down = self.upstream_to_client(upstream_r);
            tokio::pin!(up, down);
            tokio::select! {
                stop = &mut up => stop,
                stop = &mut down => stop,
                code = self.session.ended() => Stop::Ended(code),
            }
        };

        let in_flight = match &stop {
            Stop::Upstream(kind) => Outcome::UpstreamError(*kind),
            Stop::Client | Stop::Refused(_) | Stop::Ended(_) => Outcome::Aborted,
        };
        let (cycles, refused, upstream_mid_message) = {
            let mut st = self.state();
            (std::mem::take(&mut st.cycles), st.refused.take(), st.upstream_mid_message)
        };
        for c in cycles {
            // An upstream that failed after answering with an error is reported with that error.
            let outcome = match (&stop, c.denied, c.error) {
                (_, Some(code), _) => Outcome::Denied(code),
                (Stop::Upstream(_), None, Some(_)) => c.outcome(),
                _ => in_flight.clone(),
            };
            self.complete(c.action, outcome, c.bytes_up, c.bytes_down);
        }
        if let Some(r) = refused {
            self.complete(r.action, Outcome::Denied(r.code), r.bytes_up, r.bytes_down);
        }

        let close_upstream = async {
            if !upstream_mid_message {
                let _ = upstream_w.write_all(&[b'X', 0, 0, 0, 4]).await;
            }
            let _ = upstream_w.flush().await;
            let _ = upstream_w.shutdown().await;
        };
        let _ = tokio::time::timeout(END_GRACE, close_upstream).await;

        let mut out = self.out.into_inner();
        match stop {
            Stop::Client => Ok(()),
            Stop::Refused(err) => Err(err),
            Stop::Upstream(UpstreamErrorKind::Closed) => {
                let closed = AdapterError::Upstream(UpstreamErrorKind::Closed);
                out.refuse(b"08006", "seal: the upstream closed the connection", closed).await;
                Ok(())
            }
            Stop::Upstream(kind) => {
                Err(out.refuse(b"08006", "seal: the upstream connection failed", AdapterError::Upstream(kind)).await)
            }
            Stop::Ended(code) => {
                let text = refusal_text("the session has ended", code);
                Err(out.refuse(b"57P01", &text, AdapterError::Denied(code)).await)
            }
        }
    }

    /// Writes the adapter's own messages to the client, between relayed ones.
    async fn to_client(&self, bytes: &[u8]) -> Result<(), Stop> {
        let mut out = self.out.lock().await;
        out.send(bytes).await.map_err(|_| Stop::Client)?;
        out.flush().await.map_err(|_| Stop::Client)
    }

    /// Closes with a `FATAL` `ErrorResponse`.
    async fn fatal(&self, sqlstate: &[u8; 5], message: &str, err: AdapterError) -> Stop {
        let mut out = match tokio::time::timeout(END_GRACE, self.out.lock()).await {
            Ok(out) => out,
            Err(_) => return Stop::Refused(err),
        };
        Stop::Refused(out.refuse(sqlstate, message, err).await)
    }

    /// A client protocol error: `FATAL` with `seal: <text>`, then `AdapterError::Client(text)`.
    async fn client_error(&self, sqlstate: &[u8; 5], text: &'static str) -> Stop {
        self.fatal(sqlstate, &format!("seal: {text}"), AdapterError::Client(text)).await
    }

    /// Adds a forwarded message to the open extended-protocol cycle, opening one if needed.
    fn extended(&self, size: u64, action: Option<&'static str>) {
        let mut st = self.state();
        if !st.open {
            st.cycles.push_back(Cycle::new(EXECUTE, 0, false));
            st.open = true;
        }
        let c = st.cycles.back_mut().expect("an open cycle is queued");
        c.bytes_up += size;
        if let Some(action) = action {
            c.action = action;
        }
    }

    async fn client_to_upstream<CR, UW>(&self, r: &mut BufReader<CR>, w: &mut BufWriter<UW>) -> Stop
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        loop {
            if !wire::holds_message(r.buffer()) && w.flush().await.is_err() {
                return Stop::Upstream(UpstreamErrorKind::Closed);
            }
            let (ty, len) = match wire::read_header(r).await {
                Ok(Some(header)) => header,
                Ok(None) | Err(WireError::Io(_)) => return Stop::Client,
                Err(_) => return self.client_error(b"08P01", "invalid message").await,
            };
            let size = len as u64 + 5;

            let discarding = self.state().refused.is_some();
            if discarding {
                if let Err(stop) = copy_body(r, None::<&mut BufWriter<UW>>, len).await {
                    return stop;
                }
                match ty {
                    b'X' => return Stop::Client,
                    b'S' => {
                        let refused = self.state().refused.take();
                        if let Some(mut refused) = refused {
                            let ready = wire::ready_for_query(b'I');
                            refused.bytes_up += size;
                            refused.bytes_down += ready.len() as u64;
                            let (up, down) = (refused.bytes_up, refused.bytes_down);
                            self.complete(refused.action, Outcome::Denied(refused.code), up, down);
                            if let Err(stop) = self.to_client(&ready).await {
                                return stop;
                            }
                        }
                    }
                    _ => {
                        if let Some(refused) = self.state().refused.as_mut() {
                            refused.bytes_up += size;
                        }
                    }
                }
                continue;
            }

            match ty {
                b'Q' | b'P' => {
                    let body = match wire::read_body(r, len, MAX_SQL_BODY).await {
                        Ok(body) => body,
                        Err(WireError::Io(_)) => return Stop::Client,
                        Err(_) => return self.client_error(b"54000", "statement too long").await,
                    };
                    let (action, sql) =
                        if ty == b'Q' { (QUERY, wire::query_text(&body)) } else { (PARSE, wire::parse_text(&body)) };
                    let Ok(sql) = sql else {
                        return self.client_error(b"08P01", "invalid message").await;
                    };
                    let verdict =
                        self.session.observe(&Observation { protocol: Protocol::Postgres, action, content: sql });
                    let refusal = match verdict {
                        Verdict::Forward => None,
                        Verdict::Refuse(code) => Some((code, false)),
                        Verdict::End(code) => Some((code, true)),
                    };
                    if let Some((code, end)) = refusal {
                        let text = if end {
                            "the session was ended by the tenant's integrity policy"
                        } else {
                            "the statement was refused by the tenant's integrity policy"
                        };
                        match self.refuse(code, action, size, ty == b'P', end, text).await {
                            Ok(()) => continue,
                            Err(stop) => return stop,
                        }
                    }
                    if ty == b'Q' {
                        // A query inside an unsynced extended cycle ends it: one `ReadyForQuery` answers both.
                        let mut st = self.state();
                        let open = std::mem::replace(&mut st.open, false);
                        match st.cycles.back_mut() {
                            Some(c) if open => {
                                c.action = QUERY;
                                c.bytes_up += size;
                                c.closed = true;
                            }
                            _ => st.cycles.push_back(Cycle::new(action, size, true)),
                        }
                    } else {
                        self.extended(size, Some(PARSE));
                    }
                    if let Err(stop) = self.forward(w, ty, &body).await {
                        return stop;
                    }
                }
                b'B' | b'D' | b'E' | b'C' | b'H' | b'S' => {
                    self.extended(size, None);
                    if ty == b'S' {
                        let mut st = self.state();
                        st.open = false;
                        if let Some(c) = st.cycles.back_mut() {
                            c.closed = true;
                        }
                    }
                    if let Err(stop) = self.stream(r, w, ty, len).await {
                        return stop;
                    }
                }
                b'd' | b'c' | b'f' => {
                    if let Some(c) = self.state().cycles.back_mut() {
                        c.bytes_up += size;
                    }
                    if let Err(stop) = self.stream(r, w, ty, len).await {
                        return stop;
                    }
                }
                b'F' => {
                    // FunctionCall runs a function by OID, past observation: refused.
                    if let Err(stop) = copy_body(r, None::<&mut BufWriter<UW>>, len).await {
                        return stop;
                    }
                    let text = "function calls are not supported";
                    match self.refuse(ErrorCode::PolicyDenied, FUNCTION_CALL, size, false, false, text).await {
                        Ok(()) => continue,
                        Err(stop) => return stop,
                    }
                }
                b'X' => return Stop::Client,
                _ => return self.client_error(b"08P01", "unexpected message").await,
            }
        }
    }

    /// Refuses one request. In band (an `ERROR`, the connection kept) only when nothing is in
    /// flight, the upstream is idle outside a transaction and nothing of the request's cycle
    /// was forwarded, so the client's view and the upstream's agree; otherwise, and for
    /// `end`, the connection closes with `FATAL`, which also rolls back the upstream's
    /// transaction.
    async fn refuse(
        &self,
        code: ErrorCode,
        action: &'static str,
        size: u64,
        extended: bool,
        end: bool,
        text: &str,
    ) -> Result<(), Stop> {
        let message = refusal_text(text, code);
        let in_band = !end && {
            let st = self.state();
            st.cycles.is_empty() && !st.open && st.status == b'I'
        };
        if in_band {
            let error = wire::error_response(Severity::Error, &sqlstate_for(code), &message);
            if extended {
                self.state().refused = Some(Refused { action, code, bytes_up: size, bytes_down: error.len() as u64 });
                return self.to_client(&error).await;
            }
            let ready = wire::ready_for_query(b'I');
            self.complete(action, Outcome::Denied(code), size, (error.len() + ready.len()) as u64);
            return self.to_client(&[error, ready].concat()).await;
        }
        let part_of_open_cycle = {
            let mut st = self.state();
            let open = st.open;
            match st.cycles.back_mut() {
                Some(c) if open => {
                    c.bytes_up += size;
                    c.denied = Some(code);
                    true
                }
                _ => false,
            }
        };
        if !part_of_open_cycle {
            self.complete(action, Outcome::Denied(code), size, 0);
        }
        let sqlstate = if end { *b"57P01" } else { sqlstate_for(code) };
        Err(self.fatal(&sqlstate, &message, AdapterError::Denied(code)).await)
    }

    /// Forwards a message read whole.
    async fn forward<UW: AsyncWrite + Unpin>(&self, w: &mut BufWriter<UW>, ty: u8, body: &[u8]) -> Result<(), Stop> {
        self.state().upstream_mid_message = true;
        w.write_all(&header(ty, body.len())).await.map_err(|_| Stop::Upstream(UpstreamErrorKind::Closed))?;
        w.write_all(body).await.map_err(|_| Stop::Upstream(UpstreamErrorKind::Closed))?;
        self.state().upstream_mid_message = false;
        Ok(())
    }

    /// Forwards a message as it arrives.
    async fn stream<CR, UW>(&self, r: &mut BufReader<CR>, w: &mut BufWriter<UW>, ty: u8, len: usize) -> Result<(), Stop>
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        self.state().upstream_mid_message = true;
        w.write_all(&header(ty, len)).await.map_err(|_| Stop::Upstream(UpstreamErrorKind::Closed))?;
        copy_body(r, Some(w), len).await?;
        self.state().upstream_mid_message = false;
        Ok(())
    }

    async fn upstream_to_client<UR: AsyncRead + Unpin>(&self, r: &mut BufReader<UR>) -> Stop {
        let mut scrubber = Scrubber::new(vec![Zeroizing::new(self.session.secret().to_vec())]);
        loop {
            let (ty, len) = match wire::read_header(r).await {
                Ok(Some(header)) => header,
                Ok(None) | Err(WireError::Io(_)) => return Stop::Upstream(UpstreamErrorKind::Closed),
                Err(_) => return Stop::Upstream(UpstreamErrorKind::Protocol),
            };
            // Authentication, protocol negotiation and replication streams have no place here.
            if matches!(ty, b'R' | b'v' | b'W') {
                return Stop::Upstream(UpstreamErrorKind::Protocol);
            }
            let size = len as u64 + 5;
            if len <= MAX_BUFFERED_BODY {
                let mut body = match wire::read_body(r, len, MAX_BUFFERED_BODY).await {
                    Ok(body) => body,
                    Err(WireError::Io(_)) => return Stop::Upstream(UpstreamErrorKind::Closed),
                    Err(_) => return Stop::Upstream(UpstreamErrorKind::Protocol),
                };
                let ready = match ty {
                    b'Z' => match wire::ready_status(&body) {
                        Ok(status) => Some(status),
                        Err(_) => return Stop::Upstream(UpstreamErrorKind::Protocol),
                    },
                    b'K' => match wire::backend_key(&body) {
                        Ok(_) => {
                            body = wire::backend_key_data(self.client_key.0, self.client_key.1)[5..].to_vec();
                            None
                        }
                        Err(_) => return Stop::Upstream(UpstreamErrorKind::Protocol),
                    },
                    b'E' => {
                        self.errored(&body);
                        None
                    }
                    _ => None,
                };
                let mut scrubbed = scrubber.push(&body);
                scrubbed.extend(scrubber.flush());
                {
                    let mut out = self.out.lock().await;
                    if out.send(&header(ty, len)).await.is_err() || out.send(&scrubbed).await.is_err() {
                        return Stop::Client;
                    }
                    if !wire::holds_message(r.buffer()) && out.flush().await.is_err() {
                        return Stop::Client;
                    }
                }
                self.received(size, ready);
            } else {
                let mut out = self.out.lock().await;
                out.mid_message = true;
                if out.send(&header(ty, len)).await.is_err() {
                    return Stop::Client;
                }
                let mut left = len;
                // An `ErrorResponse` this long starts with its severity and SQLSTATE fields.
                let mut head = Vec::new();
                while left > 0 {
                    let chunk = match r.fill_buf().await {
                        Ok([]) | Err(_) => return Stop::Upstream(UpstreamErrorKind::Closed),
                        Ok(chunk) => chunk,
                    };
                    let n = chunk.len().min(left).min(CHUNK);
                    if ty == b'E' && head.len() < ERROR_HEAD {
                        head.extend_from_slice(&chunk[..n.min(ERROR_HEAD - head.len())]);
                    }
                    let scrubbed = scrubber.push(&chunk[..n]);
                    r.consume(n);
                    left -= n;
                    if out.send(&scrubbed).await.is_err() || out.flush().await.is_err() {
                        return Stop::Client;
                    }
                }
                if out.send(&scrubber.flush()).await.is_err() || out.flush().await.is_err() {
                    return Stop::Client;
                }
                out.mid_message = false;
                drop(out);
                if ty == b'E' {
                    self.errored(&head);
                }
                self.received(size, None);
            }
        }
    }

    /// Records an upstream `ErrorResponse` (whole, or the start of one) on the cycle it answers,
    /// unless that cycle already has one.
    fn errored(&self, body: &[u8]) {
        let state = wire::sqlstate(body).and_then(Sqlstate::new).unwrap_or(UNKNOWN_SQLSTATE);
        if let Some(c) = self.state().cycles.front_mut() {
            c.error.get_or_insert(state);
        }
    }

    /// Accounts an upstream message to the cycle it answers; a `ReadyForQuery` ends that cycle.
    fn received(&self, size: u64, ready: Option<u8>) {
        let done = {
            let mut st = self.state();
            if let Some(c) = st.cycles.front_mut() {
                c.bytes_down += size;
            }
            match ready {
                Some(status) => {
                    st.status = status;
                    match st.cycles.front() {
                        Some(c) if c.closed => st.cycles.pop_front(),
                        _ => None,
                    }
                }
                None => None,
            }
        };
        if let Some(c) = done {
            self.complete(c.action, c.outcome(), c.bytes_up, c.bytes_down);
        }
    }
}

/// Copies (into `w`) or discards (`None`) the next `len` body bytes.
async fn copy_body<CR, UW>(r: &mut BufReader<CR>, mut w: Option<&mut BufWriter<UW>>, len: usize) -> Result<(), Stop>
where
    CR: AsyncRead + Unpin,
    UW: AsyncWrite + Unpin,
{
    let mut left = len;
    while left > 0 {
        let chunk = match r.fill_buf().await {
            Ok([]) | Err(_) => return Err(Stop::Client),
            Ok(chunk) => chunk,
        };
        let n = chunk.len().min(left);
        if let Some(w) = w.as_mut() {
            w.write_all(&chunk[..n]).await.map_err(|_| Stop::Upstream(UpstreamErrorKind::Closed))?;
        }
        r.consume(n);
        left -= n;
    }
    Ok(())
}

fn header(ty: u8, body_len: usize) -> [u8; 5] {
    let len = (body_len as u32 + 4).to_be_bytes();
    [ty, len[0], len[1], len[2], len[3]]
}

//! The authenticated relay: `Up` takes client commands, checks and forwards them; `Down`
//! relays upstream replies in order, interleaved with the adapter's own refusals.

use std::collections::VecDeque;
use std::sync::Arc;

use bytes::BytesMut;
use seal_adapter::scrub::Scrubber;
use seal_adapter::{Completion, Observation, Outcome, Session, UpstreamErrorKind, Verdict};
use seal_proto::policy::Protocol;
use seal_proto::ErrorCode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

use crate::policy;
use crate::resp::{encode_command, CommandReader, FrameError, FrameInfo, ReplyScanner};
use crate::{error_reply, upper};

/// A reply is held whole up to this size, so it can be classified (pub/sub frame or reply)
/// before any of it is relayed; a longer one streams.
const INSPECT_MAX: usize = 64 << 10;
/// Commands forwarded and refusals queued but not yet answered. A client that pipelines more
/// without reading replies is no longer read until it does.
pub const MAX_PIPELINE: usize = 65_536;

/// One entry in reply order.
pub enum Pending {
    /// A forwarded command waiting for its reply.
    Command(Inflight),
    /// A reply the adapter wrote itself.
    Local(Vec<u8>),
    /// The reply to a command the adapter sent on its own (`DISCARD`), not relayed.
    Silent,
}

pub struct Inflight {
    pub action: String,
    pub expect: Expect,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

pub enum Expect {
    One,
    /// `HELLO`: one reply; a successful one switches the protocol to this version.
    Hello(Option<u8>),
    /// `(P|S)(UN)SUBSCRIBE`: one confirmation of `kind` per channel; `None` (no channel
    /// given to an unsubscribe) is one per current subscription of that kind, at least one,
    /// counted when the first confirmation arrives.
    PubSub {
        kind: &'static [u8],
        left: Option<u64>,
    },
}

const PUBSUB: [&[u8]; 6] =
    [b"subscribe", b"unsubscribe", b"psubscribe", b"punsubscribe", b"ssubscribe", b"sunsubscribe"];
const MESSAGES: [&[u8]; 3] = [b"message", b"pmessage", b"smessage"];

fn expect(args: &[Vec<u8>]) -> Expect {
    let name = upper(&args[0]);
    let channels = args.len() as u64 - 1;
    let kind = PUBSUB.into_iter().find(|k| k.eq_ignore_ascii_case(&name));
    match kind {
        Some(kind) if channels > 0 => Expect::PubSub { kind, left: Some(channels) },
        // Without channels, an unsubscribe answers once per subscription; a subscribe fails.
        Some(kind) if kind.windows(5).any(|w| w == b"unsub") => Expect::PubSub { kind, left: None },
        Some(_) => Expect::One,
        None if name == b"HELLO" => Expect::Hello(match args.get(1).map(Vec::as_slice) {
            Some(b"2") => Some(2),
            Some(b"3") => Some(3),
            _ => None,
        }),
        None => Expect::One,
    }
}

pub fn complete(session: &dyn Session, action: &str, outcome: Outcome, bytes_up: u64, bytes_down: u64) {
    session.complete(Completion {
        protocol: Protocol::Redis,
        action: action.to_string(),
        outcome,
        bytes_up,
        bytes_down,
    });
}

/// How `Up` stopped.
pub enum UpEnd {
    /// The client closed its side.
    Eof,
    /// The client sent a malformed command; the protocol error is queued for it.
    Client(&'static str),
    /// `Verdict::End`.
    End(ErrorCode),
    /// Writing to the upstream failed.
    Upstream,
}

pub struct Up<R, W> {
    pub reader: R,
    pub buf: BytesMut,
    pub commands: CommandReader,
    pub upstream: BufWriter<W>,
    pub session: Arc<dyn Session>,
    pub db: u8,
    pub tx: mpsc::Sender<Pending>,
    /// Inside `MULTI`, and the code of a command refused there, which aborts the `EXEC`.
    pub multi: bool,
    pub multi_refused: Option<ErrorCode>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Up<R, W> {
    pub async fn run(mut self) -> UpEnd {
        loop {
            let args = match self.commands.next(&mut self.buf) {
                Ok(Some(args)) => args,
                Ok(None) => {
                    if self.upstream.flush().await.is_err() {
                        return UpEnd::Upstream;
                    }
                    match self.reader.read_buf(&mut self.buf).await {
                        Ok(0) | Err(_) => return UpEnd::Eof,
                        Ok(_) => continue,
                    }
                }
                Err(FrameError(reason)) => {
                    self.send(Pending::Local(format!("-ERR Protocol error: {reason}\r\n").into_bytes())).await;
                    return UpEnd::Client(reason);
                }
            };
            if let Some(end) = self.command(args).await {
                return end;
            }
        }
    }

    async fn command(&mut self, args: Vec<Vec<u8>>) -> Option<UpEnd> {
        let name = upper(&args[0]);
        let action = policy::action(&name);
        let session = self.session.clone();
        if let Some(message) = policy::refusal(&args, self.db) {
            return self.refuse(&action, "NOPERM", ErrorCode::PolicyDenied, message).await;
        }
        if name == b"EXEC" && self.multi {
            if let Some(code) = self.multi_refused {
                // Redis aborts a transaction with a command refused while queuing; so does the
                // adapter, discarding what the upstream queued.
                self.multi = false;
                self.multi_refused = None;
                complete(&*session, &action, Outcome::Denied(code), 0, 0);
                self.send(Pending::Silent).await;
                if self.upstream.write_all(&encode_command(&["DISCARD"])).await.is_err() {
                    return Some(UpEnd::Upstream);
                }
                let reply = b"-EXECABORT Transaction discarded because of previous errors.\r\n".to_vec();
                self.send(Pending::Local(reply)).await;
                return None;
            }
        }
        let content = policy::content(&args);
        match session.observe(&Observation { protocol: Protocol::Redis, action: &action, content: &content }) {
            Verdict::Forward => {}
            Verdict::Refuse(code) => {
                let message = "the command was refused by the tenant's integrity policy";
                return self.refuse(&action, "ERR", code, message).await;
            }
            Verdict::End(code) => {
                complete(&*session, &action, Outcome::Denied(code), 0, 0);
                return Some(UpEnd::End(code));
            }
        }
        match name.as_slice() {
            b"MULTI" => self.multi = true,
            b"EXEC" | b"DISCARD" => {
                self.multi = false;
                self.multi_refused = None;
            }
            _ => {}
        }
        let encoded = encode_command(&args);
        let expect = expect(&args);
        self.send(Pending::Command(Inflight { action, expect, bytes_up: encoded.len() as u64, bytes_down: 0 })).await;
        if self.upstream.write_all(&encoded).await.is_err() {
            return Some(UpEnd::Upstream);
        }
        None
    }

    async fn refuse(&mut self, action: &str, prefix: &str, code: ErrorCode, message: &str) -> Option<UpEnd> {
        complete(&*self.session, action, Outcome::Denied(code), 0, 0);
        if self.multi {
            self.multi_refused.get_or_insert(code);
        }
        self.send(Pending::Local(error_reply(prefix, code, message))).await;
        None
    }

    /// Queues `p`; when the queue is full, flushes what is buffered for the upstream first, so
    /// the replies that drain the queue can come.
    async fn send(&mut self, p: Pending) {
        match self.tx.try_send(p) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
            Err(mpsc::error::TrySendError::Full(p)) => {
                let _ = self.upstream.flush().await;
                let _ = self.tx.send(p).await;
            }
        }
    }
}

/// How `Down` stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownEnd {
    /// `Up` stopped and every queued reply was relayed.
    Done,
    UpstreamClosed,
    UpstreamProtocol,
    ClientGone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Reply,
    /// A pub/sub confirmation answering the head command.
    Confirmation,
    /// A push or a pub/sub message: relayed, answers nothing.
    OutOfBand,
    Silent,
}

/// Subscription counts, from the confirmations the upstream sent.
#[derive(Debug, Default)]
struct Subscriptions {
    channels: i64,
    patterns: i64,
    shards: i64,
    /// The count in the last channel or pattern confirmation (channels plus patterns).
    total: i64,
}

impl Subscriptions {
    fn any(&self) -> bool {
        self.channels + self.patterns + self.shards > 0
    }
    fn update(&mut self, tag: &[u8], n: i64) {
        match tag {
            b"subscribe" | b"unsubscribe" => {
                self.channels = (self.channels + n - self.total).max(0);
                self.total = n;
            }
            b"psubscribe" | b"punsubscribe" => {
                self.patterns = (self.patterns + n - self.total).max(0);
                self.total = n;
            }
            b"ssubscribe" | b"sunsubscribe" => self.shards = n.max(0),
            _ => {}
        }
    }
    fn of(&self, kind: &[u8]) -> u64 {
        let n = match kind {
            b"unsubscribe" => self.channels,
            b"punsubscribe" => self.patterns,
            _ => self.shards,
        };
        n.max(1) as u64
    }
}

pub struct Down<R, W> {
    pub upstream: R,
    pub buf: BytesMut,
    pub client: BufWriter<W>,
    pub rx: mpsc::Receiver<Pending>,
    pub session: Arc<dyn Session>,
    pub scrubber: Scrubber,
    pub proto: u8,
    rx_closed: bool,
    scanner: ReplyScanner,
    /// The entry the next reply answers (never `Local`: those are written as they come up).
    head: Option<Pending>,
    /// The current reply's bytes, while it is held for classification.
    frame: Vec<u8>,
    /// Set once the current reply streams.
    streaming: Option<Target>,
    /// A reply, relayed or local, is partly written to the client.
    writing: bool,
    subs: Subscriptions,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Down<R, W> {
    pub fn new(
        upstream: R,
        buf: BytesMut,
        client: BufWriter<W>,
        rx: mpsc::Receiver<Pending>,
        session: Arc<dyn Session>,
        scrubber: Scrubber,
        proto: u8,
    ) -> Self {
        Self {
            upstream,
            buf,
            client,
            rx,
            session,
            scrubber,
            proto,
            rx_closed: false,
            scanner: ReplyScanner::default(),
            head: None,
            frame: Vec::new(),
            streaming: None,
            writing: false,
            subs: Subscriptions::default(),
        }
    }

    /// Part of a reply has reached the client, so an error now would corrupt it.
    pub fn mid_reply(&self) -> bool {
        self.writing
    }

    pub async fn run(&mut self) -> DownEnd {
        loop {
            if let Err(end) = self.process().await {
                return end;
            }
            if self.client.flush().await.is_err() {
                return DownEnd::ClientGone;
            }
            if self.rx_closed && self.head.is_none() {
                return DownEnd::Done;
            }
            let want_next = self.head.is_none() && !self.rx_closed;
            tokio::select! {
                item = self.rx.recv(), if want_next => match item {
                    Some(p) => self.head = Some(p),
                    None => self.rx_closed = true,
                },
                read = self.upstream.read_buf(&mut self.buf) => match read {
                    Ok(0) | Err(_) => return DownEnd::UpstreamClosed,
                    Ok(_) => {}
                },
            }
        }
    }

    /// Completes every command still waiting with `outcome`; returns how many there were.
    pub fn abort_all(&mut self, outcome: Outcome) -> usize {
        let mut n = 0;
        let mut queued: VecDeque<Pending> = self.head.take().into_iter().collect();
        self.rx.close();
        while let Ok(p) = self.rx.try_recv() {
            queued.push_back(p);
        }
        for p in queued {
            if let Pending::Command(c) = p {
                complete(&*self.session, &c.action, outcome.clone(), c.bytes_up, c.bytes_down);
                n += 1;
            }
        }
        n
    }

    /// Writes `bytes` as the adapter's last words, unless a reply is half relayed; then closes.
    pub async fn close_with(&mut self, bytes: Option<&[u8]>) {
        if let Some(bytes) = bytes.filter(|_| !self.mid_reply()) {
            let _ = self.client.write_all(bytes).await;
        }
        let _ = self.client.flush().await;
        let _ = self.client.shutdown().await;
    }

    /// Writes queued local replies until the head is a command (or nothing is queued).
    async fn next_head(&mut self) -> std::io::Result<()> {
        loop {
            match self.head.take() {
                Some(Pending::Local(bytes)) => {
                    self.writing = true;
                    self.client.write_all(&bytes).await?;
                    self.writing = false;
                }
                Some(other) => {
                    self.head = Some(other);
                    return Ok(());
                }
                None => match self.rx.try_recv() {
                    Ok(p) => self.head = Some(p),
                    Err(mpsc::error::TryRecvError::Empty) => return Ok(()),
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.rx_closed = true;
                        return Ok(());
                    }
                },
            }
        }
    }

    /// Relays everything buffered from the upstream.
    async fn process(&mut self) -> Result<(), DownEnd> {
        loop {
            self.next_head().await.map_err(|_| DownEnd::ClientGone)?;
            if self.buf.is_empty() {
                return Ok(());
            }
            let (n, done) = self.scanner.feed(&self.buf).map_err(|_| DownEnd::UpstreamProtocol)?;
            let chunk = self.buf.split_to(n);
            match self.streaming {
                Some(target) => self.emit(target, &chunk).await?,
                None => {
                    self.frame.extend_from_slice(&chunk);
                    if done.is_none() && self.frame.len() > INSPECT_MAX {
                        let info = self.scanner.current().clone();
                        let target = self.classify(&info)?;
                        if target == Target::Silent {
                            return Err(DownEnd::UpstreamProtocol);
                        }
                        self.streaming = Some(target);
                        let frame = std::mem::take(&mut self.frame);
                        self.emit(target, &frame).await?;
                    }
                }
            }
            if let Some(info) = done {
                let target = match self.streaming.take() {
                    Some(target) => target,
                    None => {
                        let target = self.classify(&info)?;
                        let frame = std::mem::take(&mut self.frame);
                        self.emit(target, &frame).await?;
                        target
                    }
                };
                if target != Target::Silent {
                    let tail = self.scrubber.flush();
                    self.client.write_all(&tail).await.map_err(|_| DownEnd::ClientGone)?;
                    self.writing = false;
                }
                self.answered(target, &info);
            }
        }
    }

    async fn emit(&mut self, target: Target, bytes: &[u8]) -> Result<(), DownEnd> {
        if target == Target::Silent {
            return Ok(());
        }
        if matches!(target, Target::Reply | Target::Confirmation) {
            if let Some(Pending::Command(c)) = &mut self.head {
                c.bytes_down += bytes.len() as u64;
            }
        }
        let out = self.scrubber.push(bytes);
        self.writing = true;
        self.client.write_all(&out).await.map_err(|_| DownEnd::ClientGone)
    }

    /// What the reply described by `info` is. Pub/sub frames are told apart by their first
    /// element: a RESP3 push is never a reply unless it confirms the head's (un)subscribe;
    /// in RESP2, an array tagged like a pub/sub frame is one while anything is subscribed.
    fn classify(&mut self, info: &FrameInfo) -> Result<Target, DownEnd> {
        let tag = info.tag.as_deref();
        let framed = matches!(info.kind, b'*' | b'>');
        if let Some(Pending::Command(c)) = &mut self.head {
            if let Expect::PubSub { kind, left } = &mut c.expect {
                if framed && tag == Some(*kind) {
                    if left.is_none() {
                        *left = Some(self.subs.of(kind));
                    }
                    return Ok(Target::Confirmation);
                }
            }
        }
        if info.kind == b'>' {
            return Ok(Target::OutOfBand);
        }
        let pubsub_tag = tag.is_some_and(|t| PUBSUB.contains(&t) || MESSAGES.contains(&t));
        if self.proto == 2 && info.kind == b'*' && self.subs.any() && pubsub_tag {
            return Ok(Target::OutOfBand);
        }
        match &self.head {
            Some(Pending::Command(_)) => Ok(Target::Reply),
            Some(Pending::Silent) => Ok(Target::Silent),
            _ => Err(DownEnd::UpstreamProtocol),
        }
    }

    /// The reply ended: update subscriptions, complete the head when it is fully answered.
    fn answered(&mut self, target: Target, info: &FrameInfo) {
        if matches!(target, Target::Confirmation | Target::OutOfBand) {
            if let (Some(tag), Some(n)) = (info.tag.as_deref(), info.third) {
                self.subs.update(tag, n);
            }
        }
        let done = match (&mut self.head, target) {
            (Some(Pending::Silent), Target::Silent) => true,
            (Some(Pending::Command(c)), Target::Confirmation) => match &mut c.expect {
                Expect::PubSub { left: Some(left), .. } => {
                    *left = left.saturating_sub(1);
                    *left == 0
                }
                _ => true,
            },
            (Some(Pending::Command(c)), Target::Reply) => {
                if let Expect::Hello(Some(proto)) = c.expect {
                    if !info.is_error() {
                        self.proto = proto;
                    }
                }
                true
            }
            _ => false,
        };
        if done {
            if let Some(Pending::Command(c)) = self.head.take() {
                let outcome = if info.is_error() && info.tag.as_deref().is_some_and(|t| t.starts_with(b"NOPERM")) {
                    Outcome::UpstreamError(UpstreamErrorKind::AuthRejected)
                } else {
                    Outcome::Allowed
                };
                complete(&*self.session, &c.action, outcome, c.bytes_up, c.bytes_down);
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
    fn expectations() {
        assert!(matches!(expect(&args("GET k")), Expect::One));
        assert!(matches!(expect(&args("subscribe a b")), Expect::PubSub { kind: b"subscribe", left: Some(2) }));
        assert!(matches!(expect(&args("SUBSCRIBE")), Expect::One));
        assert!(matches!(expect(&args("PSUBSCRIBE")), Expect::One));
        assert!(matches!(expect(&args("SSUBSCRIBE")), Expect::One));
        assert!(matches!(expect(&args("UNSUBSCRIBE")), Expect::PubSub { kind: b"unsubscribe", left: None }));
        assert!(matches!(expect(&args("PUNSUBSCRIBE")), Expect::PubSub { kind: b"punsubscribe", left: None }));
        assert!(matches!(expect(&args("SUNSUBSCRIBE x")), Expect::PubSub { kind: b"sunsubscribe", left: Some(1) }));
        assert!(matches!(expect(&args("HELLO 3")), Expect::Hello(Some(3))));
        assert!(matches!(expect(&args("HELLO")), Expect::Hello(None)));
    }

    #[test]
    fn subscription_counts() {
        let mut s = Subscriptions::default();
        s.update(b"subscribe", 1);
        s.update(b"subscribe", 2);
        s.update(b"psubscribe", 3);
        s.update(b"subscribe", 3); // a channel already subscribed
        assert_eq!((s.channels, s.patterns), (2, 1));
        assert_eq!(s.of(b"unsubscribe"), 2);
        s.update(b"unsubscribe", 2);
        s.update(b"unsubscribe", 1);
        assert_eq!((s.channels, s.patterns), (0, 1));
        assert_eq!(s.of(b"unsubscribe"), 1, "an unsubscribe with nothing subscribed still gets one reply");
        s.update(b"ssubscribe", 1);
        assert!(s.any());
    }
}

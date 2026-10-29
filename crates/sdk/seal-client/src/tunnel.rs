//! Local tunnel: one loopback listener per session, on 127.0.0.1 with a random port.
//! Each accepted connection → TLS to a replica's port (pinned key, ALPN
//! `seal_proto::tunnel::ALPN`) → `TunnelPreamble::Challenge`, whose answer must verify
//! (`verify::check_challenged`) → `tunnel::encode(TunnelPreamble::Connect)` → bidirectional
//! copy. No protocol parsing; the proxy itself runs in the enclave. The challenge proves the
//! connection ends in an attested replica, not in a holder of copied service keys, before the
//! session token goes on it; a replica that cannot answer gets no token, and the connection
//! is refused.
//!
//! Every `SESSION_EXTEND_SECS` it extends the session (`Session::extend`: fresh
//! identity proof and endpoint report), then sends `TunnelPreamble::Extend` with the new token
//! to every replica holding one of its live connections, so they stay up. On `Expired` it re-reads the
//! blob (`SessionBuilder::reload_with`) and starts a new session. On `SessionEnded` or `IntegrityFailed` it stops:
//! the server ended the session on purpose, so it is never restarted silently.
//!
//! Replicas are the client's endpoints (`SEAL_ENDPOINT`, `ClientBuilder::endpoints`): each
//! serves the API and tunnels on the one port its endpoint names, and the pinned key, not the
//! name, identifies it. Connections go to the replica that last answered; when it does not,
//! the others are tried at once and the first to answer is used from then on. A replica that
//! serves no sessions (draining, or no longer listed) refuses before the TLS handshake, so the
//! next one is tried. When none is reachable, the app's connection is held while the replicas
//! are retried as for any call (`retry`, up to `UNREACHABLE_WAIT_SECS`), until the app closes
//! it or the tunnel stops.
//!
//! Each connection pays TCP, TLS and the challenge's round trip to the replica; the tunnel keeps
//! one spare, challenged, opened right after a connection takes the last one and kept at most
//! `SPARE_SECS`, so connections that come in bursts (a pool filling up) start without any of
//! them.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use seal_proto::api::ChallengedAttestation;
use seal_proto::tunnel::{encode, TunnelConnect, TunnelPreamble, EXTEND_OK, MAX_ANSWER_LEN};
use seal_proto::Bearer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;

use crate::retry::{self, Pass};
use crate::transport::{self, ConnectError};
use crate::verify::{self, VerifiedEnclave};
use crate::{Client, ClientError};

/// The session's current token, shared by the tunnel and the session that extends it.
pub(crate) type TokenCell = Mutex<Bearer>;

/// How long a spare connection is kept: under the enclave's 30 s wait for a preamble after
/// the challenge's answer.
const SPARE_SECS: u64 = 20;
/// Copy buffer per direction and connection.
const COPY_BUFFER: usize = 64 << 10;

/// A running tunnel. Dropping it stops the listener and every connection.
pub struct Tunnel {
    local_addr: SocketAddr,
    shared: Arc<Shared>,
    accept: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Tunnel").field("local_addr", &self.local_addr).finish_non_exhaustive()
    }
}

/// A replica's host and port.
type Replica = (String, u16);

/// A replica connection, handshaken, challenged and waiting for its preamble.
struct Spare {
    replica: usize,
    /// The enclave it was opened to: a spare from before a re-verification is not used.
    enclave: Arc<VerifiedEnclave>,
    opened: Instant,
    tls: TlsStream<TcpStream>,
}

/// What the accept loop, its connections and the extender share.
pub(crate) struct Shared {
    client: Client,
    token: Arc<TokenCell>,
    local_key_sha256: [u8; 32],
    /// Replicas in failover order.
    replicas: Vec<Replica>,
    /// The replica that last answered, tried first.
    preferred: AtomicUsize,
    spare: Mutex<Option<Spare>>,
    /// A spare is being opened: one at a time, however many connections come at once.
    refilling: AtomicBool,
    /// Live connections per replica.
    live: Mutex<BTreeMap<usize, usize>>,
    stop: watch::Sender<bool>,
}

/// Counts one live connection to a replica while it exists.
struct LiveGuard {
    shared: Arc<Shared>,
    replica: usize,
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        let mut live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = live.get_mut(&self.replica) {
            *n -= 1;
            if *n == 0 {
                live.remove(&self.replica);
            }
        }
    }
}

impl Tunnel {
    /// Binds `127.0.0.1:0` and starts accepting.
    pub(crate) async fn start(
        client: Client,
        token: Arc<TokenCell>,
        local_key_sha256: [u8; 32],
        replicas: Vec<Replica>,
    ) -> Result<Self, ClientError> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| ClientError::Network(format!("tunnel listener: {e}")))?;
        let local_addr = listener.local_addr().map_err(|e| ClientError::Network(format!("tunnel listener: {e}")))?;
        let (stop, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            client,
            token,
            local_key_sha256,
            replicas,
            preferred: AtomicUsize::new(0),
            spare: Mutex::new(None),
            refilling: AtomicBool::new(false),
            live: Mutex::default(),
            stop,
        });
        let accept = tokio::spawn(accept_loop(shared.clone(), listener));
        Ok(Self { local_addr, shared, accept: Mutex::new(Some(accept)) })
    }

    /// Where the app connects: `127.0.0.1` and the tunnel's port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn shared(&self) -> Arc<Shared> {
        self.shared.clone()
    }

    /// Stops accepting, closes every connection and waits until they are gone.
    pub(crate) async fn close(&self) {
        self.shared.stop();
        let accept = self.accept.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(accept) = accept {
            let _ = accept.await;
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.shared.stop();
        if let Some(accept) = self.accept.lock().unwrap_or_else(|e| e.into_inner()).take() {
            accept.abort();
        }
    }
}

impl Shared {
    /// Stops the tunnel: the listener, every connection and the spare close.
    pub(crate) fn stop(&self) {
        self.stop.send_replace(true);
        self.spare.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    /// Sends `TunnelPreamble::Extend` with `token` to every replica holding a live
    /// connection; each answers `EXTEND_OK`. Failures are logged: those connections close at
    /// their old expiry.
    pub(crate) async fn push_extend(&self, token: &Bearer) {
        let Ok(enclave) = self.client.enclave().await else {
            tracing::warn!("tunnel: no verified enclave to send the extension to");
            return;
        };
        let replicas: Vec<usize> = self.live.lock().unwrap_or_else(|e| e.into_inner()).keys().copied().collect();
        for replica in replicas {
            let (host, port) = &self.replicas[replica];
            let result = async {
                let mut tls = connect(&self.client, &enclave, host, *port).await.map_err(ClientError::from)?;
                let preamble = encode(&TunnelPreamble::Extend { token: token.duplicate() });
                tls.write_all(&preamble).await.map_err(|e| ClientError::Network(e.to_string()))?;
                tls.flush().await.map_err(|e| ClientError::Network(e.to_string()))?;
                let mut answer = [0u8; 1];
                tls.read_exact(&mut answer).await.map_err(|e| ClientError::Network(e.to_string()))?;
                if answer[0] != EXTEND_OK {
                    return Err(ClientError::Network(format!("answered 0x{:02x}", answer[0])));
                }
                Ok(())
            };
            match tokio::time::timeout(transport::EXCHANGE_TIMEOUT, result).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(host, error = %e, "tunnel: replica refused the extension"),
                Err(_) => tracing::warn!(host, "tunnel: extending the replica's connections timed out"),
            }
        }
    }

    /// The spare, if it is fresh, still open, and to the preferred replica of the current
    /// enclave.
    fn take_spare(&self, enclave: &Arc<VerifiedEnclave>) -> Option<(usize, TlsStream<TcpStream>)> {
        let mut spare = self.spare.lock().unwrap_or_else(|e| e.into_inner()).take()?;
        let usable = spare.opened.elapsed() < Duration::from_secs(SPARE_SECS)
            && spare.replica == self.preferred.load(Ordering::Relaxed)
            && Arc::ptr_eq(&spare.enclave, enclave)
            && quiet(&mut spare.tls);
        usable.then_some((spare.replica, spare.tls))
    }

    /// A challenged connection to the preferred replica; when it does not answer, to whichever
    /// other answers first, which becomes the preferred one. A replica presenting a key other
    /// than the attested one, or failing its challenge, ends the search.
    async fn open(&self, enclave: &Arc<VerifiedEnclave>) -> Pass<(usize, TlsStream<TcpStream>)> {
        let first = self.preferred.load(Ordering::Relaxed);
        let (host, port) = &self.replicas[first];
        let mut last = match connect(&self.client, enclave, host, *port).await {
            Ok(tls) => return Pass::Answered(Ok((first, tls))),
            Err(OpenError::Refused(e)) => {
                tracing::warn!(host, error = %e, "tunnel: replica refused");
                return Pass::Answered(Err(e));
            }
            Err(OpenError::Unreachable(m)) => {
                tracing::debug!(error = %m, "tunnel: replica unreachable");
                m
            }
        };
        let mut racing = tokio::task::JoinSet::new();
        for (i, (host, port)) in self.replicas.iter().enumerate().filter(|(i, _)| *i != first) {
            let (client, enclave, host, port) = (self.client.clone(), enclave.clone(), host.clone(), *port);
            racing.spawn(async move { (i, connect(&client, &enclave, &host, port).await) });
        }
        while let Some(done) = racing.join_next().await {
            match done {
                Ok((i, Ok(tls))) => {
                    self.preferred.store(i, Ordering::Relaxed);
                    return Pass::Answered(Ok((i, tls)));
                }
                Ok((i, Err(OpenError::Refused(e)))) => {
                    tracing::warn!(host = self.replicas[i].0, error = %e, "tunnel: replica refused");
                    return Pass::Answered(Err(e));
                }
                Ok((_, Err(OpenError::Unreachable(m)))) => {
                    tracing::debug!(error = %m, "tunnel: replica unreachable");
                    last = m;
                }
                Err(_) => {}
            }
        }
        Pass::Unreachable(ClientError::Network(last))
    }

    /// Opens a spare unless one is kept or being opened.
    fn refill(self: &Arc<Self>, enclave: Arc<VerifiedEnclave>) {
        if self.spare.lock().unwrap_or_else(|e| e.into_inner()).is_some() || self.refilling.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let shared = self.clone();
        tokio::spawn(async move {
            let replica = shared.preferred.load(Ordering::Relaxed);
            let (host, port) = &shared.replicas[replica];
            let opened = connect(&shared.client, &enclave, host, *port).await;
            if let (Ok(tls), false) = (opened, *shared.stop.borrow()) {
                let mut spare = shared.spare.lock().unwrap_or_else(|e| e.into_inner());
                if spare.is_none() {
                    *spare = Some(Spare { replica, enclave, opened: Instant::now(), tls });
                }
            }
            shared.refilling.store(false, Ordering::Release);
        });
    }
}

/// Why a replica connection was not opened.
enum OpenError {
    /// Nothing was sent but the challenge: try another replica.
    Unreachable(String),
    /// The replica presented another key than the attested one, or its answer to the
    /// challenge did not verify (a release older than the challenge included).
    Refused(ClientError),
}

impl From<OpenError> for ClientError {
    fn from(e: OpenError) -> Self {
        match e {
            OpenError::Unreachable(m) => ClientError::Network(m),
            OpenError::Refused(e) => e,
        }
    }
}

/// TLS to a replica, pinned to `enclave`'s key, and the challenge (module docs): a fresh nonce
/// in a `Challenge` preamble, answered with a `ChallengedAttestation` for it and this
/// connection's exporter. Only a connection whose answer verifies is returned.
async fn connect(
    client: &Client,
    enclave: &VerifiedEnclave,
    host: &str,
    port: u16,
) -> Result<TlsStream<TcpStream>, OpenError> {
    let mut tls = transport::tls_connect(enclave.tunnel_config(), host, port).await.map_err(|e| match e {
        e @ ConnectError::Pin => OpenError::Refused(e.into()),
        ConnectError::Unreachable(m) => OpenError::Unreachable(m),
    })?;
    let exporter = verify::tls_exporter(&tls).map_err(OpenError::Refused)?;
    let nonce = *seal_crypto::Key32::generate(&mut seal_crypto::UnwrapErr(seal_crypto::SysRng)).expose();
    let answer = async {
        let unreachable = |e: std::io::Error| OpenError::Unreachable(format!("tunnel challenge to {host}:{port}: {e}"));
        let unanswered = || {
            OpenError::Refused(ClientError::Verification(format!(
                "{host}:{port} did not answer the tunnel challenge (a release older than this SDK?)"
            )))
        };
        tls.write_all(&encode(&TunnelPreamble::Challenge { nonce })).await.map_err(unreachable)?;
        tls.flush().await.map_err(unreachable)?;
        let mut len = [0u8; 4];
        tls.read_exact(&mut len).await.map_err(|_| unanswered())?;
        let len = u32::from_be_bytes(len);
        if len == 0 || len > MAX_ANSWER_LEN {
            return Err(unanswered());
        }
        let mut body = vec![0u8; len as usize];
        tls.read_exact(&mut body).await.map_err(|_| unanswered())?;
        seal_proto::codec::from_canonical::<ChallengedAttestation>(&body).map_err(|_| unanswered())
    };
    let answer = tokio::time::timeout(transport::EXCHANGE_TIMEOUT, answer)
        .await
        .map_err(|_| OpenError::Unreachable(format!("tunnel challenge to {host}:{port}: timed out")))??;
    client.check_challenged(&answer, &nonce, &exporter, enclave).map_err(OpenError::Refused)?;
    Ok(tls)
}

/// Whether a spare has nothing to read: a replica that went away has closed it (EOF, a reset,
/// or a TLS close), while one waiting for a preamble sends nothing but session tickets, which
/// TLS consumes itself.
fn quiet(tls: &mut TlsStream<TcpStream>) -> bool {
    let mut byte = [0u8; 1];
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut buf = tokio::io::ReadBuf::new(&mut byte);
    matches!(tokio::io::AsyncRead::poll_read(std::pin::Pin::new(tls), &mut cx, &mut buf), std::task::Poll::Pending)
}

async fn accept_loop(shared: Arc<Shared>, listener: TcpListener) {
    let mut stop = shared.stop.subscribe();
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.wait_for(|s| *s) => break,
            accepted = listener.accept() => match accepted {
                Ok((inbound, _)) => {
                    let _ = inbound.set_nodelay(true);
                    connections.spawn(connection(shared.clone(), inbound));
                }
                Err(e) => tracing::warn!(error = %e, "tunnel: accept failed"),
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    drop(listener);
    connections.shutdown().await;
}

/// One app connection: the spare or a new connection to a replica (held while none is
/// reachable), the `Connect` preamble, then bytes both ways until either side closes or the
/// tunnel stops.
async fn connection(shared: Arc<Shared>, mut inbound: TcpStream) {
    let mut stop = shared.stop.subscribe();
    let enclave = tokio::select! {
        _ = stop.wait_for(|s| *s) => return,
        _ = closed(&inbound) => return,
        enclave = shared.client.enclave() => match enclave {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "tunnel: enclave not verified; connection refused");
                return;
            }
        },
    };
    let upstream = match shared.take_spare(&enclave) {
        Some(spare) => Ok(spare),
        None => match shared.open(&enclave).await {
            Pass::Answered(result) => result,
            Pass::Unreachable(missed) => tokio::select! {
                _ = stop.wait_for(|s| *s) => return,
                _ = closed(&inbound) => return,
                result = retry::while_unreachable(missed, || shared.open(&enclave)) => result,
            },
        },
    };
    let (replica, mut tls) = match upstream {
        Ok(upstream) => upstream,
        Err(e) => {
            tracing::warn!(error = %e, "tunnel: no replica connection; connection refused");
            return;
        }
    };
    shared.refill(enclave);
    *shared.live.lock().unwrap_or_else(|e| e.into_inner()).entry(replica).or_default() += 1;
    let _live = LiveGuard { shared: shared.clone(), replica };

    // The preamble goes out with the app's first bytes: no round trip of its own (the
    // challenge's was made when the connection was opened).
    let token = shared.token.lock().unwrap_or_else(|e| e.into_inner()).duplicate();
    let preamble = encode(&TunnelPreamble::Connect(TunnelConnect { token, local_key_sha256: shared.local_key_sha256 }));
    if let Err(e) = tls.write_all(&preamble).await {
        tracing::debug!(error = %e, "tunnel: preamble not sent");
        return;
    }
    tokio::select! {
        _ = stop.wait_for(|s| *s) => {}
        result = tokio::io::copy_bidirectional_with_sizes(&mut inbound, &mut tls, COPY_BUFFER, COPY_BUFFER) => {
            if let Err(e) = result {
                tracing::debug!(error = %e, "tunnel: connection ended");
            }
        }
    }
}

/// Resolves once the app has closed `inbound` before sending anything. Pending for good once it
/// has sent something: its first bytes stay unread until a replica takes them.
async fn closed(inbound: &TcpStream) {
    let mut byte = [0u8; 1];
    if let Ok(1..) = inbound.peek(&mut byte).await {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preambles_are_framed() {
        let connect = encode(&TunnelPreamble::Connect(TunnelConnect {
            token: Bearer::new("sealtok_x".into()),
            local_key_sha256: [1; 32],
        }));
        assert_eq!(&connect[..8], seal_proto::tunnel::MAGIC);
        let len = u32::from_be_bytes(connect[8..12].try_into().unwrap()) as usize;
        assert_eq!(len, connect.len() - 12);
        let decoded: TunnelPreamble = seal_proto::codec::from_canonical(&connect[12..]).unwrap();
        assert!(matches!(decoded, TunnelPreamble::Connect(c) if c.local_key_sha256 == [1; 32]));
    }
}

//! The upstream side of the handshake: startup as the destination's user and database, then
//! SCRAM-SHA-256 with the secret, then the server's parameters up to its first `ReadyForQuery`.

use bytes::BytesMut;
use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256, SCRAM_SHA_256, SCRAM_SHA_256_PLUS};
use postgres_protocol::message::frontend;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::wire::{self, Auth, WireError};

/// Upstream handshake messages are small; anything longer is refused.
const MAX_HANDSHAKE_BODY: usize = 64 << 10;

/// The upstream after a successful handshake.
pub struct Ready {
    /// `ParameterStatus` and `NoticeResponse` messages, whole and unscrubbed, in order.
    pub messages: Vec<Vec<u8>>,
    /// The upstream's `BackendKeyData`: process ID and secret key, for cancel requests. Never
    /// sent to the client.
    pub pid: i32,
    pub key: i32,
    /// Transaction status of the first `ReadyForQuery`.
    pub status: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The upstream asked for something other than SCRAM-SHA-256 (cleartext, MD5, GSS, …),
    /// or skipped authentication; the secret is never sent that way.
    Method,
    /// The upstream refused the login or the session (`ErrorResponse`), with its SQLSTATE
    /// when it sent a well-formed one.
    Rejected(Option<[u8; 5]>),
    /// SCRAM failed on our side: a malformed server message or a wrong server signature.
    Scram,
    Protocol,
    Io,
}

impl From<WireError> for Failure {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Io(_) => Failure::Io,
            WireError::Malformed(_) | WireError::TooLong => Failure::Protocol,
        }
    }
}

/// Runs the upstream handshake. `params` go into the startup message as given (the caller
/// puts user, database and its allowlisted parameters there). `binding` is the
/// `tls-server-end-point` channel-binding data of the upstream's TLS connection, when known.
/// With it, SCRAM-SHA-256-PLUS is used whenever the server offers it; when the server offers
/// only SCRAM-SHA-256 the client-first message says `y` (binding supported, not offered), so
/// a server whose PLUS offer was stripped in transit refuses. Without it, the message says `n`.
/// Authentication succeeds only after the server's SCRAM signature verifies.
pub async fn handshake<R, W>(
    r: &mut R,
    w: &mut W,
    params: &[(&str, &str)],
    secret: &[u8],
    binding: Option<Vec<u8>>,
) -> Result<Ready, Failure>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = BytesMut::new();
    frontend::startup_message(params.iter().copied(), &mut buf).map_err(|_| Failure::Protocol)?;
    send(w, &mut buf).await?;

    let mut scram: Option<ScramSha256> = None;
    let mut verified = false;
    loop {
        let (ty, body) = read(r).await?;
        match ty {
            b'R' => match wire::parse_auth(&body)? {
                Auth::Sasl(mechanisms) if scram.is_none() => {
                    let offers = |m: &str| mechanisms.contains(&m.as_bytes());
                    let (mechanism, channel_binding) = match &binding {
                        Some(data) if offers(SCRAM_SHA_256_PLUS) => {
                            (SCRAM_SHA_256_PLUS, ChannelBinding::tls_server_end_point(data.clone()))
                        }
                        Some(_) if offers(SCRAM_SHA_256) => (SCRAM_SHA_256, ChannelBinding::unrequested()),
                        None if offers(SCRAM_SHA_256) => (SCRAM_SHA_256, ChannelBinding::unsupported()),
                        _ => return Err(Failure::Method),
                    };
                    let s = ScramSha256::new(secret, channel_binding);
                    frontend::sasl_initial_response(mechanism, s.message(), &mut buf).map_err(|_| Failure::Protocol)?;
                    send(w, &mut buf).await?;
                    scram = Some(s);
                }
                Auth::SaslContinue(data) => {
                    let s = scram.as_mut().ok_or(Failure::Protocol)?;
                    s.update(data).map_err(|_| Failure::Scram)?;
                    frontend::sasl_response(s.message(), &mut buf).map_err(|_| Failure::Protocol)?;
                    send(w, &mut buf).await?;
                }
                Auth::SaslFinal(data) => {
                    // Verifies the server signature: the server proved it knows the verifier.
                    scram.as_mut().ok_or(Failure::Protocol)?.finish(data).map_err(|_| Failure::Scram)?;
                    verified = true;
                }
                Auth::Ok if verified => break,
                Auth::Ok if scram.is_none() => return Err(Failure::Method),
                Auth::Ok => return Err(Failure::Scram),
                Auth::Sasl(_) => return Err(Failure::Protocol),
                Auth::Other(_) => return Err(Failure::Method),
            },
            b'E' => return Err(Failure::Rejected(wire::sqlstate(&body))),
            // The client side has not negotiated anything the upstream could refuse.
            _ => return Err(Failure::Protocol),
        }
    }

    let mut messages = Vec::new();
    let (mut pid, mut key) = (0, 0);
    loop {
        let (ty, body) = read(r).await?;
        match ty {
            b'S' | b'N' => messages.push(whole(ty, &body)),
            b'K' => (pid, key) = wire::backend_key(&body)?,
            b'Z' => return Ok(Ready { messages, pid, key, status: wire::ready_status(&body)? }),
            b'E' => return Err(Failure::Rejected(wire::sqlstate(&body))),
            _ => return Err(Failure::Protocol),
        }
    }
}

async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>), Failure> {
    let (ty, len) = wire::read_header(r).await?.ok_or(Failure::Io)?;
    Ok((ty, wire::read_body(r, len, MAX_HANDSHAKE_BODY).await?))
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, buf: &mut BytesMut) -> Result<(), Failure> {
    let out = buf.split();
    w.write_all(&out).await.map_err(|_| Failure::Io)?;
    w.flush().await.map_err(|_| Failure::Io)
}

fn whole(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![ty];
    out.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    out.extend_from_slice(body);
    out
}

//! The client side of the handshake: TLS and GSS negotiation answered `N`, the startup
//! message, and a cleartext password that carries the Seal credential; or a `CancelRequest`.

use seal_adapter::AdapterError;
use seal_proto::tunnel::find_local_key;
use seal_proto::ErrorCode;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::{Zeroize, Zeroizing};

use crate::relay::ClientOut;
use crate::wire::{self, Startup, WireError};

/// A password message carries the credential; Postgres's own limit for one (`PG_MAX_AUTH_TOKEN_LENGTH`).
const MAX_PASSWORD_BODY: usize = 65_535;

/// Startup parameters forwarded to the upstream, besides the destination's `user` and
/// `database` and a fixed `client_encoding` (`UTF8`). Each is an ordinary per-session setting
/// that any role may change with `SET`, so forwarding it grants nothing; drivers send them at
/// startup and some depend on them (pgJDBC checks `DateStyle`, drivers set
/// `extra_float_digits` for exact floats). `client_encoding` is never taken from the client:
/// the upstream session starts in UTF-8, so detectors see UTF-8 SQL and the scrubber sees the
/// secret as stored; the client learns it from the `ParameterStatus` it receives.
pub const FORWARDED_PARAMS: &[&str] =
    &["application_name", "DateStyle", "TimeZone", "IntervalStyle", "extra_float_digits"];
/// A forwarded parameter's value: printable ASCII, at most this long; others are dropped.
const MAX_PARAM_VALUE: usize = 64;

/// How a client connection starts.
pub enum Start {
    Login(Login),
    /// A `CancelRequest` with the key `BackendKeyData` gave the connection to cancel.
    Cancel {
        pid: i32,
        key: i32,
    },
}

/// What the client sent before the adapter connects upstream.
pub struct Login {
    /// The allowlisted startup parameters, in the client's order (last one wins per name).
    pub params: Vec<(String, String)>,
    pub credential: Zeroizing<String>,
}

/// Runs the client handshake up to the password, or reads a `CancelRequest`. `Ok(None)` when
/// the client closes first. Refusals are sent as `FATAL` `ErrorResponse`s with fixed text
/// before returning the error.
pub async fn login<R, W>(r: &mut R, out: &mut ClientOut<W>) -> Result<Option<Start>, AdapterError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut negotiations = 0;
    let (minor, params) = loop {
        match wire::read_startup(r).await {
            Ok(None) => return Ok(None),
            Ok(Some(Startup::Ssl | Startup::GssEnc)) if negotiations < 2 => {
                // TLS is already terminated in front of the adapter: decline a second layer,
                // and the client continues in clear on this connection.
                negotiations += 1;
                out.send(b"N").await?;
                out.flush().await?;
            }
            Ok(Some(Startup::Ssl | Startup::GssEnc)) => {
                return Err(client_error(out, b"08P01", "too many encryption requests").await)
            }
            Ok(Some(Startup::Cancel { pid, key })) => return Ok(Some(Start::Cancel { pid, key })),
            Ok(Some(Startup::Message { major: 3, minor, params })) => break (minor, params),
            Ok(Some(Startup::Message { .. })) => {
                return Err(client_error(out, b"0A000", "only protocol 3.0 is supported").await)
            }
            Err(WireError::Io(e)) => return Err(e.into()),
            Err(_) => return Err(client_error(out, b"08P01", "invalid startup packet").await),
        }
    };

    if params.iter().any(|(k, v)| k == "replication" && !is_false(v)) {
        let denied = AdapterError::Denied(ErrorCode::PolicyDenied);
        return Err(out.refuse(b"0A000", "seal: replication connections are not supported", denied).await);
    }
    // Speak 3.0 only: a client asking for a newer minor or for protocol options is told so,
    // as a 3.0 server does, and continues at 3.0 without them.
    let options: Vec<String> = params.iter().filter(|(k, _)| k.starts_with("_pq_.")).map(|(k, _)| k.clone()).collect();
    if minor > 0 || !options.is_empty() {
        out.send(&wire::negotiate_protocol_version(0, &options)).await?;
    }
    out.send(&wire::auth_cleartext_password()).await?;
    out.flush().await?;

    let (ty, len) = match wire::read_header(r).await {
        Ok(Some(header)) => header,
        Ok(None) => return Ok(None),
        Err(WireError::Io(e)) => return Err(e.into()),
        Err(_) => return Err(client_error(out, b"08P01", "invalid message").await),
    };
    if ty != b'p' {
        return Err(client_error(out, b"08P01", "expected a password message").await);
    }
    let mut body = match wire::read_body(r, len, MAX_PASSWORD_BODY).await {
        Ok(body) => Zeroizing::new(body),
        Err(WireError::Io(e)) => return Err(e.into()),
        Err(_) => return Err(client_error(out, b"08P01", "invalid password message").await),
    };
    let credential = wire::single_cstr(&body).ok().and_then(credential);
    body.zeroize();
    let Some(credential) = credential else {
        let denied = AdapterError::Denied(ErrorCode::NotAllowed);
        return Err(out.refuse(b"28P01", "seal: the password is not a Seal credential", denied).await);
    };
    Ok(Some(Start::Login(Login { params: forwarded(params), credential })))
}

/// A client protocol error: `FATAL` with `seal: <text>`, then `AdapterError::Client(text)`.
async fn client_error<W>(out: &mut ClientOut<W>, sqlstate: &[u8; 5], text: &'static str) -> AdapterError
where
    W: AsyncWrite + Unpin,
{
    out.refuse(sqlstate, &format!("seal: {text}"), AdapterError::Client(text)).await
}

/// The tunnel's local key in a password, if any.
fn credential(password: &[u8]) -> Option<Zeroizing<String>> {
    let text = Zeroizing::new(String::from_utf8_lossy(password).into_owned());
    let c = find_local_key(&text)?;
    Some(Zeroizing::new(c.to_string()))
}

/// Postgres's false spellings for a boolean `replication`; anything else asks for replication.
fn is_false(value: &str) -> bool {
    ["false", "off", "no", "0"].iter().any(|f| value.eq_ignore_ascii_case(f))
}

/// The allowlisted parameters with acceptable values, one per name (the last one sent).
fn forwarded(params: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (name, value) in params {
        let Some(allowed) = FORWARDED_PARAMS.iter().find(|p| p.eq_ignore_ascii_case(&name)) else { continue };
        if value.len() > MAX_PARAM_VALUE || !value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            continue;
        }
        out.retain(|(n, _)| n != allowed);
        out.push((allowed.to_string(), value));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwards_only_allowlisted_params() {
        let params = vec![
            ("user".to_string(), "root".to_string()),
            ("database".to_string(), "postgres".to_string()),
            ("options".to_string(), "-c role=admin".to_string()),
            ("application_name".to_string(), "first".to_string()),
            ("datestyle".to_string(), "ISO, MDY".to_string()),
            ("client_encoding".to_string(), "SJIS".to_string()),
            ("application_name".to_string(), "second".to_string()),
            ("TimeZone".to_string(), "x".repeat(65)),
            ("extra_float_digits".to_string(), "3\u{7f}".to_string()),
        ];
        assert_eq!(
            forwarded(params),
            vec![
                ("DateStyle".to_string(), "ISO, MDY".to_string()),
                ("application_name".to_string(), "second".to_string())
            ]
        );
    }

    #[test]
    fn finds_the_credential_in_the_password() {
        assert_eq!(credential(b"seallk_x9").as_deref().map(String::as_str), Some("seallk_x9"));
        assert!(credential(b"sealtok_abc").is_none(), "session tokens never reach the app");
        assert!(credential(b"hunter2").is_none());
    }

    #[test]
    fn replication_spellings() {
        assert!(is_false("off") && is_false("FALSE") && is_false("0"));
        assert!(!is_false("database") && !is_false("true") && !is_false(""));
    }
}

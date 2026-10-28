//! Postgres v3 framing: the packets the adapter reads from either side, and the backend
//! messages it writes itself. Every length is checked before anything is allocated.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

pub const SSL_REQUEST: i32 = 80_877_103;
pub const GSSENC_REQUEST: i32 = 80_877_104;
pub const CANCEL_REQUEST: i32 = 80_877_102;
/// A startup-phase packet, length included (Postgres's own `MAX_STARTUP_PACKET_LENGTH`).
pub const MAX_STARTUP_LEN: usize = 10_000;
/// Any typed message body (Postgres's own `PQ_LARGE_MESSAGE_LIMIT`, 1 GiB - 1, less the length word).
pub const MAX_BODY_LEN: usize = 0x3fff_ffff - 4;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("message too long")]
    TooLong,
}

/// A startup-phase packet from the client.
#[derive(Debug, PartialEq, Eq)]
pub enum Startup {
    Ssl,
    GssEnc,
    /// `CancelRequest`: the process ID and secret key of the connection to cancel.
    Cancel {
        pid: i32,
        key: i32,
    },
    /// `StartupMessage`: the requested protocol version and its parameters, in order.
    Message {
        major: u16,
        minor: u16,
        params: Vec<(String, String)>,
    },
}

/// Reads one startup-phase packet. `Ok(None)` when the client closes before sending one.
pub async fn read_startup<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Startup>, WireError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = startup_len(len)?;
    let mut body = vec![0u8; len - 4];
    r.read_exact(&mut body).await?;
    parse_startup(&body).map(Some)
}

/// The packet length from its first four bytes: 8..=`MAX_STARTUP_LEN`.
pub fn startup_len(len: [u8; 4]) -> Result<usize, WireError> {
    let len = u32::from_be_bytes(len) as usize;
    if len < 8 {
        return Err(WireError::Malformed("startup packet too short"));
    }
    if len > MAX_STARTUP_LEN {
        return Err(WireError::TooLong);
    }
    Ok(len)
}

/// A startup-phase packet after its length word: Int32 code, then the code's payload.
pub fn parse_startup(body: &[u8]) -> Result<Startup, WireError> {
    let (code, rest) = take_i32(body)?;
    match code {
        SSL_REQUEST if rest.is_empty() => Ok(Startup::Ssl),
        GSSENC_REQUEST if rest.is_empty() => Ok(Startup::GssEnc),
        CANCEL_REQUEST if rest.len() == 8 => {
            let (pid, rest) = take_i32(rest)?;
            let (key, _) = take_i32(rest)?;
            Ok(Startup::Cancel { pid, key })
        }
        SSL_REQUEST | GSSENC_REQUEST | CANCEL_REQUEST => Err(WireError::Malformed("bad request packet")),
        version => {
            let major = (version >> 16) as u16;
            let minor = (version & 0xffff) as u16;
            Ok(Startup::Message { major, minor, params: parse_params(rest)? })
        }
    }
}

/// `name\0value\0`… terminated by one more `\0`, and nothing after it.
fn parse_params(mut rest: &[u8]) -> Result<Vec<(String, String)>, WireError> {
    let mut params = Vec::new();
    loop {
        let (name, after) = take_cstr(rest)?;
        if name.is_empty() {
            if !after.is_empty() {
                return Err(WireError::Malformed("bytes after startup parameters"));
            }
            return Ok(params);
        }
        let (value, after) = take_cstr(after)?;
        params.push((String::from_utf8_lossy(name).into_owned(), String::from_utf8_lossy(value).into_owned()));
        rest = after;
    }
}

/// Reads a typed message header (type byte, Int32 length including itself). `Ok(None)` on a
/// clean end of stream before the type byte. Returns the type and the body length.
pub async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<(u8, usize)>, WireError> {
    let mut ty = [0u8; 1];
    if r.read(&mut ty).await? == 0 {
        return Ok(None);
    }
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    Ok(Some((ty[0], body_len(len)?)))
}

/// The body length from a typed message's length word: at least 4, at most `MAX_BODY_LEN` + 4.
pub fn body_len(len: [u8; 4]) -> Result<usize, WireError> {
    let len = u32::from_be_bytes(len) as usize;
    if len < 4 {
        return Err(WireError::Malformed("message length below 4"));
    }
    let body = len - 4;
    if body > MAX_BODY_LEN {
        return Err(WireError::TooLong);
    }
    Ok(body)
}

/// Reads a body of `len` bytes, refusing it before reading when it is over `max`.
pub async fn read_body<R: AsyncRead + Unpin>(r: &mut R, len: usize, max: usize) -> Result<Vec<u8>, WireError> {
    if len > max {
        return Err(WireError::TooLong);
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Whether `buf` starts with one whole typed message.
pub fn holds_message(buf: &[u8]) -> bool {
    if buf.len() < 5 {
        return false;
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    buf.len() > len
}

fn take_i32(buf: &[u8]) -> Result<(i32, &[u8]), WireError> {
    match buf {
        [a, b, c, d, rest @ ..] => Ok((i32::from_be_bytes([*a, *b, *c, *d]), rest)),
        _ => Err(WireError::Malformed("truncated integer")),
    }
}

fn take_i16(buf: &[u8]) -> Result<(i16, &[u8]), WireError> {
    match buf {
        [a, b, rest @ ..] => Ok((i16::from_be_bytes([*a, *b]), rest)),
        _ => Err(WireError::Malformed("truncated integer")),
    }
}

fn take_cstr(buf: &[u8]) -> Result<(&[u8], &[u8]), WireError> {
    let nul = buf.iter().position(|&b| b == 0).ok_or(WireError::Malformed("unterminated string"))?;
    Ok((&buf[..nul], &buf[nul + 1..]))
}

/// A body that is exactly one C string: its bytes without the terminator.
pub fn single_cstr(body: &[u8]) -> Result<&[u8], WireError> {
    let (s, rest) = take_cstr(body)?;
    if !rest.is_empty() {
        return Err(WireError::Malformed("bytes after string"));
    }
    Ok(s)
}

/// `Query` body: the SQL text.
pub fn query_text(body: &[u8]) -> Result<&[u8], WireError> {
    single_cstr(body)
}

/// `Parse` body: statement name, SQL text, Int16 count, that many Int32 type OIDs. Returns the SQL text.
pub fn parse_text(body: &[u8]) -> Result<&[u8], WireError> {
    let (_name, rest) = take_cstr(body)?;
    let (sql, rest) = take_cstr(rest)?;
    let (count, rest) = take_i16(rest)?;
    if count < 0 || rest.len() != count as usize * 4 {
        return Err(WireError::Malformed("bad parameter type list"));
    }
    Ok(sql)
}

/// An `Authentication` request from the upstream (`R` body).
#[derive(Debug, PartialEq, Eq)]
pub enum Auth<'a> {
    Ok,
    /// SCRAM: the offered mechanisms.
    Sasl(Vec<&'a [u8]>),
    SaslContinue(&'a [u8]),
    SaslFinal(&'a [u8]),
    /// Any other method (cleartext, MD5, Kerberos, GSS, SSPI, SCM credentials).
    Other(i32),
}

pub fn parse_auth(body: &[u8]) -> Result<Auth<'_>, WireError> {
    let (code, rest) = take_i32(body)?;
    Ok(match code {
        0 if rest.is_empty() => Auth::Ok,
        10 => {
            let mut mechanisms = Vec::new();
            let mut rest = rest;
            loop {
                let (m, after) = take_cstr(rest)?;
                if m.is_empty() {
                    if !after.is_empty() {
                        return Err(WireError::Malformed("bytes after SASL mechanisms"));
                    }
                    break;
                }
                mechanisms.push(m);
                rest = after;
            }
            Auth::Sasl(mechanisms)
        }
        11 => Auth::SaslContinue(rest),
        12 => Auth::SaslFinal(rest),
        0 => return Err(WireError::Malformed("bad AuthenticationOk")),
        other => Auth::Other(other),
    })
}

/// `BackendKeyData` body: process ID and secret key.
pub fn backend_key(body: &[u8]) -> Result<(i32, i32), WireError> {
    let (pid, rest) = take_i32(body)?;
    let (key, rest) = take_i32(rest)?;
    if !rest.is_empty() {
        return Err(WireError::Malformed("bad BackendKeyData"));
    }
    Ok((pid, key))
}

/// `ReadyForQuery` body: the transaction status, `I`, `T` or `E`.
pub fn ready_status(body: &[u8]) -> Result<u8, WireError> {
    match body {
        [s @ (b'I' | b'T' | b'E')] => Ok(*s),
        _ => Err(WireError::Malformed("bad ReadyForQuery")),
    }
}

/// The SQLSTATE (`C` field) of an `ErrorResponse` or `NoticeResponse` body, when it is five
/// ASCII digits or upper-case letters. Nothing else of the upstream's text is ever used.
pub fn sqlstate(body: &[u8]) -> Option<[u8; 5]> {
    let mut rest = body;
    loop {
        let (&code, after) = rest.split_first()?;
        if code == 0 {
            return None;
        }
        let (value, after) = take_cstr(after).ok()?;
        if code == b'C' {
            let state: [u8; 5] = value.try_into().ok()?;
            return state.iter().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()).then_some(state);
        }
        rest = after;
    }
}

fn message(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(ty);
    out.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn auth_cleartext_password() -> Vec<u8> {
    message(b'R', &3i32.to_be_bytes())
}

pub fn auth_ok() -> Vec<u8> {
    message(b'R', &0i32.to_be_bytes())
}

/// A `CancelRequest` packet, length included.
pub fn cancel_request(pid: i32, key: i32) -> Vec<u8> {
    let mut out = 16u32.to_be_bytes().to_vec();
    for word in [CANCEL_REQUEST, pid, key] {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn backend_key_data(pid: i32, key: i32) -> Vec<u8> {
    let mut body = pid.to_be_bytes().to_vec();
    body.extend_from_slice(&key.to_be_bytes());
    message(b'K', &body)
}

pub fn ready_for_query(status: u8) -> Vec<u8> {
    message(b'Z', &[status])
}

/// `NegotiateProtocolVersion`: the newest 3.x minor the adapter speaks and the protocol
/// options (`_pq_.*`) it does not.
pub fn negotiate_protocol_version(minor: u16, unsupported: &[String]) -> Vec<u8> {
    let mut body = i32::from(minor).to_be_bytes().to_vec();
    body.extend_from_slice(&(unsupported.len() as i32).to_be_bytes());
    for name in unsupported {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
    }
    message(b'v', &body)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Fatal,
}

/// `ErrorResponse` with severity, SQLSTATE and message only. `message` is always the
/// adapter's own text.
pub fn error_response(severity: Severity, sqlstate: &[u8; 5], message_text: &str) -> Vec<u8> {
    let severity = match severity {
        Severity::Error => &b"ERROR"[..],
        Severity::Fatal => &b"FATAL"[..],
    };
    let mut body = Vec::new();
    for (code, value) in [(b'S', severity), (b'V', severity), (b'C', &sqlstate[..]), (b'M', message_text.as_bytes())] {
        body.push(code);
        body.extend(value.iter().filter(|&&b| b != 0));
        body.push(0);
    }
    body.push(0);
    message(b'E', &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const PROTOCOL_3_0: i32 = 196_608;

    fn startup_packet(version: i32, params: &[(&str, &str)]) -> Vec<u8> {
        let mut body = version.to_be_bytes().to_vec();
        for (k, v) in params {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        let mut out = (body.len() as u32 + 4).to_be_bytes().to_vec();
        out.extend(body);
        out
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    #[test]
    fn parses_startup_packets() {
        let p = startup_packet(PROTOCOL_3_0, &[("user", "x"), ("database", "y")]);
        let parsed = block_on(read_startup(&mut &p[..])).unwrap().unwrap();
        assert_eq!(
            parsed,
            Startup::Message {
                major: 3,
                minor: 0,
                params: vec![("user".into(), "x".into()), ("database".into(), "y".into())]
            }
        );
        let ssl = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
        assert_eq!(block_on(read_startup(&mut &ssl[..])).unwrap(), Some(Startup::Ssl));
        let gss = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30];
        assert_eq!(block_on(read_startup(&mut &gss[..])).unwrap(), Some(Startup::GssEnc));
        let cancel = [0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0, 1, 0, 0, 0, 2];
        assert_eq!(block_on(read_startup(&mut &cancel[..])).unwrap(), Some(Startup::Cancel { pid: 1, key: 2 }));
        assert_eq!(cancel_request(1, 2), cancel);
        assert_eq!(block_on(read_startup(&mut &[][..])).unwrap(), None);
    }

    #[test]
    fn refuses_bad_startup_lengths() {
        assert!(matches!(startup_len([0, 0, 0, 7]), Err(WireError::Malformed(_))));
        assert!(matches!(startup_len([0, 0, 0x27, 0x11]), Err(WireError::TooLong)));
        assert!(matches!(startup_len([0xff, 0xff, 0xff, 0xff]), Err(WireError::TooLong)));
        assert_eq!(startup_len([0, 0, 0x27, 0x10]).unwrap(), MAX_STARTUP_LEN);
    }

    #[test]
    fn refuses_bad_message_lengths() {
        assert!(matches!(body_len([0, 0, 0, 3]), Err(WireError::Malformed(_))));
        assert!(matches!(body_len([0x40, 0, 0, 0]), Err(WireError::TooLong)));
        assert!(matches!(body_len([0xff, 0xff, 0xff, 0xff]), Err(WireError::TooLong)));
        assert_eq!(body_len([0, 0, 0, 4]).unwrap(), 0);
        let huge = [b'Q', 0x3f, 0xff, 0xff, 0xff];
        let mut r = &huge[..];
        let (ty, len) = block_on(read_header(&mut r)).unwrap().unwrap();
        assert_eq!(ty, b'Q');
        assert!(matches!(block_on(read_body(&mut r, len, 1 << 20)), Err(WireError::TooLong)), "refused before reading");
    }

    #[test]
    fn parses_frontend_bodies() {
        assert_eq!(query_text(b"SELECT 1\0").unwrap(), b"SELECT 1");
        assert!(query_text(b"SELECT 1").is_err());
        assert!(query_text(b"SELECT 1\0; DROP\0").is_err(), "nothing after the string");
        let mut parse = b"s1\0SELECT $1\0".to_vec();
        parse.extend_from_slice(&1i16.to_be_bytes());
        parse.extend_from_slice(&23i32.to_be_bytes());
        assert_eq!(parse_text(&parse).unwrap(), b"SELECT $1");
        parse.push(0);
        assert!(parse_text(&parse).is_err());
        let mut negative = b"\0SELECT\0".to_vec();
        negative.extend_from_slice(&(-1i16).to_be_bytes());
        assert!(parse_text(&negative).is_err());
    }

    #[test]
    fn parses_backend_bodies() {
        let mut sasl = 10i32.to_be_bytes().to_vec();
        sasl.extend_from_slice(b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0");
        assert_eq!(parse_auth(&sasl).unwrap(), Auth::Sasl(vec![&b"SCRAM-SHA-256-PLUS"[..], &b"SCRAM-SHA-256"[..]]));
        assert_eq!(parse_auth(&5i32.to_be_bytes()).unwrap(), Auth::Other(5));
        assert_eq!(parse_auth(&0i32.to_be_bytes()).unwrap(), Auth::Ok);
        assert_eq!(ready_status(b"T").unwrap(), b'T');
        assert!(ready_status(b"X").is_err());
        assert_eq!(sqlstate(b"SERROR\0C28P01\0Mbad\0\0"), Some(*b"28P01"));
        assert_eq!(sqlstate(b"SERROR\0C28p01\0\0"), None);
        assert_eq!(sqlstate(b"Mno code\0\0"), None);
    }

    #[test]
    fn writes_error_responses() {
        let e = error_response(Severity::Fatal, b"57P01", "seal: gone\0");
        assert_eq!(e[0], b'E');
        assert_eq!(u32::from_be_bytes([e[1], e[2], e[3], e[4]]) as usize, e.len() - 1);
        assert_eq!(sqlstate(&e[5..]), Some(*b"57P01"));
        assert!(holds_message(&e));
        assert!(!holds_message(&e[..e.len() - 1]));
    }

    proptest! {
        #[test]
        fn startup_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = block_on(read_startup(&mut &bytes[..]));
            let _ = parse_startup(&bytes);
        }

        #[test]
        fn startup_round_trips(params in proptest::collection::vec(("[a-zA-Z_]{1,12}", "[ -~]{0,20}"), 0..6)) {
            let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let packet = startup_packet(PROTOCOL_3_0, &pairs);
            let parsed = block_on(read_startup(&mut &packet[..])).unwrap().unwrap();
            let expected: Vec<(String, String)> = params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            prop_assert_eq!(parsed, Startup::Message { major: 3, minor: 0, params: expected });
        }

        #[test]
        fn typed_messages_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut r = &bytes[..];
            while let Ok(Some((_, len))) = block_on(read_header(&mut r)) {
                if block_on(read_body(&mut r, len, 32)).is_err() {
                    break;
                }
            }
            let _ = holds_message(&bytes);
            let _ = query_text(&bytes);
            let _ = parse_text(&bytes);
            let _ = parse_auth(&bytes);
            let _ = backend_key(&bytes);
            let _ = ready_status(&bytes);
            let _ = sqlstate(&bytes);
        }

        #[test]
        fn huge_lengths_are_refused(len in (MAX_BODY_LEN as u32 + 5)..=u32::MAX) {
            prop_assert!(matches!(body_len(len.to_be_bytes()), Err(WireError::TooLong)));
            prop_assert!(startup_len(len.to_be_bytes()).is_err());
        }
    }
}

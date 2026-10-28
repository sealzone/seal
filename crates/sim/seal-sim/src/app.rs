//! The app's side of the demo: an SDK client holding only its app key and a blob, which calls
//! the upstream through the enclave without ever holding the secret.

use anyhow::{anyhow, bail, Context as _};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;

use seal::Client;

use crate::net;

/// What the app saw in the HTTP flow.
#[derive(Debug, Default)]
pub struct HttpReport {
    /// The session's id.
    pub session_ids: Vec<String>,
    /// Every key the app was handed: local stand-ins only.
    pub keys: Vec<String>,
    /// Every response body the app got from the upstream, through the enclave.
    pub bodies: Vec<String>,
    /// After `close`, the tunnel connection kept alive across the extend failed, and so did a
    /// new one.
    pub tunnel_closed: bool,
}

fn step(text: &str) {
    println!("app: {text}");
}

/// A session id as telemetry shows it (base64url).
fn id(info: &seal::SessionInfo) -> String {
    seal_proto::codec::b64url(&info.session_id)
}

/// `GET /models` on `conn` with `Authorization: Bearer <key>`; fails unless 200.
async fn call(conn: &mut net::Conn, key: &str, report: &mut HttpReport) -> anyhow::Result<()> {
    let auth = format!("Bearer {key}");
    let (status, body) = conn.get("/models", &[("authorization", &auth)]).await?;
    step(&format!("GET /models -> {status} {body}"));
    if status != 200 {
        bail!("GET /models: {status} {body}");
    }
    report.bodies.push(body);
    Ok(())
}

/// Whether a request with `key` on `conn` fails (an error or a status other than 200).
async fn refused(conn: &mut net::Conn, key: &str) -> bool {
    let auth = format!("Bearer {key}");
    match conn.get("/models", &[("authorization", &auth)]).await {
        Ok((200, _)) => false,
        Ok((status, body)) => {
            step(&format!("  -> {status} {body}"));
            true
        }
        Err(e) => {
            step(&format!("  -> {e:#}"));
            true
        }
    }
}

/// A tunnel session: two calls on one kept-alive connection with an extend in between, then
/// close; afterwards the connection and a new one are refused.
pub async fn http_flow(client: &Client, blob: &str) -> anyhow::Result<HttpReport> {
    let mut report = HttpReport::default();

    let mut s = client.session(blob).http().await.context("tunnel session")?;
    step(&format!("tunnel session {} until {}", id(s.info()), s.info().expires_at));
    step(&format!("url {}  key {} (a stand-in, worthless outside this tunnel)", s.url(), s.key()));
    report.session_ids.push(id(s.info()));
    report.keys.push(s.key().to_string());
    let (url, key) = (s.url().to_string(), s.key().to_string());
    let mut conn = net::Conn::open(&url, None).await?;
    call(&mut conn, &key, &mut report).await?;
    s.extend().await.context("extend the tunnel session")?;
    step(&format!("extended until {}; the same connection again:", s.info().expires_at));
    call(&mut conn, s.key(), &mut report).await?;
    s.close().await.context("close the tunnel session")?;
    step("tunnel session closed; the connection, then a new one:");
    let kept = refused(&mut conn, &key).await;
    let new = match net::Conn::open(&url, None).await {
        Ok(mut conn) => refused(&mut conn, &key).await,
        Err(e) => {
            step(&format!("  -> {e:#}"));
            true
        }
    };
    report.tunnel_closed = kept && new;
    Ok(report)
}

/// One Postgres message: type byte and body.
async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<(u8, Vec<u8>)> {
    let kind = stream.read_u8().await?;
    let len = stream.read_u32().await? as usize;
    let mut body = vec![0; len.checked_sub(4).ok_or_else(|| anyhow!("bad message length"))?];
    stream.read_exact(&mut body).await?;
    Ok((kind, body))
}

fn cstr(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// The text of a Postgres `ErrorResponse`'s message field.
fn error_text(body: &[u8]) -> String {
    body.split(|b| *b == 0)
        .find_map(|field| field.strip_prefix(b"M"))
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_default()
}

/// The text columns of a `DataRow`.
fn data_row(body: &[u8]) -> anyhow::Result<Vec<String>> {
    let short = || anyhow!("short DataRow");
    let count = i16::from_be_bytes(body.get(..2).ok_or_else(short)?.try_into()?);
    let mut rest = &body[2..];
    let mut out = Vec::new();
    for _ in 0..count {
        let len = i32::from_be_bytes(rest.get(..4).ok_or_else(short)?.try_into()?);
        rest = &rest[4..];
        if len < 0 {
            out.push("NULL".into());
            continue;
        }
        let (value, tail) = rest.split_at_checked(len as usize).ok_or_else(short)?;
        out.push(String::from_utf8_lossy(value).into_owned());
        rest = tail;
    }
    Ok(out)
}

/// Runs `sql` as a simple query on the connection `dsn` names, sending the credential as the
/// cleartext password the enclave asks for, and returns the rows. The DSN is the tunnel's
/// (`sslmode=disable`): in clear to loopback.
pub async fn pg_query(dsn: &str, sql: &str) -> anyhow::Result<Vec<Vec<String>>> {
    let url = url::Url::parse(dsn).context("the DSN")?;
    let host = url.host_str().ok_or_else(|| anyhow!("the DSN names no host"))?.to_string();
    let port = url.port().unwrap_or(5432);
    if !url.query_pairs().any(|(k, v)| k == "sslmode" && v == "disable") {
        bail!("not a tunnel DSN (sslmode=disable): {dsn}");
    }
    let tcp = TcpStream::connect((host.as_str(), port)).await.with_context(|| format!("connect {host}:{port}"))?;
    login_and_query(tcp, &url, sql).await
}

async fn login_and_query<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    url: &url::Url,
    sql: &str,
) -> anyhow::Result<Vec<Vec<String>>> {
    // Seal credentials are URL-safe, so the DSN carries them unescaped.
    let password = url.password().unwrap_or_default();
    let mut startup = Vec::new();
    startup.extend_from_slice(&196_608u32.to_be_bytes());
    cstr(&mut startup, "user");
    cstr(&mut startup, url.username());
    cstr(&mut startup, "database");
    cstr(&mut startup, url.path().trim_start_matches('/'));
    startup.push(0);
    let mut packet = (startup.len() as u32 + 4).to_be_bytes().to_vec();
    packet.extend_from_slice(&startup);
    stream.write_all(&packet).await?;

    loop {
        let (kind, body) = read_message(&mut stream).await?;
        match kind {
            b'R' if body.get(..4) == Some(&3u32.to_be_bytes()) => {
                let mut pw = Vec::new();
                cstr(&mut pw, password);
                stream.write_all(&message(b'p', &pw)).await?;
            }
            b'R' if body.get(..4) == Some(&0u32.to_be_bytes()) => {}
            b'R' => bail!("unexpected authentication request {body:?}"),
            b'E' => bail!("login refused: {}", error_text(&body)),
            b'Z' => break,
            _ => {}
        }
    }

    let mut q = Vec::new();
    cstr(&mut q, sql);
    stream.write_all(&message(b'Q', &q)).await?;
    let mut rows = Vec::new();
    loop {
        let (kind, body) = read_message(&mut stream).await?;
        match kind {
            b'D' => rows.push(data_row(&body)?),
            b'E' => bail!("query failed: {}", error_text(&body)),
            b'Z' => break,
            _ => {}
        }
    }
    stream.write_all(&message(b'X', &[])).await?;
    let _ = stream.shutdown().await;
    Ok(rows)
}

/// What `pg_flow` asks: who the enclave logged in as, and that the query ran.
const PG_QUERY: &str = "select current_user, 41 + 1";

/// A database session on a Postgres blob: one query (`PG_QUERY`), then close.
pub async fn pg_flow(client: &Client, blob: &str) -> anyhow::Result<Vec<Vec<String>>> {
    let sql = PG_QUERY;
    let s = client.session(blob).database().await.context("database session")?;
    step(&format!("database session {}: dsn {}", id(s.info()), s.dsn()));
    let rows = pg_query(s.dsn(), sql).await?;
    step(&format!("{sql} -> {rows:?}"));
    s.close().await.context("close the database session")?;
    step("database session closed");
    Ok(rows)
}

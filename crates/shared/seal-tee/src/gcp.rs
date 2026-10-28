//! GCP Confidential Space: attestation tokens from the launcher.
//!
//! The Confidential Space launcher serves `POST /v1/token` on a Unix socket it mounts into the
//! workload container. The attestor asks it for a custom token of type PKI with Seal's
//! audience (`seal_attest::gcp::AUDIENCE`) and the lowercase hex of the 32 report-data bytes
//! as its one nonce, which is what `seal_attest::gcp` verifies. The launcher answers with the
//! token as the whole response body.
//!
//! The image digest, and with it the measurement, is read once at construction from a token
//! requested with an all-zero nonce: the token is the only place the workload learns its own
//! digest. Every later token must name the same digest.
//!
//! `oidc_token` asks the same socket for an OIDC token for another audience (the guardian's
//! Cloud KMS key source exchanges it at Google STS); Seal never verifies those itself.
//!
//! Google allows 5 token requests per second per project and region; the enclave's periodic
//! attestation and the guardian's boot stay far below it.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use seal_proto::{Evidence, Measurement};

use crate::TeeError;

#[cfg(test)]
mod tests;

/// Where the launcher mounts its token server inside the container.
pub(crate) const TEESERVER_SOCKET: &str = "/run/container_launcher/teeserver.sock";

/// How long one token request may take (the launcher asks Google's attestation service).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response accepted. A PKI token with its three certificates is about 10 KiB.
const MAX_RESPONSE: usize = 64 * 1024;

/// Tokens from the launcher's socket: PKI tokens committing to the report data as their one
/// nonce, and OIDC tokens for other audiences.
pub struct ConfidentialSpaceAttestor {
    socket: PathBuf,
    image_digest: String,
    measurement: Measurement,
}

impl ConfidentialSpaceAttestor {
    /// From the launcher socket at `TEESERVER_SOCKET`; requests one token to learn the image
    /// digest. `Unavailable` when the launcher does not answer with a usable token.
    pub fn new() -> Result<Self, TeeError> {
        Self::at(Path::new(TEESERVER_SOCKET))
    }

    pub(crate) fn at(socket: &Path) -> Result<Self, TeeError> {
        let token = request_token(socket, &request_body(&[0; 32]))?;
        let image_digest = image_digest(&token)?;
        let measurement = seal_attest::gcp::measurement(&image_digest)
            .map_err(|e| TeeError::Unavailable(format!("confidential space: {e}")))?;
        Ok(Self { socket: socket.to_owned(), image_digest, measurement })
    }

    pub fn measurement(&self) -> Measurement {
        self.measurement
    }

    /// A PKI token for `report_data`.
    pub(crate) async fn attest(&self, report_data: [u8; 32]) -> Result<Evidence, TeeError> {
        let token = self.request(request_body(&report_data)).await?;
        if image_digest(&token)? != self.image_digest {
            return Err(TeeError::Unavailable("confidential space: the token names another image digest".into()));
        }
        Ok(Evidence::GcpConfidentialSpace { token })
    }

    /// An OIDC attestation token for `audience` (`token_type: OIDC`, no nonces), as the JWT
    /// text. `Unavailable` if the launcher refuses or answers with anything but a JWT.
    pub async fn oidc_token(&self, audience: &str) -> Result<String, TeeError> {
        self.request(oidc_request_body(audience)).await
    }

    /// One token request, on tokio's blocking pool.
    async fn request(&self, body: String) -> Result<String, TeeError> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || request_token(&socket, &body))
            .await
            .map_err(|e| unavailable(format!("token request: {e}")))?
    }
}

fn unavailable(msg: impl std::fmt::Display) -> TeeError {
    TeeError::Unavailable(format!("confidential space: {msg}"))
}

/// The request body: PKI, Seal's audience, one nonce.
pub(crate) fn request_body(report_data: &[u8; 32]) -> String {
    serde_json::json!({
        "audience": seal_attest::gcp::AUDIENCE,
        "token_type": "PKI",
        "nonces": [hex(report_data)],
    })
    .to_string()
}

/// The request body for an OIDC token: the caller's audience, no nonces.
pub(crate) fn oidc_request_body(audience: &str) -> String {
    serde_json::json!({ "audience": audience, "token_type": "OIDC" }).to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `POST /v1/token` with `body` over the socket; the response body is the token. Every
/// failure, the socket's included, is `Unavailable`.
fn request_token(socket: &Path, body: &str) -> Result<String, TeeError> {
    let io = |e: std::io::Error| unavailable(format!("{}: {e}", socket.display()));
    let mut stream = UnixStream::connect(socket).map_err(io)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT)).map_err(io)?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT)).map_err(io)?;
    let request = format!(
        "POST /v1/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).map_err(io)?;
    let mut response = Vec::new();
    stream.take(MAX_RESPONSE as u64 + 1).read_to_end(&mut response).map_err(io)?;
    if response.len() > MAX_RESPONSE {
        return Err(unavailable("response too large"));
    }
    let (status, body) = http::parse_response(&response).map_err(unavailable)?;
    let text = String::from_utf8(body).map_err(|_| unavailable("response is not UTF-8"))?;
    if status != 200 {
        let detail: String = text.chars().take(200).collect();
        return Err(unavailable(format!("launcher answered {status}: {}", detail.trim())));
    }
    let token = text.trim();
    // Three parts with a JSON object as payload; the signature is the recipient's to check.
    let payload = seal_crypto::jws::peek_payload(token).map_err(|_| unavailable("response is not a JWT"))?;
    if !serde_json::from_slice::<serde_json::Value>(&payload).is_ok_and(|v| v.is_object()) {
        return Err(unavailable("response is not a JWT"));
    }
    Ok(token.to_owned())
}

/// `submods.container.image_digest` of our own token, unverified: it came from the local
/// launcher and only selects which release evidence to load.
fn image_digest(token: &str) -> Result<String, TeeError> {
    let payload = seal_crypto::jws::peek_payload(token).map_err(|e| unavailable(format!("token: {e}")))?;
    let claims: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|_| unavailable("token payload is not JSON"))?;
    claims["submods"]["container"]["image_digest"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| unavailable("token has no image digest"))
}

/// Just enough HTTP/1.1 for one response on a connection the server closes: a status line,
/// headers, and a body framed by `Transfer-Encoding: chunked`, `Content-Length` or the end of
/// the stream.
pub(crate) mod http {
    pub(crate) fn parse_response(response: &[u8]) -> Result<(u16, Vec<u8>), String> {
        let end = find(response, b"\r\n\r\n").ok_or("response has no complete header")?;
        let head = std::str::from_utf8(&response[..end]).map_err(|_| "response header is not UTF-8")?;
        let rest = &response[end + 4..];
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let mut parts = status_line.splitn(3, ' ');
        let (Some(version), Some(code)) = (parts.next(), parts.next()) else {
            return Err("bad status line".into());
        };
        if !version.starts_with("HTTP/1.") || code.len() != 3 {
            return Err("bad status line".into());
        }
        let status: u16 = code.parse().map_err(|_| "bad status code")?;
        let (mut chunked, mut length) = (false, None);
        for line in lines {
            let (name, value) = line.split_once(':').ok_or("bad header line")?;
            let value = value.trim();
            if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value.eq_ignore_ascii_case("chunked");
                if !chunked {
                    return Err(format!("unsupported transfer encoding {value}"));
                }
            } else if name.eq_ignore_ascii_case("content-length") {
                let n: usize = value.parse().map_err(|_| "bad content length")?;
                if length.is_some_and(|l| l != n) {
                    return Err("conflicting content lengths".into());
                }
                length = Some(n);
            }
        }
        let body = if chunked {
            dechunk(rest)?
        } else if let Some(n) = length {
            rest.get(..n).ok_or("body shorter than its content length")?.to_vec()
        } else {
            rest.to_vec()
        };
        Ok((status, body))
    }

    fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        loop {
            let line_end = find(rest, b"\r\n").ok_or("truncated chunk size")?;
            let size_line = std::str::from_utf8(&rest[..line_end]).map_err(|_| "bad chunk size")?;
            let size_hex = size_line.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size_hex, 16).map_err(|_| "bad chunk size")?;
            rest = &rest[line_end + 2..];
            if size == 0 {
                return Ok(body);
            }
            let chunk = rest.get(..size).ok_or("truncated chunk")?;
            body.extend_from_slice(chunk);
            rest = rest.get(size..).and_then(|r| r.strip_prefix(b"\r\n")).ok_or("chunk not terminated")?;
        }
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }
}

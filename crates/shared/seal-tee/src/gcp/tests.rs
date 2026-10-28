//! The attestor against a fake launcher on a Unix socket, answering with tokens recorded on
//! live VMs (`seal-attest/tests/data/gcp`, sources in its README).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use seal_proto::Evidence;

use super::http::parse_response;
use super::{request_body, ConfidentialSpaceAttestor};
use crate::TeeError;

const TDX: &str = include_str!("../../../seal-attest/tests/data/gcp/tdx.jwt");
const TDX_DEBUG: &str = include_str!("../../../seal-attest/tests/data/gcp/tdx-debug.jwt");
const TDX_IMAGE: &str = "sha256:58c94f8c38b3cbda5a900479583caad991052559ffdb33d898eb8bf35cfbd6b6";

/// How the fake launcher answers one request.
#[derive(Clone)]
enum Answer {
    /// 200 with the token in chunks of this size, as the launcher (Go's net/http) does.
    Chunked(&'static str, usize),
    Status(u16, &'static str),
}

/// A launcher serving `answers` in order on a fresh socket; records each request.
struct Launcher {
    socket: PathBuf,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    _dir: TempDir,
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn launcher(answers: Vec<Answer>) -> Launcher {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("seal-tee-gcp-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("teeserver.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    std::thread::spawn(move || {
        for answer in answers {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            recorded.lock().unwrap().push((request_line.trim().to_owned(), String::from_utf8(body).unwrap()));
            let mut stream = reader.into_inner();
            let response = match answer {
                Answer::Chunked(token, size) => {
                    let mut r =
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                    for chunk in token.as_bytes().chunks(size) {
                        r.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                        r.extend_from_slice(chunk);
                        r.extend_from_slice(b"\r\n");
                    }
                    r.extend_from_slice(b"0\r\n\r\n");
                    r
                }
                Answer::Status(code, text) => {
                    format!("HTTP/1.1 {code} Bad\r\nContent-Length: {}\r\n\r\n{text}", text.len()).into_bytes()
                }
            };
            stream.write_all(&response).unwrap();
        }
    });
    Launcher { socket, requests, _dir: TempDir(dir) }
}

fn nonces(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(v["audience"], seal_attest::gcp::AUDIENCE);
    assert_eq!(v["token_type"], "PKI");
    assert_eq!(v.as_object().unwrap().len(), 3);
    v["nonces"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_owned()).collect()
}

#[test]
fn request_body_is_pki_with_one_hex_nonce() {
    let body = request_body(&std::array::from_fn(|i| i as u8));
    assert_eq!(nonces(&body), ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"]);
}

#[tokio::test]
async fn attests_through_the_launcher() {
    let l = launcher(vec![Answer::Chunked(TDX, 4096), Answer::Chunked(TDX, 1000)]);
    let attestor = ConfidentialSpaceAttestor::at(&l.socket).unwrap();
    assert_eq!(attestor.measurement(), seal_attest::gcp::measurement(TDX_IMAGE).unwrap());
    let evidence = attestor.attest([0xab; 32]).await.unwrap();
    assert_eq!(evidence, Evidence::GcpConfidentialSpace { token: TDX.to_owned() });
    let requests = l.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    for (line, _) in &requests {
        assert_eq!(line, "POST /v1/token HTTP/1.1");
    }
    assert_eq!(nonces(&requests[0].1), ["00".repeat(32)]);
    assert_eq!(nonces(&requests[1].1), ["ab".repeat(32)]);
}

#[tokio::test]
async fn a_token_for_another_image_is_refused() {
    let l = launcher(vec![Answer::Chunked(TDX, 4096), Answer::Chunked(TDX_DEBUG, 4096)]);
    let attestor = ConfidentialSpaceAttestor::at(&l.socket).unwrap();
    match attestor.attest([1; 32]).await {
        Err(TeeError::Unavailable(msg)) => assert!(msg.contains("another image digest"), "{msg}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn oidc_tokens_for_any_audience() {
    const AUDIENCE: &str = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q";
    // Any JWT text is passed through unverified; a recorded token stands in for an OIDC one.
    let l = launcher(vec![
        Answer::Chunked(TDX, 4096),
        Answer::Chunked(TDX_DEBUG, 1000),
        Answer::Status(400, "audience refused"),
        Answer::Status(200, "a.b.c"),
        Answer::Status(200, "e30.WzFd.c2ln"),
    ]);
    let attestor = ConfidentialSpaceAttestor::at(&l.socket).unwrap();
    assert_eq!(attestor.oidc_token(AUDIENCE).await.unwrap(), TDX_DEBUG);
    let body: serde_json::Value = serde_json::from_str(&l.requests.lock().unwrap()[1].1).unwrap();
    assert_eq!(body, serde_json::json!({"audience": AUDIENCE, "token_type": "OIDC"}));
    match attestor.oidc_token(AUDIENCE).await {
        Err(TeeError::Unavailable(msg)) => assert!(msg.contains("400") && msg.contains("audience refused"), "{msg}"),
        other => panic!("{other:?}"),
    }
    // Not base64url JSON, then a JSON array as payload: not JWTs.
    for _ in 0..2 {
        match attestor.oidc_token(AUDIENCE).await {
            Err(TeeError::Unavailable(msg)) => assert!(msg.contains("not a JWT"), "{msg}"),
            other => panic!("{other:?}"),
        }
    }
    // The launcher is gone.
    assert!(matches!(attestor.oidc_token(AUDIENCE).await, Err(TeeError::Unavailable(_))));
}

#[test]
fn launcher_errors_are_unavailable() {
    let l = launcher(vec![Answer::Status(400, "each nonce must be between 8 bytes and 88 bytes long")]);
    match ConfidentialSpaceAttestor::at(&l.socket) {
        Err(TeeError::Unavailable(msg)) => assert!(msg.contains("400") && msg.contains("each nonce"), "{msg}"),
        Err(e) => panic!("{e}"),
        Ok(_) => panic!("accepted an error answer"),
    }
    let l = launcher(vec![Answer::Status(200, "not a token")]);
    assert!(matches!(ConfidentialSpaceAttestor::at(&l.socket), Err(TeeError::Unavailable(_))));
    let missing = std::env::temp_dir().join("seal-tee-gcp-no-such-socket");
    assert!(matches!(ConfidentialSpaceAttestor::at(&missing), Err(TeeError::Unavailable(_))));
}

#[test]
fn http_framing() {
    let ok = |r: &[u8]| parse_response(r).unwrap();
    assert_eq!(ok(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef"), (200, b"abc".to_vec()));
    assert_eq!(ok(b"HTTP/1.1 200 OK\r\n\r\nto the end"), (200, b"to the end".to_vec()));
    assert_eq!(
        ok(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"),
        (200, b"abcde".to_vec())
    );
    assert_eq!(ok(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n").0, 404);
    for bad in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"[..],
        b"HTTP/2 200 OK\r\n\r\n",
        b"HTTP/1.1 20 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabX\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
    ] {
        assert!(parse_response(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
    }
}

proptest! {
    #[test]
    fn http_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_response(&bytes);
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        chunked.extend_from_slice(&bytes);
        let _ = parse_response(&chunked);
    }
}

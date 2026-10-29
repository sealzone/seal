//! `seal-tlog-dev`: the dev log (`seal_tlog::dev::DevLog`) over HTTP, routes as in that
//! module's docs. Development and tests only.
//!
//! ```text
//! seal-tlog-dev --dir DIR [--listen 127.0.0.1:7300] [--seed HEX32] [--witnesses 3] [--quorum 2]
//!               [--origin dev.log.seal.zone/v1]
//! ```
//!
//! The seed may come from `SEAL_TLOG_SEED` instead of `--seed`, which keeps it out of the
//! process's arguments (readable by every local user).
//!
//! `--origin` names the log in its checkpoints (a staging log served as `log.seal.zone` takes
//! `log.seal.zone/v1`); a log directory keeps the origin it was created with.
//!
//! Prints the log's origin, log key and witness keys (hex) on start, for the `TlogTrust`
//! of the components under test.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Serialize;

use seal_proto::release::{LogEntry, ReleaseConstraints};
use seal_proto::state::SignedTenantState;
use seal_proto::TenantId;
use seal_tlog::dev::DevLog;

type Log = Arc<Mutex<DevLog>>;

#[derive(Serialize)]
struct Index {
    index: u64,
}

fn refuse(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, msg.into()).into_response()
}

fn lock(log: &Log) -> std::sync::MutexGuard<'_, DevLog> {
    log.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn append(State(log): State<Log>, Json(entry): Json<LogEntry>) -> Response {
    match lock(&log).append(entry) {
        Ok(index) => Json(Index { index }).into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => refuse(StatusCode::BAD_REQUEST, e.to_string()),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn entry(State(log): State<Log>, Path(index): Path<u64>) -> Response {
    match lock(&log).entry(index) {
        Some(entry) => Json(entry).into_response(),
        None => refuse(StatusCode::NOT_FOUND, "no such entry"),
    }
}

async fn proof(State(log): State<Log>, Path(index): Path<u64>) -> Response {
    let mut log = lock(&log);
    if index >= log.size() {
        return refuse(StatusCode::NOT_FOUND, "no such entry");
    }
    Json(log.prove(index)).into_response()
}

async fn checkpoint(State(log): State<Log>) -> Response {
    Json(lock(&log).recent_checkpoint(seal_tlog::dev::CHECKPOINT_REUSE_SECS)).into_response()
}

async fn policy(State(log): State<Log>, Json(policy): Json<ReleaseConstraints>) -> Response {
    match lock(&log).set_policy(policy) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => refuse(StatusCode::CONFLICT, e),
    }
}

async fn state(State(log): State<Log>, Path(tenant): Path<TenantId>, Json(state): Json<SignedTenantState>) -> Response {
    if state.body.tenant != tenant {
        return refuse(StatusCode::BAD_REQUEST, "the state is for another tenant");
    }
    match lock(&log).append_state(&state) {
        Ok(index) => Json(Index { index }).into_response(),
        Err(e) => refuse(StatusCode::CONFLICT, e),
    }
}

async fn freshness(State(log): State<Log>, Path(tenant): Path<TenantId>) -> Response {
    match lock(&log).freshness(&tenant) {
        Some(statement) => Json(statement).into_response(),
        None => refuse(StatusCode::NOT_FOUND, "no logged state for this tenant"),
    }
}

/// The routes of the `seal_tlog::dev` module docs.
fn router(log: DevLog) -> Router {
    Router::new()
        .route("/v1/entries", post(append))
        .route("/v1/entries/{index}", get(entry))
        .route("/v1/proof/{index}", get(proof))
        .route("/v1/checkpoint", get(checkpoint))
        .route("/v1/policy", put(policy))
        .route("/v1/tenants/{tenant}/states", post(state))
        .route("/v1/tenants/{tenant}/freshness", get(freshness))
        .with_state(Arc::new(Mutex::new(log)))
}

struct Args {
    dir: PathBuf,
    listen: String,
    seed: [u8; 32],
    witnesses: usize,
    quorum: usize,
    origin: String,
}

fn parse_seed(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.is_ascii() {
        return Err("--seed takes 64 hex digits".into());
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "--seed takes 64 hex digits")?;
    }
    Ok(seed)
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        dir: PathBuf::new(),
        listen: "127.0.0.1:7300".into(),
        seed: [0; 32],
        witnesses: 3,
        quorum: 2,
        origin: seal_tlog::dev::ORIGIN.into(),
    };
    if let Some(seed) = std::env::var("SEAL_TLOG_SEED").ok().filter(|s| !s.is_empty()) {
        args.seed = parse_seed(&seed)?;
    }
    let mut dir = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--dir" => dir = Some(PathBuf::from(value()?)),
            "--listen" => args.listen = value()?,
            "--seed" => args.seed = parse_seed(&value()?)?,
            "--witnesses" => args.witnesses = value()?.parse().map_err(|_| "--witnesses takes a number")?,
            "--quorum" => args.quorum = value()?.parse().map_err(|_| "--quorum takes a number")?,
            "--origin" => args.origin = value()?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    args.dir = dir.ok_or("--dir is required")?;
    Ok(args)
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("seal-tlog-dev: {e}\nusage: seal-tlog-dev --dir DIR [--listen ADDR] [--seed HEX32] [--witnesses N] [--quorum M] [--origin ORIGIN]");
            std::process::exit(2);
        }
    };
    let log =
        DevLog::open_with_origin(&args.dir, args.seed, args.witnesses, args.quorum, &args.origin).unwrap_or_else(|e| {
            eprintln!("seal-tlog-dev: cannot open {}: {e}", args.dir.display());
            std::process::exit(1);
        });
    let trust = log.trust();
    println!("origin {}", trust.origin);
    println!("log key {}", trust.log_key);
    for key in &trust.witness_keys {
        println!("witness key {key}");
    }
    println!("witness quorum {}", trust.witness_quorum);

    let app = router(log);
    let listener = tokio::net::TcpListener::bind(&args.listen).await.unwrap_or_else(|e| {
        eprintln!("seal-tlog-dev: cannot listen on {}: {e}", args.listen);
        std::process::exit(1);
    });
    println!("listening on {}", args.listen);
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("seal-tlog-dev: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use seal_proto::release::{Component, ReleaseManifest};
    use seal_proto::{Measurement, PlatformId, ServiceKeyVersion};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn manifest(n: u8) -> LogEntry {
        LogEntry::Release(ReleaseManifest {
            component: Component::Enclave,
            platform: PlatformId::Sim,
            measurement: Measurement([n; 48]),
            service_key_version: ServiceKeyVersion(1),
            version: "0.1.0".into(),
            source_commit: "abc".into(),
            serves: None,
        })
    }

    /// One HTTP/1.1 GET; the status and body.
    async fn get(addr: std::net::SocketAddr, path: &str) -> (u16, Vec<u8>) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let status = std::str::from_utf8(&response[9..12]).unwrap().parse().unwrap();
        (status, response[split + 4..].to_vec())
    }

    #[tokio::test]
    async fn entries_are_served_by_index() {
        let dir = std::env::temp_dir().join(format!("seal-tlog-dev-bin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut log = DevLog::open(&dir, [7; 32], 3, 2).unwrap();
        log.append(manifest(1)).unwrap();
        log.append(manifest(2)).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(log)).await });

        for (index, expected) in [(0, manifest(1)), (1, manifest(2))] {
            let (status, body) = get(addr, &format!("/v1/entries/{index}")).await;
            assert_eq!(status, 200);
            assert_eq!(serde_json::from_slice::<LogEntry>(&body).unwrap(), expected);
        }
        assert_eq!(get(addr, "/v1/entries/2").await.0, 404);
        assert_eq!(get(addr, &format!("/v1/entries/{}", u64::MAX)).await.0, 404);
        assert_eq!(get(addr, "/v1/entries/x").await.0, 400);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

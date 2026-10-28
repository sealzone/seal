//! HTTP surface, plain HTTP behind an untrusted TLS-terminating proxy (see `client`):
//! - `GET /v1/challenge` → `GuardianChallenge` (stateless; any instance verifies it).
//! - `POST /v1/keys`: `KeyRequest` → `KeyResponse`; any denial → 403 `{"error":"denied"}`,
//!   details only in the guardian's log.
//! - `GET /v1/wrap-keys/{tenant}/{root_id}/{tenant_key_version}` → `SignedTenantWrapKey`
//!   (public; the control plane fetches these for `TenantBundle::wrap_keys`).
//! - `POST /v1/anchors/{tenant}/{root_id}`: `TenantBundle` → `SignedTenantAnchor` (public; the
//!   control plane asks for one so bundles carry only the states from it on); a bundle that does
//!   not verify → 403 `denied`.
//! - `GET /v1/identity?challenge=<b64url>` → `{"platform", "runs_on", "guardian_key", "evidence"}`:
//!   the guardian's own evidence, whose report data is
//!   `labeled_digest(GUARDIAN_IDENTITY_LABEL, (challenge, platform, guardian_key))`.
//!   Run once when a platform root is created to publish the guardian key that SDKs and
//!   enclaves compile into `seal_verify::Trust::guardians`; anyone can repeat it.
//!
//! Bodies are JSON. Other failures: 400 `{"error":"bad_request"}` (malformed request, body
//! over `MAX_REQUEST_BODY`), 404 `{"error":"not_found"}`, 503 `{"error":"unavailable"}` (the
//! clock or the TEE did not answer). HTTP/1.1 only; request headers must arrive within
//! `READ_TIMEOUT`, and so must the body.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use seal_proto::release::KeyRequest;
use seal_proto::{TenantId, TenantKeyVersion, TenantRootId};
use serde::Serialize;

use crate::{Guardian, GuardianError};

/// Largest request body accepted: evidence, release evidence and a tenant bundle.
pub const MAX_REQUEST_BODY: usize = 4 << 20;
/// Time for a request's headers, and separately for its body, to arrive.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Accepts connections on `listener` and serves each on its own task. Returns only if the
/// listener fails for good; a failed accept (e.g. out of file descriptors) is logged and retried.
pub async fn serve(guardian: Arc<Guardian>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let guardian = guardian.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let guardian = guardian.clone();
                async move { Ok::<_, Infallible>(respond(&guardian, req).await) }
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(READ_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service);
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "connection ended");
            }
        });
    }
}

/// One request → one response. Never fails: every error becomes its status and JSON body.
async fn respond(guardian: &Guardian, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(&path).split('/').collect();
    match (req.method(), segments.as_slice()) {
        (&Method::GET, ["v1", "challenge"]) => json(StatusCode::OK, &guardian.challenge()),
        (&Method::POST, ["v1", "keys"]) => {
            let Some(body) = read_body(req.into_body()).await else {
                return error(StatusCode::BAD_REQUEST, "bad_request");
            };
            let Ok(key_request) = serde_json::from_slice::<KeyRequest>(&body) else {
                return error(StatusCode::BAD_REQUEST, "bad_request");
            };
            match guardian.handle(key_request).await {
                Ok(resp) => json(StatusCode::OK, &resp),
                Err(e) => guardian_error(&e),
            }
        }
        (&Method::GET, ["v1", "wrap-keys", tenant, root_id, version]) => {
            let (Ok(tenant), Ok(root_id), Ok(version)) =
                (tenant.parse::<TenantId>(), root_id.parse::<TenantRootId>(), version.parse::<u32>())
            else {
                return error(StatusCode::BAD_REQUEST, "bad_request");
            };
            json(StatusCode::OK, &guardian.wrap_key(&tenant, &root_id, TenantKeyVersion(version)))
        }
        (&Method::POST, ["v1", "anchors", tenant, root_id]) => {
            let (Ok(tenant), Ok(root_id)) = (tenant.parse::<TenantId>(), root_id.parse::<TenantRootId>()) else {
                return error(StatusCode::BAD_REQUEST, "bad_request");
            };
            let Some(body) = read_body(req.into_body()).await else {
                return error(StatusCode::BAD_REQUEST, "bad_request");
            };
            let Ok(bundle) = serde_json::from_slice::<seal_proto::state::TenantBundle>(&body) else {
                return error(StatusCode::BAD_REQUEST, "bad_request");
            };
            match guardian.anchor(&tenant, &root_id, &bundle).await {
                Ok(anchor) => json(StatusCode::OK, &anchor),
                Err(e) => guardian_error(&e),
            }
        }
        (&Method::GET, ["v1", "identity"]) => {
            let Some(challenge) = identity_challenge(query.as_deref()) else {
                return error(StatusCode::BAD_REQUEST, "bad_request");
            };
            match guardian.identity(challenge).await {
                Ok(identity) => json(StatusCode::OK, &identity),
                Err(e) => guardian_error(&e),
            }
        }
        _ => error(StatusCode::NOT_FOUND, "not_found"),
    }
}

/// The body, unless it is larger than `MAX_REQUEST_BODY`, fails or takes over `READ_TIMEOUT`.
async fn read_body(body: Incoming) -> Option<Bytes> {
    let collect = Limited::new(body, MAX_REQUEST_BODY).collect();
    match tokio::time::timeout(READ_TIMEOUT, collect).await {
        Ok(Ok(collected)) => Some(collected.to_bytes()),
        _ => None,
    }
}

/// `challenge=<b64url of 32 bytes>`, the only parameter.
fn identity_challenge(query: Option<&str>) -> Option<[u8; 32]> {
    let value = query?.strip_prefix("challenge=")?;
    seal_proto::codec::from_b64url(value).ok()?.try_into().ok()
}

/// Denials (and evidence that does not verify) → 403 `denied`; the reason was logged by
/// `Guardian::handle`. Everything else the guardian can fail with is a dependency → 503.
fn guardian_error(e: &GuardianError) -> Response<Full<Bytes>> {
    match e {
        GuardianError::Denied(_) | GuardianError::Evidence(_) | GuardianError::Refused => {
            error(StatusCode::FORBIDDEN, "denied")
        }
        GuardianError::Tee(_) | GuardianError::Root(_) | GuardianError::Unavailable(_) => {
            tracing::warn!(error = %e, "request failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).expect("guardian responses serialize to JSON");
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    resp
}

fn error(status: StatusCode, code: &str) -> Response<Full<Bytes>> {
    json(status, &serde_json::json!({ "error": code }))
}

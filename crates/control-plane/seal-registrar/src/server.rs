//! The registrar's HTTP API (JSON). Every route but the public key needs
//! `Authorization: Bearer <API token>`; only the console holds the token, and the registrar is
//! reachable only inside Seal's network.
//!
//! - `POST /v1/roots`: `{"tenant", "admin_key": AdminKey}` → 200 `Registered`
//!   (`{"root_id", "key_id", "log_index"}`): root version 1 of `tenant` with `admin_key` its
//!   only admin, threshold 1, signed, logged and stored on the control plane. Repeating the
//!   same request answers the same; another key for a taken id is refused.
//! - `GET /v1/key` → `{"public_key": "<hex>"}`, the key that signs every root version 1.
//!
//! Refusals answer `{"message": "..."}`: 400 (malformed body), 401 (missing or wrong API
//! token), 403 (refused: the message is safe to show the user, e.g. a taken id or a passkey
//! for another RP ID), 503 (the log, the control plane or the ledger failed; retry).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use seal_proto::state::AdminKey;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{Registrar, RegistrarError};

pub struct App {
    registrar: Registrar,
    /// SHA-256 of the API token, compared in constant time.
    token_digest: [u8; 32],
}

impl App {
    pub fn new(registrar: Registrar, api_token: &str) -> Self {
        Self { registrar, token_digest: digest(api_token) }
    }

    pub(crate) fn authorized(&self, headers: &HeaderMap) -> bool {
        let given = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();
        bool::from(digest(given).ct_eq(&self.token_digest))
    }
}

fn digest(s: &str) -> [u8; 32] {
    seal_proto::codec::digest(&s)
}

#[derive(Serialize)]
struct Message {
    message: String,
}

fn reply(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(Message { message: message.into() })).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRoot {
    tenant: String,
    admin_key: AdminKey,
}

async fn create_root(State(app): State<Arc<App>>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    if !app.authorized(&headers) {
        return reply(StatusCode::UNAUTHORIZED, "missing or wrong API token");
    }
    let req: CreateRoot = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return reply(StatusCode::BAD_REQUEST, format!("expected {{ tenant, admin_key }}: {e}")),
    };
    match app.registrar.create_root(&req.tenant, req.admin_key).await {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(RegistrarError::Refused(m)) => reply(StatusCode::FORBIDDEN, m),
        Err(RegistrarError::Unavailable(d)) => {
            tracing::warn!(detail = %d, "registration failed");
            reply(StatusCode::SERVICE_UNAVAILABLE, "an upstream is unavailable; try again")
        }
    }
}

#[derive(Serialize)]
struct Key {
    public_key: String,
}

/// The registrar's public key, for configuring verifiers. Public by design.
async fn key(State(app): State<Arc<App>>) -> Json<Key> {
    Json(Key { public_key: app.registrar.public_key().to_string() })
}

pub fn router(app: Arc<App>) -> Router {
    Router::new().route("/v1/roots", post(create_root)).route("/v1/key", get(key)).with_state(app)
}

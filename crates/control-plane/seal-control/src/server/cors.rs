//! CORS for the console's web UI, and for no other origin. A request whose `Origin` is the
//! configured one gets `Access-Control-Allow-Origin` with that origin, and its preflight is
//! answered here; requests from any other origin get no CORS headers, so browsers refuse
//! them, and their preflights reach the router (405). Credentials travel in `Authorization`,
//! never in cookies, so credentialed CORS is not allowed.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

const ALLOW_METHODS: &str = "GET, PUT, POST, DELETE";
const ALLOW_HEADERS: &str = "authorization, content-type";
/// How long a browser may cache a preflight answer.
const MAX_AGE_SECS: &str = "600";

pub async fn cors(State(origin): State<Option<Arc<str>>>, request: Request, next: Next) -> Response {
    let Some(origin) = origin else {
        return next.run(request).await;
    };
    let from_console = request.headers().get(header::ORIGIN).is_some_and(|o| o.as_bytes() == origin.as_bytes());
    let allow = HeaderValue::from_str(&origin).ok().filter(|_| from_console);
    let mut response = match &allow {
        Some(allow)
            if request.method() == Method::OPTIONS
                && request.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD) =>
        {
            let mut preflight = StatusCode::NO_CONTENT.into_response();
            let headers = preflight.headers_mut();
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow.clone());
            headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static(ALLOW_METHODS));
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static(ALLOW_HEADERS));
            headers.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static(MAX_AGE_SECS));
            preflight
        }
        Some(allow) => {
            let mut response = next.run(request).await;
            response.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow.clone());
            response
        }
        None => next.run(request).await,
    };
    // Answers differ by origin, so caches must key on it.
    response.headers_mut().append(header::VARY, HeaderValue::from_static("origin"));
    response
}

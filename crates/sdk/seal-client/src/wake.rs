//! Waking the tenant's Seal-hosted replicas. They stop when idle, so the first call after a
//! quiet period finds no replica listening. When some endpoint is Seal-hosted
//! (`<tenant>.enclave.seal.zone`), the SDK then POSTs `{"tenant": "<id>"}` to `WAKE_URL`,
//! without credentials, and keeps trying the endpoints with backoff for up to
//! `WAKE_WAIT_SECS`. There is nothing to configure: customers' own replicas never idle out,
//! so clients that list only those never call Seal. Nothing about verification changes:
//! whatever answers is verified and pinned as on any other call. Sim builds take
//! `SEAL_WAKE_URL` instead, for a local stand-in.
//!
//! `WAKE_URL` only ever starts the tenant's stopped hosted replicas. It answers `202` (starting), `200` (already running), `404` (no hosted
//! replicas: the SDK gives up at once) or `429` (rate limited: a start is already under way).

use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use seal_proto::TenantId;

use crate::ClientError;

/// Where the SDK asks Seal to start the tenant's hosted replicas.
pub const WAKE_URL: &str = "https://console.seal.zone/api/v1/wake";
/// Seal-hosted replicas are `<tenant>.HOSTED_SUFFIX`.
pub const HOSTED_SUFFIX: &str = "enclave.seal.zone";

/// The wake URL for a client of `endpoints`: `WAKE_URL` when one of them is Seal-hosted, else
/// none. Sim builds use `SEAL_WAKE_URL` instead, when it is set.
pub(crate) fn url_for(endpoints: &[url::Url]) -> Result<Option<url::Url>, ClientError> {
    if cfg!(feature = "sim") {
        if let Some(text) = std::env::var("SEAL_WAKE_URL").ok().filter(|t| !t.trim().is_empty()) {
            return url::Url::parse(text.trim())
                .map(Some)
                .map_err(|e| ClientError::Invalid(format!("SEAL_WAKE_URL {text}: {e}")));
        }
    }
    Ok(endpoints.iter().any(is_hosted).then(|| url::Url::parse(WAKE_URL).expect("a valid URL")))
}

/// Whether `endpoint` is a Seal-hosted replica: `https://<tenant>.enclave.seal.zone[:port]`.
fn is_hosted(endpoint: &url::Url) -> bool {
    let host = endpoint.host_str().unwrap_or_default().to_ascii_lowercase();
    host.strip_suffix(HOSTED_SUFFIX)
        .and_then(|tenant| tenant.strip_suffix('.'))
        .is_some_and(|tenant| !tenant.is_empty() && !tenant.contains('.'))
}

/// How long the SDK keeps trying to reach a replica after asking the wake URL to start the
/// tenant's replicas: a stopped Confidential Space VM serves again after about a minute.
pub const WAKE_WAIT_SECS: u64 = 120;

/// The first wait between attempts, doubled up to `MAX_RETRY` each time.
const FIRST_RETRY: Duration = Duration::from_secs(2);
const MAX_RETRY: Duration = Duration::from_secs(15);
/// One POST to the wake URL.
const WAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// One pass over the tenant's endpoints.
pub(crate) enum Pass<T> {
    /// A replica answered; this is its result.
    Answered(Result<T, ClientError>),
    /// None accepted a connection.
    Unreachable(ClientError),
}

/// The wake URL of one client, and its last request.
pub(crate) struct Waker {
    url: url::Url,
    tenant: TenantId,
    /// When the last request went out, and whether it said to wait.
    last: Mutex<Option<(Instant, bool)>>,
}

impl Waker {
    /// `url` must be `https://` (sim builds also take `http://`, for a local stand-in).
    pub(crate) fn new(url: url::Url, tenant: TenantId) -> Result<Self, ClientError> {
        let allowed = url.scheme() == "https" || (cfg!(feature = "sim") && url.scheme() == "http");
        if !allowed || url.host_str().is_none() {
            return Err(ClientError::Invalid(format!("wake URL {url} is not an https:// URL")));
        }
        Ok(Self { url, tenant, last: Mutex::new(None) })
    }

    /// Asks the wake URL to start the tenant's replicas, at most once per `WAKE_WAIT_SECS` for
    /// this client. Returns whether waiting can help: `false` when the endpoint says the tenant
    /// has no hosted replicas.
    async fn request(&self) -> bool {
        let window = Duration::from_secs(WAKE_WAIT_SECS);
        if let Some((at, wait)) = *self.last.lock().unwrap_or_else(|e| e.into_inner()) {
            if at.elapsed() < window {
                return wait;
            }
        }
        let body = serde_json::json!({ "tenant": self.tenant.as_str() }).to_string().into_bytes();
        let wait = match self.post(body).await {
            Ok(404) => false,
            Ok(status) => {
                tracing::info!(url = %self.url, status, "asked to start the tenant's hosted replicas");
                true
            }
            Err(e) => {
                tracing::warn!(url = %self.url, error = %e, "the wake request failed; still retrying");
                true
            }
        };
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), wait));
        wait
    }

    async fn post(&self, body: Vec<u8>) -> Result<u16, ClientError> {
        let headers = [("content-type", "application/json"), ("accept", "application/json")];
        if self.url.scheme() == "http" {
            let posted =
                crate::transport::plain(hyper::Method::POST, self.url.as_str(), &headers, Some(body), WAKE_TIMEOUT);
            return posted.await.map(|(status, _)| status);
        }
        let https = crate::admin::https();
        let posted = https.post(self.url.as_str(), &headers, &body).await;
        posted.map(|(status, _)| status).map_err(|e| ClientError::Network(e.to_string()))
    }
}

/// After `missed` (no endpoint reachable): asks `waker` to start the tenant's replicas, then
/// runs `attempt` with backoff until a replica answers or `WAKE_WAIT_SECS` pass. Without a
/// waker, or when the tenant has no hosted replicas, `missed` is the answer.
pub(crate) async fn retry_after_wake<T, F, Fut>(
    waker: Option<&Waker>,
    missed: ClientError,
    mut attempt: F,
) -> Result<T, ClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Pass<T>>,
{
    let Some(waker) = waker else { return Err(missed) };
    if !waker.request().await {
        return Err(missed);
    }
    let deadline = Instant::now() + Duration::from_secs(WAKE_WAIT_SECS);
    let mut delay = FIRST_RETRY;
    loop {
        tokio::time::sleep(delay.min(deadline.saturating_duration_since(Instant::now()))).await;
        match attempt().await {
            Pass::Answered(result) => return result,
            Pass::Unreachable(e) if Instant::now() >= deadline => {
                return Err(ClientError::Network(format!(
                    "no enclave replica answered within {WAKE_WAIT_SECS} s of asking {} to start them: {e}",
                    waker.url
                )))
            }
            Pass::Unreachable(_) => delay = (delay * 2).min(MAX_RETRY),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A wake endpoint answering `status`; records each request.
    async fn endpoint(status: u16) -> (url::Url, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = url::Url::parse(&format!("http://{}/api/v1/wake", listener.local_addr().unwrap())).unwrap();
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let record = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { return };
                let mut got = Vec::new();
                let mut buf = [0u8; 1024];
                while !String::from_utf8_lossy(&got).contains("{\"tenant\"") || !got.ends_with(b"}") {
                    let n = s.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                record.lock().unwrap().push(String::from_utf8(got).unwrap());
                let reply = format!("HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                s.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        (url, seen)
    }

    fn acme() -> TenantId {
        TenantId::new("acme").unwrap()
    }

    #[test]
    fn only_seal_hosted_endpoints_wake() {
        let urls = |list: &[&str]| list.iter().map(|s| url::Url::parse(s).unwrap()).collect::<Vec<_>>();
        let wake = |list: &[&str]| url_for(&urls(list)).unwrap().map(|u| u.to_string());
        if cfg!(feature = "sim") && std::env::var_os("SEAL_WAKE_URL").is_some() {
            return;
        }
        assert_eq!(wake(&["https://10.0.1.4:8443", "https://acme.enclave.seal.zone:8443"]).as_deref(), Some(WAKE_URL));
        assert_eq!(wake(&["https://ACME.Enclave.Seal.Zone"]).as_deref(), Some(WAKE_URL));
        for not_hosted in [
            "https://10.0.1.4:8443",
            "https://enclave.seal.zone",
            "https://a.b.enclave.seal.zone",
            "https://acme.enclave.seal.zone.evil.example",
            "https://acmeenclave.seal.zone",
            "https://localhost:8443",
        ] {
            assert_eq!(wake(&[not_hosted]), None, "{not_hosted}");
        }
    }

    #[test]
    fn wake_urls_are_https() {
        let url = |s: &str| url::Url::parse(s).unwrap();
        assert!(Waker::new(url("https://console.seal.zone/api/v1/wake"), acme()).is_ok());
        assert!(Waker::new(url("ftp://console.seal.zone/"), acme()).is_err());
        assert_eq!(Waker::new(url("http://127.0.0.1:1/wake"), acme()).is_ok(), cfg!(feature = "sim"));
    }

    #[tokio::test]
    async fn without_a_waker_or_hosted_replicas_the_miss_stands() {
        let tries = AtomicUsize::new(0);
        let attempt = || async {
            tries.fetch_add(1, Ordering::Relaxed);
            Pass::<()>::Unreachable(ClientError::Network("down".into()))
        };
        let missed = || ClientError::Network("first".into());
        let err = retry_after_wake(None, missed(), attempt).await.unwrap_err();
        assert!(matches!(err, ClientError::Network(m) if m == "first"));
        if !cfg!(feature = "sim") {
            return;
        }
        let (url, seen) = endpoint(404).await;
        let waker = Waker::new(url, acme()).unwrap();
        let err = retry_after_wake(Some(&waker), missed(), attempt).await.unwrap_err();
        assert!(matches!(err, ClientError::Network(m) if m == "first"));
        assert_eq!(tries.load(Ordering::Relaxed), 0);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn posts_the_tenant_once_and_retries_until_a_replica_answers() {
        if !cfg!(feature = "sim") {
            return;
        }
        let (url, seen) = endpoint(202).await;
        let waker = Waker::new(url, acme()).unwrap();
        let tries = AtomicUsize::new(0);
        let attempt = || async {
            match tries.fetch_add(1, Ordering::Relaxed) {
                0 => Pass::Unreachable(ClientError::Network("booting".into())),
                _ => Pass::Answered(Ok(7)),
            }
        };
        let missed = ClientError::Network("down".into());
        assert_eq!(retry_after_wake(Some(&waker), missed, attempt).await.unwrap(), 7);
        assert_eq!(tries.load(Ordering::Relaxed), 2);
        // Another miss soon after waits without asking again.
        let answered = || async { Pass::Answered(Ok(8)) };
        assert_eq!(retry_after_wake(Some(&waker), ClientError::Network("down".into()), answered).await.unwrap(), 8);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let request = seen[0].to_ascii_lowercase();
        assert!(request.starts_with("post /api/v1/wake http/1.1\r\n"), "{request}");
        assert!(request.contains("content-type: application/json\r\n"));
        assert!(!request.contains("authorization"));
        assert!(request.ends_with("\r\n\r\n{\"tenant\":\"acme\"}"), "{request}");
    }

    #[tokio::test]
    async fn an_answer_ends_the_wait() {
        if !cfg!(feature = "sim") {
            return;
        }
        let (url, _) = endpoint(202).await;
        let waker = Waker::new(url, acme()).unwrap();
        // A replica that answers with a refusal: that is the result, no more retries.
        let refused = || async {
            Pass::<()>::Answered(Err(ClientError::Seal {
                code: seal_proto::ErrorCode::NotAllowed,
                message: "no".into(),
            }))
        };
        let err = retry_after_wake(Some(&waker), ClientError::Network("down".into()), refused).await.unwrap_err();
        assert_eq!(err.code(), seal_proto::ErrorCode::NotAllowed);
    }
}

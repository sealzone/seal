//! Riding out replicas that do not answer. When a pass over the tenant's endpoints reaches none
//! of them (no TCP connection and TLS handshake within `transport::CONNECT_TIMEOUT`, or, when
//! verifying, no attestation served), the SDK repeats the pass with backoff, 2 s doubling to 15 s,
//! for up to `UNREACHABLE_WAIT_SECS`. That covers a replica restarting and a Seal-hosted
//! replica cold-starting: Seal's front door starts a stopped one on the connection and holds it
//! until the replica serves. Every client does this, whatever its endpoints are.
//!
//! A replica that answers ends the wait with its answer: a failed verification, a key other
//! than the attested one or an error code from the enclave is the result, never retried.
//! An API request is retried only when no connection was made, so none is sent twice.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use crate::ClientError;

/// How long the SDK keeps retrying when no replica is reachable: a stopped Seal-hosted
/// replica serves again after about a minute.
pub const UNREACHABLE_WAIT_SECS: u64 = 120;

/// The first wait between passes, doubled up to `MAX_RETRY` each time.
const FIRST_RETRY: Duration = Duration::from_secs(2);
const MAX_RETRY: Duration = Duration::from_secs(15);

/// One pass over the tenant's endpoints.
pub(crate) enum Pass<T> {
    /// A replica answered; this is its result.
    Answered(Result<T, ClientError>),
    /// None was reachable.
    Unreachable(ClientError),
}

/// After `missed` (a pass that reached no replica): runs `attempt` with backoff until a
/// replica answers, or fails with `Network` once `UNREACHABLE_WAIT_SECS` have passed.
pub(crate) async fn while_unreachable<T, F, Fut>(missed: ClientError, mut attempt: F) -> Result<T, ClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Pass<T>>,
{
    tracing::info!(error = %missed, "no enclave replica reachable; retrying for up to {UNREACHABLE_WAIT_SECS} s");
    let deadline = Instant::now() + Duration::from_secs(UNREACHABLE_WAIT_SECS);
    let mut delay = FIRST_RETRY;
    loop {
        tokio::time::sleep(delay.min(deadline.saturating_duration_since(Instant::now()))).await;
        match attempt().await {
            Pass::Answered(result) => return result,
            Pass::Unreachable(e) if Instant::now() >= deadline => {
                return Err(ClientError::Network(format!(
                    "no enclave replica reachable within {UNREACHABLE_WAIT_SECS} s: {e}"
                )))
            }
            Pass::Unreachable(e) => {
                tracing::debug!(error = %e, "no enclave replica reachable yet");
                delay = (delay * 2).min(MAX_RETRY);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn down() -> ClientError {
        ClientError::Network("down".into())
    }

    #[tokio::test(start_paused = true)]
    async fn retries_with_backoff_until_a_replica_answers() {
        let start = Instant::now();
        let tries: Mutex<Vec<u64>> = Mutex::default();
        let attempt = || async {
            let mut tries = tries.lock().unwrap();
            tries.push(start.elapsed().as_secs());
            match tries.len() {
                1..=4 => Pass::Unreachable(down()),
                _ => Pass::Answered(Ok(7)),
            }
        };
        assert_eq!(while_unreachable(down(), attempt).await.unwrap(), 7);
        assert_eq!(*tries.lock().unwrap(), [2, 6, 14, 29, 44]);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_the_wait() {
        let start = Instant::now();
        let err = while_unreachable(down(), || async { Pass::<()>::Unreachable(down()) }).await.unwrap_err();
        assert_eq!(start.elapsed(), Duration::from_secs(UNREACHABLE_WAIT_SECS));
        assert_eq!(err.code(), seal_proto::ErrorCode::Unavailable);
        assert!(err.to_string().contains("within 120 s: network: down"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_ends_the_wait() {
        let start = Instant::now();
        // A replica that answers with a refusal: that is the result, no more retries.
        let refused = || async {
            Pass::<()>::Answered(Err(ClientError::Seal {
                code: seal_proto::ErrorCode::NotAllowed,
                message: "no".into(),
            }))
        };
        let err = while_unreachable(down(), refused).await.unwrap_err();
        assert_eq!(err.code(), seal_proto::ErrorCode::NotAllowed);
        assert_eq!(start.elapsed(), FIRST_RETRY);
    }
}

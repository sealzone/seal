//! Cancel requests. A relayed connection's client gets a `BackendKeyData` of the adapter's own:
//! a random process ID and secret key (63 random bits together), never the upstream's. A
//! `CancelRequest` naming that pair, on a new connection to the same replica while the relayed
//! connection lives, is passed to the session's `observe` (action `CANCEL`) and then sent as a
//! `CancelRequest` with the upstream's own key, over a new verified TLS connection to the
//! session's destination. Any other pair is closed without a reply, as Postgres does. So a
//! client cancels only queries of a connection whose key it was given, and the upstream's key
//! never leaves the enclave.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::Rng as _;
use seal_adapter::{
    AdapterError, Completion, Observation, Outcome, Session, UpstreamConnector, UpstreamErrorKind, Verdict,
};
use seal_proto::policy::Protocol;
use seal_proto::ErrorCode;
use tokio::io::AsyncWriteExt;

use crate::wire;

/// `Completion::action` of a cancel request.
pub const CANCEL: &str = "CANCEL";

/// The relayed connections of one adapter, by the key their clients were given.
#[derive(Default)]
pub struct Cancels {
    targets: Mutex<HashMap<(i32, i32), Target>>,
}

struct Target {
    session: Arc<dyn Session>,
    /// The upstream's `BackendKeyData`.
    pid: i32,
    key: i32,
}

impl std::fmt::Debug for Cancels {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Cancels").field("connections", &self.targets().len()).finish()
    }
}

/// A registered connection: the key its client gets. Dropping it unregisters the connection.
pub struct Registration {
    cancels: Arc<Cancels>,
    pub pid: i32,
    pub key: i32,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.cancels.targets().remove(&(self.pid, self.key));
    }
}

impl Cancels {
    fn targets(&self) -> std::sync::MutexGuard<'_, HashMap<(i32, i32), Target>> {
        self.targets.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers a relayed connection whose upstream sent `BackendKeyData` (`pid`, `key`) and
    /// returns the fresh key its client gets instead.
    pub fn register(self: &Arc<Self>, session: Arc<dyn Session>, pid: i32, key: i32) -> Registration {
        let mut rng = UnwrapErr(SysRng);
        let mut targets = self.targets();
        loop {
            // A positive process ID, as clients expect one.
            let client = (rng.next_u32() as i32 & i32::MAX, rng.next_u32() as i32);
            if client.0 != 0 && !targets.contains_key(&client) {
                targets.insert(client, Target { session, pid, key });
                return Registration { cancels: self.clone(), pid: client.0, key: client.1 };
            }
        }
    }

    /// Serves a `CancelRequest` for the client key (`pid`, `key`): refused (`NotAllowed`) when
    /// no live connection has it, otherwise sent upstream with that connection's key.
    pub async fn cancel(&self, pid: i32, key: i32, upstream: &dyn UpstreamConnector) -> Result<(), AdapterError> {
        let found = self.targets().get(&(pid, key)).map(|t| (t.session.clone(), t.pid, t.key));
        let Some((session, upstream_pid, upstream_key)) = found else {
            return Err(AdapterError::Denied(ErrorCode::NotAllowed));
        };
        let complete = |outcome: Outcome, bytes_up: u64| {
            let action = CANCEL.to_string();
            session.complete(Completion { protocol: Protocol::Postgres, action, outcome, bytes_up, bytes_down: 0 });
        };
        let observation = Observation { protocol: Protocol::Postgres, action: CANCEL, content: b"" };
        if let Verdict::Refuse(code) | Verdict::End(code) = session.observe(&observation) {
            complete(Outcome::Denied(code), 0);
            return Err(AdapterError::Denied(code));
        }
        let policy = session.policy();
        let send = async {
            let mut stream = upstream.connect(policy.destination(), policy.pins()).await.map_err(|e| {
                if e.code() == ErrorCode::PolicyDenied {
                    UpstreamErrorKind::Tls
                } else {
                    UpstreamErrorKind::Connect
                }
            })?;
            let request = wire::cancel_request(upstream_pid, upstream_key);
            stream.write_all(&request).await.map_err(|_| UpstreamErrorKind::Closed)?;
            stream.flush().await.map_err(|_| UpstreamErrorKind::Closed)?;
            let _ = stream.shutdown().await;
            Ok(request.len() as u64)
        };
        match tokio::time::timeout(crate::UPSTREAM_TIMEOUT, send).await {
            Ok(Ok(sent)) => {
                complete(Outcome::Allowed, sent);
                Ok(())
            }
            Ok(Err(kind)) => {
                complete(Outcome::UpstreamError(kind), 0);
                Err(AdapterError::Upstream(kind))
            }
            Err(_) => {
                complete(Outcome::UpstreamError(UpstreamErrorKind::Timeout), 0);
                Err(AdapterError::Upstream(UpstreamErrorKind::Timeout))
            }
        }
    }
}

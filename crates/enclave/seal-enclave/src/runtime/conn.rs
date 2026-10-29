//! The data plane's front: tunnel connections on the enclave's one port (TLS ALPN
//! `seal_proto::tunnel::ALPN`, next to the API's `http/1.1`), their preamble, then the
//! adapter of the session's protocol.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use seal_adapter::{AdapterCtx, BoxStream, ConnMeta};
use seal_authz::TenantAuthorizer;
use seal_crypto::TlsKey;
use seal_proto::tunnel::{TunnelPreamble, ALPN, EXTEND_OK, MAGIC, MAX_PREAMBLE_LEN};
use seal_proto::{codec, Bearer, ErrorCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::live::Resolver;
use super::{fail, Runtime};
use crate::ServiceError;

/// Time a tunnel has, after the handshake, to send its whole preamble.
pub(crate) const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(30);
/// The one name the certificates carry. Clients pin the attested key, never a name.
const CERT_NAME: &str = "enclave.seal.invalid";

/// The server configuration of the enclave's port: `[leaf, CA]` with the derived TLS key, ALPN
/// `http/1.1` (the API) and the tunnel's, no session resumption.
pub(super) fn tls_config(tls: &TlsKey) -> Result<Arc<rustls::ServerConfig>, ServiceError> {
    let internal = |what: &str, e: &dyn std::fmt::Display| fail(ErrorCode::Internal, format!("{what}: {e}"));
    let names = [CERT_NAME.to_string()];
    let ca = tls.ca_certificate_der(&names).map_err(|e| internal("TLS CA certificate", &e))?;
    let leaf = tls.leaf_certificate_der(&names).map_err(|e| internal("TLS certificate", &e))?;
    let chain = vec![CertificateDer::from(leaf), CertificateDer::from(ca)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls.private_key_pkcs8_der().to_vec()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| internal("TLS versions", &e))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| internal("TLS identity", &e))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec(), ALPN.to_vec()];
    // Clients never resume (every connection checks the attested key): no tickets to make.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// `SealService::admits_tunnel`: a replica that serves no sessions (draining, or no longer
/// listed) refuses a tunnel before the TLS handshake, so the tunnel tries the next
/// replica.
pub(crate) fn admit(runtime: &Runtime) -> Result<(), ServiceError> {
    let tenant = runtime.snapshot(&runtime.time.estimate())?;
    runtime.serving(&tenant)?;
    runtime.activity.check()
}

/// `SealService::serve_tunnel`: a tunnel connection after its TLS handshake. A `Connect`
/// preamble's token says the session, and its blob the protocol whose adapter serves the
/// bytes that follow, once the session passes `TenantAuthorizer::recheck` from `peer` (live,
/// granted, inside the app's networks); an `Extend` preamble never reaches an adapter.
pub(crate) async fn serve(
    runtime: &Arc<Runtime>,
    stream: BoxStream,
    peer: Option<std::net::SocketAddr>,
) -> Result<(), ServiceError> {
    let (stream, preamble) = tokio::time::timeout(PREAMBLE_TIMEOUT, read_preamble(stream))
        .await
        .map_err(|_| fail(ErrorCode::BadRequest, "no tunnel preamble in time"))??;
    let connect = match preamble {
        TunnelPreamble::Extend { token } => return extend(runtime, stream, &token, peer).await,
        TunnelPreamble::Connect(connect) => connect,
    };
    // Before any adapter runs, for whatever the connection carries (a Postgres cancel too);
    // the resolver checks again, with the local key, when the adapter presents it.
    let (time, tenant) = runtime.serving_now().await?;
    let claims = runtime.redeem(connect.token.expose())?;
    TenantAuthorizer::new(&tenant).with_source(peer.map(|p| p.ip())).recheck(&claims, &time)?;
    let protocol = claims.blob.policy.destination().protocol();
    let adapter = runtime
        .adapters
        .iter()
        .find(|a| a.protocol() == protocol)
        .ok_or_else(|| fail(ErrorCode::Unavailable, format!("no adapter for {protocol:?}")))?;
    let meta = ConnMeta {
        connection_id: runtime.connections.fetch_add(1, Ordering::Relaxed),
        protocol,
        peer,
        tunnel: connect,
    };
    let ctx =
        AdapterCtx { resolver: Arc::new(Resolver { runtime: runtime.clone() }), upstream: runtime.upstream.clone() };
    adapter.serve(stream, meta, ctx).await.map_err(|e| fail(e.code(), e.to_string()))
}

/// `MAGIC`, the length and the preamble, read whole.
async fn read_preamble(mut stream: BoxStream) -> Result<(BoxStream, TunnelPreamble), ServiceError> {
    let io = |e: std::io::Error| fail(ErrorCode::BadRequest, e.to_string());
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).await.map_err(io)?;
    if &head[..8] != MAGIC {
        return Err(fail(ErrorCode::BadRequest, "not a tunnel preamble"));
    }
    let len = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
    if len == 0 || len > MAX_PREAMBLE_LEN {
        return Err(fail(ErrorCode::BadRequest, "tunnel preamble length out of range"));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await.map_err(io)?;
    let preamble =
        codec::from_canonical(&body).map_err(|e| fail(ErrorCode::BadRequest, format!("tunnel preamble: {e}")))?;
    Ok((stream, preamble))
}

/// Moves this replica's live connections of the token's session to the token's expiry,
/// answers `EXTEND_OK` and closes. A token that does not pass the session recheck gets the
/// connection closed without an answer.
async fn extend(
    runtime: &Arc<Runtime>,
    mut stream: BoxStream,
    token: &Bearer,
    peer: Option<std::net::SocketAddr>,
) -> Result<(), ServiceError> {
    let result = async {
        let time = runtime.now().await?;
        let tenant = runtime.snapshot(&time)?;
        let claims = runtime.redeem(token.expose())?;
        TenantAuthorizer::new(&tenant).with_source(peer.map(|p| p.ip())).recheck(&claims, &time)?;
        for session in runtime.live.of(&claims.session_id) {
            session.extend(&claims);
        }
        Ok::<_, ServiceError>(())
    }
    .await;
    if result.is_ok() {
        let answered = async {
            stream.write_all(&[EXTEND_OK]).await?;
            stream.flush().await
        };
        if let Err(e) = answered.await {
            tracing::debug!(error = %e, "could not answer an extend preamble");
        }
    }
    let _ = stream.shutdown().await;
    result
}

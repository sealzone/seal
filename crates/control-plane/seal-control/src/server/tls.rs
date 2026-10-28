//! Inbound TLS: a listener for `axum::serve` that completes handshakes off the accept loop, so
//! a slow client never holds up others, and the server's certificate from PEM files that are
//! reread when they change (`ReloadingCert`): a certificate renewed next to the server (a
//! certbot DNS-01 sidecar replacing the files) serves new handshakes within
//! `TLS_RELOAD_SECS`, without a restart. A pair that does not load (a chain whose key is not
//! the new key, a file half written) is skipped and the current one kept until the next check.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the certificate files are checked for a change.
pub const TLS_RELOAD_SECS: u64 = 60;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_config(resolver: Arc<dyn ResolvesServerCert>) -> Result<Arc<rustls::ServerConfig>, String> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The certificate chain (leaf first) and private key the server presents.
pub struct TlsIdentity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl TlsIdentity {
    /// From the PEM text of the chain and of the key; `chain` and `key` name them in errors.
    fn from_pem(chain: (&Path, &[u8]), key: (&Path, &[u8])) -> Result<Self, String> {
        let chain_certs = CertificateDer::pem_slice_iter(chain.1)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", chain.0.display()))?;
        if chain_certs.is_empty() {
            return Err(format!("{}: no certificate", chain.0.display()));
        }
        let key_der = PrivateKeyDer::from_pem_slice(key.1).map_err(|e| format!("{}: {e}", key.0.display()))?;
        Ok(Self { chain: chain_certs, key: key_der })
    }

    /// The pair as rustls serves it; refused when the key is not the leaf's.
    fn certified(self) -> Result<Arc<CertifiedKey>, String> {
        CertifiedKey::from_der(self.chain, self.key, &provider())
            .map(Arc::new)
            .map_err(|e| format!("TLS identity: {e}"))
    }

    #[cfg(test)]
    pub fn server_config(self) -> Result<Arc<rustls::ServerConfig>, String> {
        let key = self.certified()?;
        server_config(Arc::new(rustls::sign::SingleCertAndKey::from(key)))
    }
}

/// The certificate chain and key from two PEM files, reloaded by `reload` when either changes.
#[derive(Debug)]
pub struct ReloadingCert {
    chain: PathBuf,
    key: PathBuf,
    current: RwLock<Loaded>,
}

#[derive(Debug)]
struct Loaded {
    /// The files' bytes the current pair was made from.
    chain_pem: Vec<u8>,
    key_pem: zeroize::Zeroizing<Vec<u8>>,
    certified: Arc<CertifiedKey>,
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

impl ReloadingCert {
    pub fn load(chain: &Path, key: &Path) -> Result<Arc<Self>, String> {
        let (chain_pem, key_pem) = (read(chain)?, zeroize::Zeroizing::new(read(key)?));
        let certified = TlsIdentity::from_pem((chain, &chain_pem), (key, &key_pem))?.certified()?;
        let current = RwLock::new(Loaded { chain_pem, key_pem, certified });
        Ok(Arc::new(Self { chain: chain.to_path_buf(), key: key.to_path_buf(), current }))
    }

    /// Rereads both files and serves them from now on if they changed and load. Whether it
    /// swapped; an error leaves the current pair in place.
    pub fn reload(&self) -> Result<bool, String> {
        let (chain_pem, key_pem) = (read(&self.chain)?, zeroize::Zeroizing::new(read(&self.key)?));
        {
            let current = self.current.read().unwrap_or_else(|p| p.into_inner());
            if current.chain_pem == chain_pem && *current.key_pem == *key_pem {
                return Ok(false);
            }
        }
        let certified = TlsIdentity::from_pem((&self.chain, &chain_pem), (&self.key, &key_pem))?.certified()?;
        *self.current.write().unwrap_or_else(|p| p.into_inner()) = Loaded { chain_pem, key_pem, certified };
        Ok(true)
    }

    /// Calls `reload` every `TLS_RELOAD_SECS`.
    pub fn watch(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(TLS_RELOAD_SECS));
            every.tick().await;
            loop {
                every.tick().await;
                match this.reload() {
                    Ok(true) => tracing::info!(chain = %this.chain.display(), "TLS certificate reloaded"),
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "TLS certificate files did not load; keeping the current pair")
                    }
                }
            }
        })
    }

    pub fn server_config(self: &Arc<Self>) -> Result<Arc<rustls::ServerConfig>, String> {
        server_config(self.clone())
    }

    /// What handshakes get now.
    pub fn current(&self) -> Arc<CertifiedKey> {
        self.current.read().unwrap_or_else(|p| p.into_inner()).certified.clone()
    }
}

impl ResolvesServerCert for ReloadingCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// Accepted connections, handshaken.
pub struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: Arc<rustls::ServerConfig>) -> std::io::Result<Self> {
        let local = listener.local_addr()?;
        let (tx, rx) = mpsc::channel(64);
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        tokio::spawn(async move {
            loop {
                let (tcp, peer) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if tx.is_closed() {
                    return;
                }
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, peer)).await;
                        }
                        Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                });
            }
        });
        Ok(Self { rx, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The accept loop never ends while this listener lives.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

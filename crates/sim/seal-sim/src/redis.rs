//! A Redis upstream in a container (Docker or Podman): Redis 7, TLS only with the test CA's
//! `localhost` certificate, the default user off and user `app` holding the password (as in
//! seal-adapter-redis's Docker test).

use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::container::{self, Container};
use crate::net;
use crate::setup::Sim;

pub const USER: &str = "app";
/// Fully qualified, so Podman needs no short-name configuration.
const IMAGE: &str = "docker.io/library/redis:7-alpine";

/// A running Redis, removed on drop.
pub struct Redis(pub Container);

impl Redis {
    /// What producers seal the password to.
    pub fn destination(&self) -> String {
        format!("rediss://{USER}@{}:{}/0", crate::setup::HOST, self.0.port)
    }
}

/// Starts `IMAGE` with user `app` and `password`; waits until it answers over TLS.
pub async fn start(sim: &Sim, password: &str) -> anyhow::Result<Redis> {
    let read = |name: &str| std::fs::read_to_string(sim.path(name)).with_context(|| name.to_string());
    let (cert, key, ca) = (read("tls-chain.pem")?, read("tls-key.pem")?, read("ca.pem")?);
    let conf = format!(
        "port 0\ntls-port 6379\ntls-cert-file /tls/cert.pem\ntls-key-file /tls/key.pem\n\
         tls-ca-cert-file /tls/ca.pem\ntls-auth-clients no\nsave \"\"\nappendonly no\n\
         user default off\nuser {USER} on >{password} ~* &* +@all\n"
    );
    let script =
        "mkdir -p /tls && printf '%s' \"$TLS_CERT\" > /tls/cert.pem && printf '%s' \"$TLS_KEY\" > /tls/key.pem \
                  && printf '%s' \"$TLS_CA\" > /tls/ca.pem && printf '%s' \"$REDIS_CONF\" > /tls/redis.conf \
                  && exec redis-server /tls/redis.conf";
    let env = [("TLS_CERT", cert.as_str()), ("TLS_KEY", &key), ("TLS_CA", &ca), ("REDIS_CONF", &conf)];
    let redis = Redis(container::start(IMAGE, &env, "sh", script, 6379)?);

    let deadline = Instant::now() + Duration::from_secs(60);
    while !tls_answers(redis.0.port, ca.as_bytes()).await {
        if Instant::now() > deadline {
            bail!("Redis did not start");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(redis)
}

/// Whether Redis answers `PING` over TLS (with `-NOAUTH`, since nobody logged in).
async fn tls_answers(port: u16, ca_pem: &[u8]) -> bool {
    let Ok(config) = net::client_config(ca_pem) else { return false };
    let Ok(tcp) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else { return false };
    let name = rustls::pki_types::ServerName::try_from(crate::setup::HOST).expect("a valid name");
    let answered = async {
        let mut tls = tokio_rustls::TlsConnector::from(config).connect(name, tcp).await.ok()?;
        tls.write_all(b"PING\r\n").await.ok()?;
        let mut reply = [0u8; 1];
        tls.read_exact(&mut reply).await.ok()?;
        Some(reply[0] == b'-' || reply[0] == b'+')
    };
    tokio::time::timeout(Duration::from_secs(2), answered).await.ok().flatten().unwrap_or(false)
}

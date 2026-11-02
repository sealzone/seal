//! A Postgres upstream in a container (Docker or Podman): SCRAM-SHA-256 only, TLS with the
//! test CA's `localhost` certificate (as in seal-adapter-pg's Docker test).

use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::container::{self, Container};
use crate::setup::Sim;

pub const USER: &str = "app";
pub const DATABASE: &str = "orders";
/// Fully qualified, so Podman needs no short-name configuration.
const IMAGE: &str = "docker.io/library/postgres:17";

/// A running Postgres, removed on drop.
pub struct Postgres(pub Container);

impl Postgres {
    /// What the password is sealed to.
    pub fn destination(&self) -> String {
        format!("postgres://{USER}@{}:{}/{DATABASE}", crate::setup::HOST, self.0.port)
    }
}

/// Starts `IMAGE` with user `app`, database `orders` and `password`,
/// SCRAM-only authentication and TLS; waits until it answers `SSLRequest` with `S`.
pub async fn start(sim: &Sim, password: &str) -> anyhow::Result<Postgres> {
    let read = |name: &str| std::fs::read_to_string(sim.path(name)).with_context(|| name.to_string());
    let (cert, key) = (read("tls-chain.pem")?, read("tls-key.pem")?);
    let script = r#"printf '%s' "$PG_CERT" > /tmp/server.crt && printf '%s' "$PG_KEY" > /tmp/server.key \
        && chown postgres /tmp/server.crt /tmp/server.key && chmod 600 /tmp/server.key \
        && exec docker-entrypoint.sh postgres -c ssl=on \
           -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key -c password_encryption=scram-sha-256"#;
    let env = [
        ("POSTGRES_USER", USER),
        ("POSTGRES_DB", DATABASE),
        ("POSTGRES_PASSWORD", password),
        ("POSTGRES_HOST_AUTH_METHOD", "scram-sha-256"),
        ("POSTGRES_INITDB_ARGS", "--auth-host=scram-sha-256"),
        ("PG_CERT", &cert),
        ("PG_KEY", &key),
    ];
    let pg = Postgres(container::start(IMAGE, &env, "bash", script, 5432)?);

    // The entrypoint's initdb server listens on a Unix socket only, so the first TLS answer on
    // TCP is the final server's.
    let deadline = Instant::now() + Duration::from_secs(90);
    while !ssl_answers(pg.0.port).await {
        if Instant::now() > deadline {
            bail!("Postgres did not start");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(pg)
}

/// The control plane's telemetry database, in a container: returns it and its URL. Plain and
/// published on loopback only: it holds a throwaway run's telemetry.
pub async fn start_control_db() -> anyhow::Result<(Container, String)> {
    let env = [("POSTGRES_PASSWORD", "sim"), ("POSTGRES_DB", "control")];
    let db = container::start(IMAGE, &env, "bash", "exec docker-entrypoint.sh postgres", 5432)?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while ssl_answer(db.port).await.is_none() {
        if Instant::now() > deadline {
            bail!("the control plane's Postgres did not start");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let url = format!("postgres://postgres:sim@127.0.0.1:{}/control?sslmode=disable", db.port);
    Ok((db, url))
}

async fn ssl_answers(port: u16) -> bool {
    ssl_answer(port).await == Some(b'S')
}

/// Its answer to `SSLRequest`, which only the final server gives: `S` or `N`.
async fn ssl_answer(port: u16) -> Option<u8> {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    let mut reply = [0u8; 1];
    s.write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]).await.ok()?;
    tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut reply)).await.ok()?.ok()?;
    Some(reply[0])
}

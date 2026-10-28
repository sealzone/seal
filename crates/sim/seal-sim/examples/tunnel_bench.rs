//! Times the data plane through the SDK tunnel against a running simulator: new connections
//! one after another, a burst of new connections at once, requests on one kept-alive
//! connection, and a large response. The client comes from the environment
//! (`Client::from_env`); the blob is for the simulator's upstream.
//!
//! ```text
//! cargo run --release --features sim -p seal-sim --example tunnel_bench -- BLOB_FILE
//! ```

extern crate seal_client as seal;

use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use seal_sim::net::Conn;

const SEQUENTIAL: usize = 200;
const BURST: usize = 64;
const KEPT_ALIVE: usize = 500;
const LARGE: usize = 32 << 20;

fn summary(name: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let mean = samples.iter().sum::<Duration>() / samples.len() as u32;
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q) as usize];
    println!(
        "{name:<34} n={:<4} mean {:>7.2} ms  p50 {:>7.2} ms  p90 {:>7.2} ms  p99 {:>7.2} ms",
        samples.len(),
        ms(mean),
        ms(at(0.5)),
        ms(at(0.9)),
        ms(at(0.99))
    );
}

async fn call(conn: &mut Conn, path: &str, auth: &str) -> anyhow::Result<usize> {
    let (status, body) = conn.get(path, &[("authorization", auth)]).await?;
    if status != 200 {
        bail!("GET {path}: {status} {body}");
    }
    Ok(body.len())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let blob_file = std::env::args().nth(1).context("usage: tunnel_bench BLOB_FILE")?;
    let blob = std::fs::read_to_string(&blob_file)?;
    let client = seal::Client::from_env().await?;
    let s = client.session(blob.trim()).http().await?;
    let (url, auth) = (s.url().to_string(), format!("Bearer {}", s.key()));

    // Warm up: the first connection, and whatever the tunnel keeps after it.
    let mut warm = Conn::open(&url, None).await?;
    call(&mut warm, "/ping", &auth).await?;
    drop(warm);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut samples = Vec::new();
    for _ in 0..SEQUENTIAL {
        let started = Instant::now();
        let mut conn = Conn::open(&url, None).await?;
        call(&mut conn, "/ping", &auth).await?;
        samples.push(started.elapsed());
    }
    summary("new connection + request", samples);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    let mut burst = tokio::task::JoinSet::new();
    for _ in 0..BURST {
        let (url, auth) = (url.clone(), auth.clone());
        burst.spawn(async move {
            let started = Instant::now();
            let mut conn = Conn::open(&url, None).await?;
            call(&mut conn, "/ping", &auth).await?;
            Ok::<_, anyhow::Error>(started.elapsed())
        });
    }
    let mut samples = Vec::new();
    while let Some(done) = burst.join_next().await {
        samples.push(done??);
    }
    let whole = started.elapsed();
    summary(&format!("burst of {BURST} new connections"), samples);
    println!("{:<34} {:.2} ms for all", "", whole.as_secs_f64() * 1000.0);

    let mut conn = Conn::open(&url, None).await?;
    let mut samples = Vec::new();
    for _ in 0..KEPT_ALIVE {
        let started = Instant::now();
        call(&mut conn, "/ping", &auth).await?;
        samples.push(started.elapsed());
    }
    summary("request on a kept-alive connection", samples);

    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        let got = call(&mut conn, &format!("/bytes/{LARGE}"), &auth).await?;
        if got != LARGE {
            bail!("/bytes: {got} bytes, not {LARGE}");
        }
        best = best.min(started.elapsed());
    }
    println!(
        "{:<34} {:.0} MiB/s ({} MiB in {:.0} ms, best of 3)",
        "large response",
        (LARGE as f64 / (1 << 20) as f64) / best.as_secs_f64(),
        LARGE >> 20,
        best.as_secs_f64() * 1000.0
    );
    s.close().await?;
    Ok(())
}

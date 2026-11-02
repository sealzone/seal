//! Telemetry pages over many streams: pages match what reading every batch gives.

use super::*;
use seal_control::client::TelemetryOrder;

/// A batch of `entries` entries, one second apart from `at`.
fn wide_batch(stream: [u8; 16], sequence: u64, at: UnixTime, entries: u32) -> TelemetryBatch {
    TelemetryBatch {
        tenant: acme(),
        stream,
        sequence,
        first_entry: sequence * u64::from(entries),
        count: entries,
        from: at,
        to: at + u64::from(entries) - 1,
        entries: TelemetryEntries::Clear {
            entries: (0..entries)
                .map(|i| TelemetryEntry {
                    at: at + u64::from(i),
                    tenant: acme(),
                    identity: None,
                    event: TelemetryEvent::Dropped { requests: sequence, other: u64::from(i) },
                })
                .collect(),
        },
        last: false,
    }
}

fn stream_id(n: u32) -> [u8; 16] {
    let mut id = [0x5a; 16];
    id[..4].copy_from_slice(&n.to_be_bytes());
    id
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every batch with its size as stored.
fn stored(batches: &[SignedTelemetryBatch]) -> Vec<(SignedTelemetryBatch, u64)> {
    batches.iter().map(|b| (b.clone(), serde_json::to_vec(b).unwrap().len() as u64)).collect()
}

/// Cuts a page from batches already filtered and ordered, as the route does.
fn cut<'a>(batches: impl IntoIterator<Item = &'a SignedTelemetryBatch>, limit: usize) -> Vec<SignedTelemetryBatch> {
    let mut page = Vec::new();
    let mut bytes = 0;
    for batch in batches.into_iter().take(limit) {
        bytes += serde_json::to_vec(batch).map_or(0, |b| b.len() + 1);
        if !page.is_empty() && bytes > TELEMETRY_PAGE_BYTES {
            break;
        }
        page.push(batch.clone());
    }
    page
}

/// What the route answered when it read every batch for each page.
fn reference_page(
    all: &[(SignedTelemetryBatch, u64)],
    since: UnixTime,
    after: Option<([u8; 16], u64)>,
    limit: usize,
) -> Vec<SignedTelemetryBatch> {
    let mut batches: Vec<_> = all
        .iter()
        .map(|(b, _)| b)
        .filter(|b| b.body.to >= since && after.is_none_or(|a| (b.body.stream, b.body.sequence) > a))
        .collect();
    batches.sort_by_key(|b| (b.body.stream, b.body.sequence));
    cut(batches, limit)
}

/// The fixture: 40 streams of 1 to 23 batches of 1 to 60 entries, some of 2 000 (so bytes end
/// pages), overlapping in time, one stream going back in time, six sharing their times, posted
/// out of order.
async fn many_streams(env: &Env) -> Vec<SignedTelemetryBatch> {
    let sign = |b: TelemetryBatch| env.telemetry_signer().sign_into(TELEMETRY_BATCH_LABEL, b);
    let mut batches = Vec::new();
    for s in 0..40u32 {
        for q in 0..u64::from(1 + s * 7 % 23) {
            let entries = if (s + q as u32).is_multiple_of(29) { 2_000 } else { 1 + (s * 31 + q as u32 * 17) % 60 };
            let at = match s {
                5 => 5_000 - q * 100,
                30..=35 => 2_000 + q * 50,
                _ => 1_000 + u64::from(s) * 13 + q * 20,
            };
            batches.push(sign(wide_batch(stream_id((s * 7_919) % 1_000), q, at, entries)));
        }
    }
    batches.sort_by_key(|b| (b.body.sequence % 3, std::cmp::Reverse(b.body.sequence), b.body.stream));
    for b in &batches {
        assert_eq!(env.post("/v1/tenants/acme/telemetry", b).await, 204);
    }
    batches
}

fn header(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    headers.get(name).map(|v| v.to_str().unwrap().to_string())
}

/// Pages from `query` on, following `Seal-Telemetry-Next`: each page's body and headers.
async fn walk(env: &Env, query: &str) -> Vec<(Vec<u8>, hyper::HeaderMap)> {
    let mut pages = Vec::new();
    let mut path = format!("/v1/tenants/acme/telemetry?{query}");
    loop {
        let (status, headers, body) = env.send("GET", &path, Auth::Key(V1_ADMINS[0]), &[], Vec::new()).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let next = header(&headers, TELEMETRY_NEXT);
        pages.push((body, headers));
        let Some(next) = next else { return pages };
        path = format!("/v1/tenants/acme/telemetry?{query}&after={next}");
    }
}

#[tokio::test]
async fn stream_pages_are_what_reading_every_batch_gave() {
    let mut env = Env::new().await;
    env.ready().await;
    let all = stored(&many_streams(&env).await);
    let mut cut_by_bytes = false;
    for since in [0, 1_300, 1_600, 4_000, 99_999] {
        for limit in [None, Some(7), Some(1_000)].into_iter().chain((since == 1_600).then_some(Some(1))) {
            let query = match limit {
                Some(n) => format!("since={since}&limit={n}"),
                None => format!("since={since}"),
            };
            let mut after = None;
            let mut seen = 0;
            for (body, headers) in walk(&env, &query).await {
                let expected = reference_page(&all, since, after, limit.unwrap_or(TELEMETRY_PAGE_BATCHES));
                assert_eq!(body, serde_json::to_vec(&expected).unwrap(), "{query} after {after:?}");
                let rest: Vec<_> = all
                    .iter()
                    .filter(|(b, _)| b.body.to >= since && after.is_none_or(|a| (b.body.stream, b.body.sequence) > a))
                    .collect();
                assert_eq!(header(&headers, TELEMETRY_REMAINING_BATCHES), Some(rest.len().to_string()));
                let bytes: u64 = rest.iter().map(|(_, size)| size).sum();
                assert_eq!(header(&headers, TELEMETRY_REMAINING_BYTES), Some(bytes.to_string()));
                cut_by_bytes |= expected.len() < rest.len().min(limit.unwrap_or(TELEMETRY_PAGE_BATCHES));
                if let Some(last) = expected.last() {
                    // The header is the cursor old readers build themselves.
                    assert_eq!(
                        header(&headers, TELEMETRY_NEXT),
                        Some(format!("{}-{}", hex(&last.body.stream), last.body.sequence))
                    );
                    after = Some((last.body.stream, last.body.sequence));
                }
                seen += expected.len();
            }
            let matching = all.iter().filter(|(b, _)| b.body.to >= since).count();
            assert_eq!(seen, matching, "{query}: every batch once");
        }
    }
    assert!(cut_by_bytes, "some pages end on bytes");

    // The same answers after a restart.
    let before = walk(&env, "since=1300&limit=9").await;
    env.restart().await;
    let after = walk(&env, "since=1300&limit=9").await;
    assert_eq!(before.iter().map(|(b, _)| b).collect::<Vec<_>>(), after.iter().map(|(b, _)| b).collect::<Vec<_>>());

    // A write shows in the next page and its count.
    let (_, headers, _) =
        env.send("GET", "/v1/tenants/acme/telemetry?since=0", Auth::Key(V1_ADMINS[0]), &[], Vec::new()).await;
    let total: u64 = header(&headers, TELEMETRY_REMAINING_BATCHES).unwrap().parse().unwrap();
    let new = env.telemetry_signer().sign_into(TELEMETRY_BATCH_LABEL, wide_batch([0xff; 16], 0, 7_000, 2));
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &new).await, 204);
    let after = format!("{}-0", "fe".repeat(16));
    let (_, headers, body) = env
        .send("GET", &format!("/v1/tenants/acme/telemetry?since=0&after={after}"), Auth::Key(V1_ADMINS[0]), &[], vec![])
        .await;
    assert_eq!(serde_json::from_slice::<Vec<SignedTelemetryBatch>>(&body).unwrap(), vec![new]);
    let (_, all_headers, _) =
        env.send("GET", "/v1/tenants/acme/telemetry?since=0", Auth::Key(V1_ADMINS[0]), &[], Vec::new()).await;
    assert_eq!(header(&all_headers, TELEMETRY_REMAINING_BATCHES), Some((total + 1).to_string()));
    assert_eq!(header(&headers, TELEMETRY_REMAINING_BATCHES).as_deref(), Some("1"));
}

#[tokio::test]
async fn time_order_pages_cover_every_batch_once_by_time() {
    let env = Env::new().await;
    env.ready().await;
    let all = stored(&many_streams(&env).await);
    let key = |b: &SignedTelemetryBatch| (b.body.to, b.body.stream, b.body.sequence);
    for since in [0, 1_600] {
        for limit in [None, Some(13)].into_iter().chain((since == 1_600).then_some(Some(1))) {
            let query = match limit {
                Some(n) => format!("since={since}&order=time&limit={n}"),
                None => format!("since={since}&order=time"),
            };
            let mut rest: Vec<_> = all.iter().filter(|(b, _)| b.body.to >= since).cloned().collect();
            rest.sort_by_key(|(b, _)| key(b));
            for (body, headers) in walk(&env, &query).await {
                assert_eq!(header(&headers, TELEMETRY_REMAINING_BATCHES), Some(rest.len().to_string()));
                let bytes: u64 = rest.iter().map(|(_, size)| size).sum();
                assert_eq!(header(&headers, TELEMETRY_REMAINING_BYTES), Some(bytes.to_string()));
                let expected = cut(rest.iter().map(|(b, _)| b), limit.unwrap_or(TELEMETRY_PAGE_BATCHES));
                assert_eq!(body, serde_json::to_vec(&expected).unwrap(), "{query}");
                if let Some(last) = expected.last() {
                    assert_eq!(header(&headers, TELEMETRY_NEXT), Some(TelemetryOrder::Time.cursor(&last.body)));
                }
                rest.drain(..expected.len());
            }
            assert!(rest.is_empty(), "{query}: every batch once");
        }
    }
    // Cursors belong to their order.
    let time_cursor = format!("2000-{}-0", hex(&stream_id(0)));
    assert_eq!(env.get(&format!("/v1/tenants/acme/telemetry?after={time_cursor}")).await.0, 400);
    let stream_cursor = format!("{}-0", hex(&stream_id(0)));
    assert_eq!(env.get(&format!("/v1/tenants/acme/telemetry?order=time&after={stream_cursor}")).await.0, 400);
    assert_eq!(env.get("/v1/tenants/acme/telemetry?order=newest").await.0, 400);
}

#[tokio::test]
async fn the_console_reads_the_page_hints() {
    let env = Env::new().await;
    env.ready().await;
    let (_, headers, _) = env
        .send("GET", "/v1/tenants/acme/telemetry", Auth::Key(V1_ADMINS[0]), &[("origin", CONSOLE_ORIGIN)], vec![])
        .await;
    let exposed = header(&headers, "access-control-expose-headers").unwrap();
    for name in [TELEMETRY_REMAINING_BATCHES, TELEMETRY_REMAINING_BYTES, TELEMETRY_NEXT] {
        assert!(exposed.split(", ").any(|n| n == name), "{name}");
    }
    assert_eq!(header(&headers, TELEMETRY_REMAINING_BATCHES).as_deref(), Some("0"));
    assert_eq!(header(&headers, TELEMETRY_NEXT), None, "an empty page has no next");
}

#[tokio::test]
async fn a_batch_needs_a_certified_key_and_keeps_its_place() {
    let env = Env::new().await;
    env.ready().await;
    let sign = |b: TelemetryBatch| env.telemetry_signer().sign_into(TELEMETRY_BATCH_LABEL, b);
    let good = sign(wide_batch(stream_id(1), 0, 1_000, 2));
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &good).await, 204);
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &sign(wide_batch(stream_id(1), 0, 1_000, 3))).await, 409);
    let forged: SignedTelemetryBatch =
        key(STRANGER).sign_into(TELEMETRY_BATCH_LABEL, wide_batch(stream_id(2), 0, 1_000, 2));
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &forged).await, 403);
    let (_, headers, _) = env.send("GET", "/v1/tenants/acme/telemetry", Auth::Key(V1_ADMINS[0]), &[], vec![]).await;
    assert_eq!(header(&headers, TELEMETRY_REMAINING_BATCHES).as_deref(), Some("1"));
}

#[tokio::test]
async fn counts_are_for_members() {
    let usage = "/v1/tenants/acme/telemetry/usage?from=0&to=100000";
    let env = Env::new().await;
    env.ready().await;
    let batch = env.telemetry_signer().sign_into(TELEMETRY_BATCH_LABEL, wide_batch(stream_id(1), 0, 90_000, 3));
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &batch).await, 204);
    for path in [usage, "/v1/tenants/acme/telemetry/metrics?from=0&to=100000", "/v1/tenants/acme/telemetry/gaps"] {
        let status = env.get_as(path, Auth::None).await.0;
        assert!(status == 401 || status == 403, "{path}: anonymous got {status}");
    }
    // How the console reads them.
    let member = Auth::Header(control_token(&console_key(), "acme", env.root_id(), "read", env.now()));
    assert_eq!(env.get_as(usage, member).await.0, 200);
    let admin = || Auth::Key(V1_ADMINS[0]);
    let (status, body) = env.get_as(usage, admin()).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let days: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        days,
        serde_json::json!([{ "day": "1970-01-02", "requests": 0, "sessions": 0, "entries": 3, "sealed_entries": 0, "active_secrets": 0 }])
    );
    let (status, body) =
        env.get_as("/v1/tenants/acme/telemetry/metrics?from=0&to=100000&group_by=event", admin()).await;
    assert_eq!(status, 200);
    let points: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(points, serde_json::json!([{ "hour": "1970-01-02T01:00:00Z", "key": "dropped", "count": 3 }]));
    assert_eq!(env.get_as("/v1/tenants/acme/telemetry/metrics?from=0&to=1&group_by=x", admin()).await.0, 400);
    let (status, body) = env.get_as("/v1/tenants/acme/telemetry/gaps", admin()).await;
    assert_eq!((status, body.as_slice()), (200, b"[]".as_slice()));
}

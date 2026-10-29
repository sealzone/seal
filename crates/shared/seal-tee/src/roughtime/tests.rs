use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use seal_net::{Datagrams, NetError};

use super::*;

const ALL: [RoughtimeVersion; 4] =
    [RoughtimeVersion::Rfc10049, RoughtimeVersion::Draft12, RoughtimeVersion::Draft11, RoughtimeVersion::Draft07];

// ---------------------------------------------------------------------------------------
// Editing packets without re-signing them

fn pairs(message: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let m = Message::parse(message).unwrap();
    m.tags.iter().copied().zip(m.values.iter().map(|v| v.to_vec())).collect()
}

/// Rewrites the value at `path` (tags from the top level down) with `f`.
fn edit(packet: &[u8], path: &[u32], f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    fn go(message: &[u8], path: &[u32], f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut pairs = pairs(message);
        let (_, value) = pairs.iter_mut().find(|(t, _)| *t == path[0]).expect("tag present");
        if path.len() == 1 {
            f(value);
        } else {
            *value = go(value, &path[1..], f);
        }
        encode(pairs)
    }
    frame(&go(unframe(packet).unwrap(), path, f))
}

// Takes what `edit` hands its closure.
#[allow(clippy::ptr_arg)]
fn flip(v: &mut Vec<u8>) {
    v[0] ^= 1;
}

fn nonce_of(request: &[u8]) -> [u8; 32] {
    Message::parse(unframe(request).unwrap()).unwrap().fixed(NONC, "nonce").unwrap()
}

// ---------------------------------------------------------------------------------------
// A test server that signs with its own keys

#[derive(Clone)]
struct TestServer {
    root: SigningKey,
    online: SigningKey,
    version: RoughtimeVersion,
    /// Leaves in the batch (ours included) and our position among them.
    leaves: usize,
    index: usize,
    order: Order,
    /// `TYPE = 1` in the reply.
    typed: bool,
    /// `RADI` as sent (seconds, or microseconds for draft 7).
    radi: u32,
    /// `MINT` and `MAXT` relative to `MIDP`, in microseconds.
    mint: i128,
    maxt: i128,
}

impl TestServer {
    fn new(seed: u8, version: RoughtimeVersion) -> Self {
        let profile = Profile::of(version);
        Self {
            root: SigningKey::from_bytes(&[seed; 32]),
            online: SigningKey::from_bytes(&[seed ^ 0x80; 32]),
            version,
            leaves: 5,
            index: 3,
            order: profile.typed_orders[profile.typed_orders.len() - 1],
            typed: profile.type_required || version == RoughtimeVersion::Draft12,
            radi: if profile.time == Time::MjdMicros { 100_000 } else { 1 },
            mint: -86_400_000_000,
            maxt: 86_400_000_000,
        }
    }

    fn public_key(&self) -> [u8; 32] {
        self.root.verifying_key().to_bytes()
    }

    fn config(&self, address: &str, operator: &str) -> RoughtimeServer {
        RoughtimeServer {
            address: address.into(),
            public_key: self.public_key(),
            version: self.version,
            operator: operator.into(),
        }
    }

    fn encode_time(&self, us: i128) -> Vec<u8> {
        let raw = match Profile::of(self.version).time {
            Time::UnixSeconds => us.div_euclid(1_000_000) as u64,
            Time::MjdMicros => {
                let day = us.div_euclid(86_400_000_000) + 40_587;
                ((day as u64) << 40) | us.rem_euclid(86_400_000_000) as u64
            }
        };
        raw.to_le_bytes().to_vec()
    }

    /// The reply to `request` with `MIDP` = `midp` (microseconds since the Unix epoch).
    fn respond(&self, request: &[u8], midp: i128) -> Vec<u8> {
        let p = Profile::of(self.version);
        let nonce = nonce_of(request);
        let leaf = match p.leaf {
            Leaf::Packet => request.to_vec(),
            Leaf::Nonce => nonce.to_vec(),
        };
        // The batch: other clients' leaves around ours, padded to a power of two.
        let width = self.leaves.next_power_of_two();
        let mut level: Vec<[u8; 32]> = (0..width)
            .map(|i| if i == self.index { p.hash.of(&[&[0], &leaf]) } else { p.hash.of(&[&[0], &[i as u8]]) })
            .collect();
        let (mut path, mut at) = (Vec::new(), self.index);
        while level.len() > 1 {
            path.extend(level[at ^ 1]);
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| match self.order {
                    Order::HashFirst => p.hash.of(&[&[1], &pair[0], &pair[1]]),
                    Order::NodeFirst => p.hash.of(&[&[1], &pair[1], &pair[0]]),
                })
                .collect();
            at /= 2;
        }
        let mut srep =
            vec![(ROOT, level[0].to_vec()), (MIDP, self.encode_time(midp)), (RADI, self.radi.to_le_bytes().to_vec())];
        if p.version_in == VersionIn::Srep {
            srep.push((VER, p.number.to_le_bytes().to_vec()));
            srep.push((VERS, [0u32, p.number].iter().flat_map(|v| v.to_le_bytes()).collect()));
        }
        let srep = encode(srep);
        let dele = encode(vec![
            (PUBK, self.online.verifying_key().to_bytes().to_vec()),
            (MINT, self.encode_time(midp + self.mint)),
            (MAXT, self.encode_time(midp + self.maxt)),
        ]);
        let cert = encode(vec![
            (SIG, self.root.sign(&[p.delegation_context, &dele].concat()).to_bytes().to_vec()),
            (DELE, dele),
        ]);
        let mut top = vec![
            (SIG, self.online.sign(&[p.response_context, &srep].concat()).to_bytes().to_vec()),
            (NONC, nonce.to_vec()),
            (PATH, path),
            (SREP, srep),
            (CERT, cert),
            (INDX, (self.index as u32).to_le_bytes().to_vec()),
        ];
        if p.version_in == VersionIn::TopLevel {
            top.push((VER, p.number.to_le_bytes().to_vec()));
        }
        if self.typed {
            top.push((TYPE, 1u32.to_le_bytes().to_vec()));
        }
        frame(&encode(top))
    }
}

const NOW_US: i128 = 1_800_000_000_000_000;

fn exchange(server: &TestServer, midp: i128) -> (Vec<u8>, [u8; 32], Vec<u8>) {
    let nonce = [0x5a; 32];
    let request = Profile::of(server.version).request(&server.public_key(), &nonce);
    let reply = server.respond(&request, midp);
    (request, nonce, reply)
}

fn check(server: &TestServer, request: &[u8], nonce: &[u8; 32], reply: &[u8]) -> Check<Sample> {
    Profile::of(server.version).verify(&server.public_key(), request, nonce, reply)
}

// ---------------------------------------------------------------------------------------
// Requests and single replies

#[test]
fn requests_offer_only_the_pinned_version() {
    for version in ALL {
        let p = Profile::of(version);
        let request = p.request(&[1; 32], &[2; 32]);
        assert_eq!(request.len(), if version == RoughtimeVersion::Rfc10049 { 1036 } else { 1024 });
        let m = Message::parse(unframe(&request).unwrap()).unwrap();
        assert_eq!(m.get(VER).unwrap(), p.number.to_le_bytes());
        assert_eq!(m.get(NONC).unwrap(), [2; 32]);
        assert_eq!(m.get(SRV).unwrap(), Hash::Sha512Trunc.of(&[&[0xff], &[1; 32]]));
        assert_eq!(m.get(TYPE).is_some(), matches!(version, RoughtimeVersion::Rfc10049 | RoughtimeVersion::Draft12));
        assert!(m.get(ZZZZ).unwrap().iter().all(|&b| b == 0));
    }
}

#[test]
fn every_profile_round_trips() {
    for version in ALL {
        let p = Profile::of(version);
        for (leaves, index) in [(1, 0), (2, 1), (5, 3), (16, 10)] {
            for typed in [false, true] {
                let orders = if typed { p.typed_orders } else { p.orders };
                if p.type_required && !typed {
                    continue;
                }
                for order in [Order::HashFirst, Order::NodeFirst] {
                    let server = TestServer { leaves, index, typed, order, ..TestServer::new(1, version) };
                    let (request, nonce, reply) = exchange(&server, NOW_US);
                    let result = check(&server, &request, &nonce, &reply);
                    // Without siblings the order cannot matter.
                    if leaves == 1 || orders.contains(&order) {
                        let sample = result.unwrap_or_else(|e| panic!("{version:?} {leaves} {typed} {order:?}: {e:?}"));
                        let radius = if p.time == Time::MjdMicros { 100_000 } else { 1_000_000 };
                        assert_eq!(sample, Sample { midp: NOW_US, radius });
                    } else {
                        assert_eq!(result, Err(Invalid("Merkle proof does not lead to ROOT")), "{version:?} {order:?}");
                    }
                }
            }
        }
    }
}

#[test]
fn tampered_replies_are_refused() {
    for version in ALL {
        let server = TestServer::new(2, version);
        let (request, nonce, reply) = exchange(&server, NOW_US);
        assert!(check(&server, &request, &nonce, &reply).is_ok());
        let refused = |packet: &[u8], why: &str| {
            assert_eq!(check(&server, &request, &nonce, packet).map_err(|e| e.0), Err(why), "{version:?}")
        };
        refused(&edit(&reply, &[SIG], flip), "response signature");
        refused(&edit(&reply, &[CERT, SIG], flip), "delegation signature");
        refused(&edit(&reply, &[CERT, DELE, MAXT], flip), "delegation signature");
        refused(&edit(&reply, &[SREP, MIDP], flip), "response signature");
        refused(&edit(&reply, &[PATH], flip), "Merkle proof does not lead to ROOT");
        refused(&edit(&reply, &[INDX], flip), "Merkle proof does not lead to ROOT");
        refused(&edit(&reply, &[INDX], |v| v[3] = 0x80), "Merkle proof does not lead to ROOT");
        refused(&edit(&reply, &[PATH], |v| v.truncate(v.len() - 4)), "bad PATH");
        refused(&edit(&reply, &[NONC], flip), "nonce not echoed");

        // Another request (another nonce) with this reply: the echo, or the Merkle leaf.
        let other_nonce = [0x11; 32];
        let other = Profile::of(version).request(&server.public_key(), &other_nonce);
        assert!(check(&server, &other, &other_nonce, &reply).is_err());
        let same_nonce_other_packet = edit(&request, &[ZZZZ], |v| v[0] = 1);
        let result = check(&server, &same_nonce_other_packet, &nonce, &reply);
        match Profile::of(version).leaf {
            Leaf::Packet => assert_eq!(result, Err(Invalid("Merkle proof does not lead to ROOT"))),
            Leaf::Nonce => assert!(result.is_ok()),
        }

        // Another server's key, and another profile than the pinned one.
        let stranger = TestServer::new(3, version);
        assert_eq!(check(&stranger, &request, &nonce, &reply), Err(Invalid("delegation signature")));
        for other in ALL.into_iter().filter(|v| *v != version) {
            let p = Profile::of(other);
            assert!(p.verify(&server.public_key(), &request, &nonce, &reply).is_err(), "{version:?} as {other:?}");
        }
        assert!(check(&server, &request, &nonce, &reply[..reply.len() - 1]).is_err());
        assert!(check(&server, &request, &nonce, &[]).is_err());
    }
}

#[test]
fn midp_outside_the_delegation_is_refused() {
    for version in ALL {
        let expired = TestServer { mint: -2_000_000, maxt: -1_000_000, ..TestServer::new(4, version) };
        let (request, nonce, reply) = exchange(&expired, NOW_US);
        assert_eq!(check(&expired, &request, &nonce, &reply), Err(Invalid("MIDP outside MINT..MAXT")));
        let early = TestServer { mint: 1_000_000, maxt: 2_000_000, ..TestServer::new(4, version) };
        let (request, nonce, reply) = exchange(&early, NOW_US);
        assert_eq!(check(&early, &request, &nonce, &reply), Err(Invalid("MIDP outside MINT..MAXT")));
        let edge = TestServer { mint: 0, maxt: 0, ..TestServer::new(4, version) };
        let (request, nonce, reply) = exchange(&edge, NOW_US);
        assert!(check(&edge, &request, &nonce, &reply).is_ok());
    }
}

#[test]
fn type_and_version_rules() {
    // RFC 10049 needs `TYPE = 1` and a nonzero radius.
    let untyped = TestServer { typed: false, ..TestServer::new(5, RoughtimeVersion::Rfc10049) };
    let (request, nonce, reply) = exchange(&untyped, NOW_US);
    assert_eq!(check(&untyped, &request, &nonce, &reply), Err(Invalid("no TYPE")));
    let server = TestServer::new(5, RoughtimeVersion::Rfc10049);
    let (request, nonce, reply) = exchange(&server, NOW_US);
    assert_eq!(check(&server, &request, &nonce, &edit(&reply, &[TYPE], |v| v[0] = 0)), Err(Invalid("TYPE is not 1")));
    let zero = TestServer { radi: 0, ..TestServer::new(5, RoughtimeVersion::Rfc10049) };
    let (request, nonce, reply) = exchange(&zero, NOW_US);
    assert_eq!(check(&zero, &request, &nonce, &reply), Err(Invalid("RADI is 0")));
    // Draft 11 names its version at the top level, unsigned, but it must still be ours.
    let d11 = TestServer::new(5, RoughtimeVersion::Draft11);
    let (request, nonce, reply) = exchange(&d11, NOW_US);
    assert_eq!(
        check(&d11, &request, &nonce, &edit(&reply, &[VER], |v| v[0] = 0x0c)),
        Err(Invalid("not the pinned version"))
    );
    // `NONC` may be missing only where the Merkle leaf is the nonce.
    for version in ALL {
        let server = TestServer::new(6, version);
        let (request, nonce, reply) = exchange(&server, NOW_US);
        let mut top = pairs(unframe(&reply).unwrap());
        top.retain(|(t, _)| *t != NONC);
        let result = check(&server, &request, &nonce, &frame(&encode(top)));
        match Profile::of(version).leaf {
            Leaf::Packet => assert_eq!(result, Err(Invalid("no NONC")), "{version:?}"),
            Leaf::Nonce => assert!(result.is_ok(), "{version:?}"),
        }
    }
}

#[test]
fn mjd_timestamps() {
    let p = Profile::of(RoughtimeVersion::Draft07);
    // 2026-10-26T23:21:11.5Z: MJD 61339.
    let raw = (61_339u64 << 40) | 84_071_500_000;
    assert_eq!(p.timestamp(raw), 1_793_056_871_500_000);
    assert_eq!(Profile::of(RoughtimeVersion::Rfc10049).timestamp(5), 5_000_000);
}

// ---------------------------------------------------------------------------------------
// Captured live replies and RFC 10049 Appendix B

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/roughtime")
}

struct Capture {
    name: String,
    version: RoughtimeVersion,
    public_key: [u8; 32],
    request: Vec<u8>,
    response: Vec<u8>,
    captured_at: u64,
}

fn version_named(name: &str) -> RoughtimeVersion {
    ALL.into_iter().find(|v| format!("{v:?}") == name).unwrap_or_else(|| panic!("version {name}"))
}

fn captures() -> Vec<Capture> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(data_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".json") || name.starts_with("rfc10049-appendix") {
            continue;
        }
        let j: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let hex = |k: &str| hex::decode(j[k].as_str().unwrap()).unwrap();
        out.push(Capture {
            name,
            version: version_named(j["version"].as_str().unwrap()),
            public_key: hex("public_key").try_into().unwrap(),
            request: hex("request"),
            response: hex("response"),
            captured_at: j["captured_at"].as_u64().unwrap(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[test]
fn every_captured_profile_verifies() {
    let captures = captures();
    for version in ALL {
        assert!(captures.iter().any(|c| c.version == version), "no capture for {version:?}");
    }
    for c in &captures {
        let nonce = nonce_of(&c.request);
        let sample = Profile::of(c.version)
            .verify(&c.public_key, &c.request, &nonce, &c.response)
            .unwrap_or_else(|e| panic!("{}: {e:?}", c.name));
        let captured = i128::from(c.captured_at) * 1_000_000;
        assert!((sample.midp - captured).abs() < 60_000_000, "{}: MIDP far from the capture time", c.name);
        assert!(sample.radius > 0 && sample.radius <= 10_000_000, "{}", c.name);
    }
}

#[test]
fn default_servers_are_the_captured_ones() {
    let servers = default_servers();
    let operators: BTreeSet<_> = servers.iter().map(|s| s.operator.as_str()).collect();
    assert_eq!(operators.len(), 5);
    assert!(2 * DEFAULT_MIN_AGREEING > operators.len());
    let captures = captures();
    for s in &servers {
        assert!(
            captures.iter().any(|c| c.public_key == s.public_key && c.version == s.version),
            "no capture for {}",
            s.address
        );
    }
}

#[test]
fn tampered_captures_are_refused() {
    for c in captures() {
        let p = Profile::of(c.version);
        let nonce = nonce_of(&c.request);
        let verify = |packet: &[u8]| p.verify(&c.public_key, &c.request, &nonce, packet);
        assert!(verify(&c.response).is_ok());
        assert_eq!(verify(&edit(&c.response, &[SIG], flip)), Err(Invalid("response signature")), "{}", c.name);
        assert_eq!(verify(&edit(&c.response, &[CERT, SIG], flip)), Err(Invalid("delegation signature")), "{}", c.name);
        assert_eq!(verify(&edit(&c.response, &[CERT, DELE, MINT], flip)), Err(Invalid("delegation signature")));
        assert_eq!(verify(&edit(&c.response, &[SREP, MIDP], flip)), Err(Invalid("response signature")));
        assert_eq!(verify(&edit(&c.response, &[SREP, ROOT], flip)), Err(Invalid("response signature")));
        if Message::parse(unframe(&c.response).unwrap()).unwrap().get(NONC).is_some() {
            assert_eq!(verify(&edit(&c.response, &[NONC], flip)), Err(Invalid("nonce not echoed")));
        }
        let merkle = Err(Invalid("Merkle proof does not lead to ROOT"));
        assert_eq!(verify(&edit(&c.response, &[INDX], |v| v[3] ^= 0x80)), merkle, "{}", c.name);
        if !Message::parse(unframe(&c.response).unwrap()).unwrap().get(PATH).unwrap().is_empty() {
            assert_eq!(verify(&edit(&c.response, &[PATH], flip)), merkle, "{}", c.name);
        }
        assert!(p.verify(&[9; 32], &c.request, &nonce, &c.response).is_err());
        for other in ALL.into_iter().filter(|v| *v != c.version) {
            assert!(Profile::of(other).verify(&c.public_key, &c.request, &nonce, &c.response).is_err());
        }
    }
}

/// RFC 10049 Appendix B is signed with the draft labels (`RoughTime`, not `Roughtime`), so it
/// verifies only with those: version 1 otherwise, packet leaves and `HashFirst` included.
#[test]
fn rfc10049_appendix_b() {
    let j: serde_json::Value =
        serde_json::from_slice(&std::fs::read(data_dir().join("rfc10049-appendix-b.json")).unwrap()).unwrap();
    let with_draft_labels =
        Profile { response_context: DRAFT_RESPONSE, delegation_context: DRAFT_DELEGATION, ..RFC10049 };
    let responses = j["responses"].as_array().unwrap();
    assert_eq!(responses.len(), 3);
    let mut previous: Option<Vec<u8>> = None;
    for r in responses {
        let hex = |k: &str| hex::decode(r[k].as_str().unwrap()).unwrap();
        let public_key: [u8; 32] = hex("public_key").try_into().unwrap();
        let (request, response) = (hex("request"), hex("response"));
        let nonce = nonce_of(&request);
        // §8.2: each nonce after the first is H(previous response || rand).
        if let Some(previous) = &previous {
            assert_eq!(nonce, Hash::Sha512Trunc.of(&[previous, &hex("rand")]));
        }
        let sample = with_draft_labels.verify(&public_key, &request, &nonce, &response).unwrap();
        assert_eq!(sample.radius, 3_000_000);
        assert_eq!(RFC10049.verify(&public_key, &request, &nonce, &response), Err(Invalid("delegation signature")));
        previous = Some(response);
    }
}

// ---------------------------------------------------------------------------------------
// Agreement over a simulated network (tokio's paused clock)

/// The true time, `NOW_US` when the network was built, advancing with tokio's clock.
struct FakeNet {
    start: Instant,
    servers: HashMap<String, Fake>,
}

struct Fake {
    server: TestServer,
    /// How wrong this server's clock is.
    error_us: i128,
    /// Each way.
    delay: Duration,
    silent: bool,
    /// Ignore the caller's timeout (a slow transport).
    no_timeout: bool,
    /// Replies spoiled (greased) before a good one.
    spoiled: usize,
    calls: AtomicUsize,
}

impl Fake {
    fn new(server: TestServer) -> Self {
        Self {
            server,
            error_us: 0,
            delay: Duration::ZERO,
            silent: false,
            no_timeout: false,
            spoiled: 0,
            calls: AtomicUsize::new(0),
        }
    }
}

impl FakeNet {
    fn truth(&self) -> i128 {
        NOW_US + micros(Instant::now() - self.start)
    }
}

#[async_trait]
impl Datagrams for FakeNet {
    async fn exchange(&self, host: &str, port: u16, request: &[u8], timeout: Duration) -> Result<Vec<u8>, NetError> {
        let lost = || NetError::Connect { host: host.into(), port, reason: "no reply".into() };
        let fake = self.servers.get(&format!("{host}:{port}")).ok_or_else(lost)?;
        let call = fake.calls.fetch_add(1, Ordering::SeqCst);
        let work = async {
            tokio::time::sleep(fake.delay).await;
            let mut reply = fake.server.respond(request, self.truth() + fake.error_us);
            if call < fake.spoiled {
                reply = edit(&reply, &[SIG], flip);
            }
            tokio::time::sleep(fake.delay).await;
            reply
        };
        if fake.silent {
            tokio::time::sleep(timeout).await;
            return Err(lost());
        }
        if fake.no_timeout {
            return Ok(work.await);
        }
        tokio::time::timeout(timeout, work).await.map_err(|_| lost())
    }
}

struct Setup {
    servers: Vec<RoughtimeServer>,
    fakes: Vec<(String, Fake)>,
}

impl Setup {
    fn new() -> Self {
        Self { servers: Vec::new(), fakes: Vec::new() }
    }
    /// Adds a server of `operator`; `tweak` adjusts its fake.
    fn add(mut self, operator: &str, version: RoughtimeVersion, tweak: impl FnOnce(&mut Fake)) -> Self {
        let n = self.servers.len() as u8;
        let address = format!("s{n}.test:2002");
        let server = TestServer::new(10 + n, version);
        self.servers.push(server.config(&address, operator));
        let mut fake = Fake::new(server);
        tweak(&mut fake);
        self.fakes.push((address, fake));
        self
    }
    fn honest(self, operator: &str, version: RoughtimeVersion) -> Self {
        self.add(operator, version, |_| {})
    }
    async fn run(self, min_agreeing: usize) -> (Result<TrustedTime, TeeError>, i128) {
        let net = Arc::new(FakeNet { start: Instant::now(), servers: self.fakes.into_iter().collect() });
        let clock = RoughtimeClock::new(self.servers, min_agreeing, net.clone());
        let result = clock.now().await;
        (result, net.truth())
    }
}

fn contains(t: &TrustedTime, truth_us: i128) -> bool {
    i128::from(t.earliest()) * 1_000_000 <= truth_us && truth_us <= i128::from(t.latest()) * 1_000_000
}

const HOUR_US: i128 = 3_600_000_000;

#[tokio::test(start_paused = true)]
async fn honest_operators_agree() {
    use RoughtimeVersion::*;
    let (result, truth) = Setup::new()
        .honest("a", Rfc10049)
        .honest("b", Draft12)
        .honest("c", Draft11)
        .honest("d", Draft07)
        .honest("d", Draft07)
        .run(3)
        .await;
    let t = result.unwrap();
    assert!(contains(&t, truth), "{t:?} vs {truth}");
    assert!(t.radius <= 2, "{t:?}");
}

#[tokio::test(start_paused = true)]
async fn falseticker_is_outvoted() {
    use RoughtimeVersion::*;
    let (result, truth) = Setup::new()
        .honest("a", Rfc10049)
        .honest("b", Draft12)
        .honest("c", Draft11)
        .add("liar", Draft07, |f| f.error_us = HOUR_US)
        .run(3)
        .await;
    let t = result.unwrap();
    assert!(contains(&t, truth) && t.radius <= 2, "{t:?}");
}

#[tokio::test(start_paused = true)]
async fn disagreeing_operator_counts_once() {
    // Three servers of one wrong operator against three honest operators: by server it would
    // be a tie; by operator it is three against one.
    use RoughtimeVersion::*;
    let (result, truth) = Setup::new()
        .honest("a", Rfc10049)
        .honest("b", Draft12)
        .honest("c", Draft11)
        .add("liar", Draft07, |f| f.error_us = -HOUR_US)
        .add("liar", Draft07, |f| f.error_us = -HOUR_US)
        .add("liar", Draft12, |f| f.error_us = -HOUR_US)
        .run(3)
        .await;
    let t = result.unwrap();
    assert!(contains(&t, truth) && t.radius <= 2, "{t:?}");
}

#[tokio::test(start_paused = true)]
async fn too_few_operators_is_unavailable() {
    use RoughtimeVersion::*;
    let (result, _) =
        Setup::new().honest("a", Rfc10049).honest("b", Draft12).add("c", Draft11, |f| f.silent = true).run(3).await;
    assert!(matches!(result, Err(TeeError::Unavailable(_))), "{result:?}");
    let (result, _) = Setup::new().run(3).await;
    assert!(matches!(result, Err(TeeError::Unavailable(_))), "{result:?}");
}

#[tokio::test(start_paused = true)]
async fn two_servers_of_one_operator_count_once() {
    use RoughtimeVersion::*;
    let (result, _) =
        Setup::new().honest("netnod", Draft07).honest("netnod", Draft07).honest("b", Draft12).run(3).await;
    assert!(matches!(result, Err(TeeError::Unavailable(_))), "{result:?}");
    let (result, _) = Setup::new()
        .honest("netnod", Draft07)
        .honest("netnod", Draft07)
        .honest("b", Draft12)
        .honest("c", Draft11)
        .run(3)
        .await;
    assert!(result.is_ok());
}

#[tokio::test(start_paused = true)]
async fn no_strict_majority_is_unavailable() {
    use RoughtimeVersion::*;
    let (result, _) = Setup::new()
        .honest("a", Rfc10049)
        .honest("b", Draft12)
        .add("x", Draft11, |f| f.error_us = HOUR_US)
        .add("y", Draft07, |f| f.error_us = HOUR_US)
        .run(2)
        .await;
    assert!(matches!(result, Err(TeeError::Unavailable(_))), "{result:?}");
}

#[tokio::test(start_paused = true)]
async fn round_trip_widens_the_interval() {
    use RoughtimeVersion::*;
    // Draft 7: RADI 0.1 s, so the round trip dominates.
    let (fast, truth) = Setup::new().honest("a", Draft07).run(1).await;
    let fast = fast.unwrap();
    assert!(contains(&fast, truth) && fast.radius <= 1, "{fast:?}");
    let (slow, truth) = Setup::new().add("a", Draft07, |f| f.delay = Duration::from_millis(1_500)).run(1).await;
    let slow = slow.unwrap();
    // 3 s round trip plus 0.2 s: at least 1.6 s each side of the midpoint.
    assert!(contains(&slow, truth) && slow.radius >= 2, "{slow:?}");
    // The server signed early in the round trip; the reply arrived 1.5 s later.
    let (late, truth) = Setup::new()
        .add("a", Draft07, |f| {
            f.delay = Duration::from_millis(1_500);
            f.error_us = -1_400_000;
        })
        .run(1)
        .await;
    assert!(contains(&late.unwrap(), truth));
}

#[tokio::test(start_paused = true)]
async fn round_trips_over_the_cap_are_discarded() {
    use RoughtimeVersion::*;
    let (result, _) = Setup::new().add("a", Draft12, |f| f.delay = Duration::from_secs(3)).run(1).await;
    assert!(matches!(result, Err(TeeError::Unavailable(_))), "{result:?}");
    let (result, _) = Setup::new()
        .add("a", Draft12, |f| {
            f.delay = Duration::from_secs(3);
            f.no_timeout = true;
        })
        .run(1)
        .await;
    assert!(matches!(result, Err(TeeError::Unavailable(_))), "{result:?}");
}

#[tokio::test(start_paused = true)]
async fn readings_carried_past_the_cap_are_discarded() {
    // A host that jumps the monotonic clock forward after the replies arrive shifts every
    // reading alike; the carry bounds how far.
    let sent = Instant::now();
    let reading = |at: Duration| Reading { sent, received: sent + at, sample: Sample { midp: NOW_US, radius: 1 } };
    let readings = vec![("a".to_owned(), reading(Duration::from_millis(10)))];
    assert_eq!(carry(&readings, sent + MAX_CARRY).len(), 1);
    assert!(carry(&readings, sent + MAX_CARRY + Duration::from_millis(1)).is_empty());
    assert!(carry(&readings, sent + Duration::from_secs(3_600)).is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_slow_transport_ends_at_the_query_timeout() {
    use RoughtimeVersion::*;
    // A transport that ignores its timeout cannot hold the call open, or stretch the carry of
    // the servers that answered.
    let (result, truth) = Setup::new()
        .honest("a", Rfc10049)
        .add("b", Draft12, |f| {
            f.delay = Duration::from_secs(3_600);
            f.no_timeout = true;
        })
        .run(1)
        .await;
    let t = result.unwrap();
    assert!(contains(&t, truth) && t.radius <= 2, "{t:?}");
}

#[tokio::test(start_paused = true)]
async fn a_greased_reply_is_retried() {
    use RoughtimeVersion::*;
    let (result, _) = Setup::new().add("a", Rfc10049, |f| f.spoiled = 1).run(1).await;
    assert!(result.is_ok());
    let (result, _) = Setup::new().add("a", Rfc10049, |f| f.spoiled = ATTEMPTS).run(1).await;
    assert!(result.is_err());
}

#[test]
fn ties_take_the_hull() {
    let iv = |lo, hi, operator| Interval { lo, hi, operator };
    // a overlaps b and c; b and c do not overlap: two cliques of two.
    let intervals = [iv(0, 100, "a"), iv(10, 20, "b"), iv(50, 60, "c")];
    assert_eq!(agree(&intervals, 2), Ok((10, 60)));
    assert!(agree(&intervals, 3).is_err());
    assert_eq!(agree(&[iv(0, 10, "a")], 0), Ok((0, 10)));
    assert!(agree(&[], 1).is_err());
}

#[test]
fn trusted_time_rounds_outwards() {
    assert_eq!(to_trusted_time(10_200_000, 10_800_000), Ok(TrustedTime { now: 10, radius: 1 }));
    assert_eq!(to_trusted_time(10_000_000, 10_000_000), Ok(TrustedTime { now: 10, radius: 0 }));
    let t = to_trusted_time(7_900_000, 12_100_001).unwrap();
    assert!(t.earliest() * 1_000_000 <= 7_900_000 && t.latest() * 1_000_000 >= 12_100_001, "{t:?}");
    assert!(to_trusted_time(-1, 5).is_err());
}

// ---------------------------------------------------------------------------------------
// Arbitrary input

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Message::parse(&bytes);
        let _ = unframe(&bytes);
        let mut framed = MAGIC.to_vec();
        framed.extend((bytes.len() as u32).to_le_bytes());
        framed.extend(&bytes);
        for version in ALL {
            let p = Profile::of(version);
            let _ = p.verify(&[1; 32], &bytes, &[2; 32], &bytes);
            let _ = p.verify(&[1; 32], &bytes, &[2; 32], &framed);
        }
    }

    #[test]
    fn mutated_replies_never_panic(at in any::<prop::sample::Index>(), byte in any::<u8>(), v in 0..4usize) {
        let server = TestServer::new(7, ALL[v]);
        let (request, nonce, mut reply) = exchange(&server, NOW_US);
        let i = at.index(reply.len());
        reply[i] = byte;
        let _ = check(&server, &request, &nonce, &reply);
    }
}

// ---------------------------------------------------------------------------------------
// Live (network): `cargo test -p seal-tee -- --ignored live`

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// Queries every default server once and checks each reply. With `SEAL_ROUGHTIME_CAPTURE=1`
/// also writes them to `tests/data/roughtime/` (the captured profiles above).
#[tokio::test]
#[ignore]
async fn live_default_servers_capture() {
    let capture = std::env::var_os("SEAL_ROUGHTIME_CAPTURE").is_some_and(|v| v == "1");
    let udp = seal_net::UdpDatagrams;
    let mut answered = 0;
    for server in default_servers() {
        let (host, port) = server.address.rsplit_once(':').unwrap();
        let p = Profile::of(server.version);
        let nonce = random_nonce(&mut rand::rand_core::UnwrapErr(rand::rngs::SysRng));
        let request = p.request(&server.public_key, &nonce);
        let sent = Instant::now();
        let Ok(response) = udp.exchange(host, port.parse().unwrap(), &request, MAX_RTT).await else {
            eprintln!("{}: no reply", server.address);
            continue;
        };
        let rtt = Instant::now() - sent;
        let sample = p.verify(&server.public_key, &request, &nonce, &response);
        eprintln!("{} {:?}: {sample:?} in {} ms", server.address, server.version, rtt.as_millis());
        let sample = sample.unwrap();
        assert!((sample.midp / 1_000_000 - i128::from(unix_now())).abs() < 30);
        answered += 1;
        if capture {
            let json = serde_json::json!({
                "server": server.address,
                "operator": server.operator,
                "version": format!("{:?}", server.version),
                "public_key": hex::encode(server.public_key),
                "request": hex::encode(&request),
                "response": hex::encode(&response),
                "rtt_ms": rtt.as_millis() as u64,
                "captured_at": unix_now(),
            });
            let name = format!("{:?}-{}", server.version, host.replace('.', "-")).to_lowercase();
            let path = data_dir().join(format!("{name}.json"));
            std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap() + "\n").unwrap();
        }
    }
    assert!(answered >= DEFAULT_MIN_AGREEING);
}

#[tokio::test]
#[ignore]
async fn live_clock() {
    let clock = RoughtimeClock::new(default_servers(), DEFAULT_MIN_AGREEING, Arc::new(seal_net::UdpDatagrams));
    let t = clock.now().await.unwrap();
    eprintln!("{t:?}");
    assert!(t.radius <= 10);
    let host = unix_now();
    assert!(t.earliest() <= host + 2 && host <= t.latest() + 2, "{t:?} vs host {host}");
}

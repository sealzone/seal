//! Roughtime client (RFC 10049), the clock on Azure, GCP and the guardians (Nitro uses its
//! hypervisor's signed timestamp, `nitro::NitroClock`). Queries `servers` with fresh nonces
//! over UDP (`seal_net::Datagrams`), verifies each signed
//! response against the server's pinned key, and returns the intersection of the agreeing
//! intervals.
//!
//! - Each server's wire profile is pinned (`RoughtimeVersion`): servers drop requests in a
//!   version they do not speak instead of negotiating. The request offers only that version,
//!   and a reply naming another one is refused.
//! - A reply counts only if the delegation (`CERT`) verifies under the pinned key, the signed
//!   response (`SREP`) under the delegated key, the Merkle proof (`INDX`, `PATH`) leads from
//!   our request (or our nonce, in the drafts that hash the nonce) to the signed `ROOT`, `NONC`
//!   echoes our nonce (required where the leaf is the request; where it is the nonce the
//!   signed root binds it already), and `MIDP` lies within the delegation's `MINT..MAXT`.
//! - The interval is widened by the measured round trip: the true time lies in
//!   `[MIDP - RADI, MIDP + RADI + rtt]`. Round trips over `MAX_RTT` are discarded. So whoever
//!   carries the packets can drop them, or delay them within the cap, which only widens the
//!   interval; it can never rewind or forge, since replies are signed over our nonce.
//!   Intervals are carried to one common instant with the monotonic clock, never the host's
//!   wall clock.
//! - Agreement is counted per operator: at least `min_agreeing` distinct operators whose
//!   intervals overlap, and they must be a strict majority of the operators that answered
//!   validly, so a signed but wrong server is outvoted. The result is the intersection of the
//!   intervals that overlap at the point where most operators agree (if several points tie,
//!   the hull of their intersections), as a midpoint and a radius rounded outwards to whole
//!   seconds.
//! - Otherwise `TeeError::Unavailable`: callers fail closed and never fall back to the host's
//!   clock.
//!
//! Every server is queried at once, each up to `ATTEMPTS` times (servers grease: they send a
//! fraction of deliberately invalid replies).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use seal_proto::TrustedTime;
use sha2::{Digest, Sha512, Sha512_256};
use tokio::time::Instant;

use crate::TeeError;

/// Replies slower than this are discarded.
pub const MAX_RTT: Duration = Duration::from_secs(5);

/// Tries per server and `now` call.
const ATTEMPTS: usize = 2;

/// The wire profile a server speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoughtimeVersion {
    /// RFC 10049, version `0x1`.
    Rfc10049,
    /// Drafts 12–19, version `0x8000000c`.
    Draft12,
    /// Draft 11. Some servers answer only a request padded to 1024 bytes.
    Draft11,
    /// Draft 7.
    Draft07,
}

#[derive(Clone, Debug)]
pub struct RoughtimeServer {
    /// `host:port`, e.g. `roughtime.cloudflare.com:2003`.
    pub address: String,
    pub public_key: [u8; 32],
    pub version: RoughtimeVersion,
    /// Who runs it. Servers of one operator count once toward `min_agreeing`.
    pub operator: String,
}

/// The `min_agreeing` to use with `default_servers`.
pub const DEFAULT_MIN_AGREEING: usize = 3;

/// The production set: five operators, each server pinned to the profile it answers.
pub fn default_servers() -> Vec<RoughtimeServer> {
    use RoughtimeVersion::*;
    #[rustfmt::skip]
    let servers = [
        ("roughtime.cloudflare.com:2003", Draft11, "Cloudflare",
         "d060fb737c8ff3111ce19976cdeb8dd9294bbc3555a1c8ec3d22fcfd197fef38"),
        ("sth1.roughtime.netnod.se:2002", Draft07, "Netnod",
         "f65d493781da9069c6e38cb2ab234d09bd073745dfb32b016e797f91b6686437"),
        ("sth2.roughtime.netnod.se:2002", Draft07, "Netnod",
         "4ffc715f811150100ea6deb867ca6159a98ab00499c49d155ae88f9b7192ffc8"),
        ("rough.time.nl:2002", Draft12, "TimeNL",
         "bf60a27af8602acc739563f0224605517780e75024864bf9ba12428f5fe46e26"),
        ("roughtime.int08h.com:2002", Draft12, "int08h",
         "016e6e0284d24c37c6e4d7d8d5b4e1d3c1949ceaa545bf875616c9dce0c9bec1"),
        ("time.txryan.com:2002", Rfc10049, "txryan",
         "881563c60ff58fbcb5fa44144c161d4da6f10a9a5eb14ff4ec3e0f303264d960"),
    ];
    servers
        .into_iter()
        .map(|(address, version, operator, public_key)| RoughtimeServer {
            address: address.into(),
            public_key: key(public_key),
            version,
            operator: operator.into(),
        })
        .collect()
}

/// A 32-byte key from 64 hex digits (the constants above).
fn key(hex: &str) -> [u8; 32] {
    let digit = |c: u8| (c as char).to_digit(16).expect("hex key") as u8;
    let b = hex.as_bytes();
    assert_eq!(b.len(), 64, "hex key");
    std::array::from_fn(|i| digit(b[2 * i]) << 4 | digit(b[2 * i + 1]))
}

pub struct RoughtimeClock {
    servers: Vec<RoughtimeServer>,
    min_agreeing: usize,
    datagrams: Arc<dyn seal_net::Datagrams>,
}

impl RoughtimeClock {
    /// `min_agreeing` is 3 in production.
    pub fn new(servers: Vec<RoughtimeServer>, min_agreeing: usize, datagrams: Arc<dyn seal_net::Datagrams>) -> Self {
        Self { servers, min_agreeing, datagrams }
    }

    pub async fn now(&self) -> Result<TrustedTime, TeeError> {
        let mut queries = tokio::task::JoinSet::new();
        for server in self.servers.iter().cloned() {
            let datagrams = self.datagrams.clone();
            queries.spawn(async move {
                let reading = query(&server, &*datagrams).await;
                (server, reading)
            });
        }
        let mut readings = Vec::new();
        while let Some(joined) = queries.join_next().await {
            match joined {
                Ok((server, Ok(reading))) => readings.push((server.operator, reading)),
                Ok((server, Err(reason))) => {
                    tracing::warn!(server = %server.address, %reason, "roughtime server not counted")
                }
                Err(e) => tracing::warn!(error = %e, "roughtime query task failed"),
            }
        }
        // Carry every interval to this one instant: offsets on the monotonic clock only.
        let end = Instant::now();
        let intervals: Vec<Interval> = readings
            .iter()
            .map(|(operator, r)| Interval {
                lo: r.sample.midp - r.sample.radius + micros(end - r.received),
                hi: r.sample.midp + r.sample.radius + micros(end - r.sent),
                operator,
            })
            .collect();
        let (lo, hi) = agree(&intervals, self.min_agreeing).map_err(TeeError::Unavailable)?;
        to_trusted_time(lo, hi).map_err(TeeError::Unavailable)
    }
}

fn micros(d: Duration) -> i128 {
    d.as_micros() as i128
}

fn random_nonce(rng: &mut impl rand::CryptoRng) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// A verified reply and when, on the monotonic clock, we sent the request and got the reply.
struct Reading {
    sent: Instant,
    received: Instant,
    sample: Sample,
}

async fn query(server: &RoughtimeServer, datagrams: &dyn seal_net::Datagrams) -> Result<Reading, String> {
    let (host, port) = server
        .address
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?)))
        .ok_or_else(|| format!("address {:?} is not host:port", server.address))?;
    let profile = Profile::of(server.version);
    let mut last = String::new();
    for _ in 0..ATTEMPTS {
        let nonce = random_nonce(&mut rand::rand_core::UnwrapErr(rand::rngs::SysRng));
        let request = profile.request(&server.public_key, &nonce);
        let sent = Instant::now();
        let reply = match datagrams.exchange(host, port, &request, MAX_RTT).await {
            Ok(reply) => reply,
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        let received = Instant::now();
        if received - sent > MAX_RTT {
            last = format!("round trip {} ms over the cap", (received - sent).as_millis());
            continue;
        }
        match profile.verify(&server.public_key, &request, &nonce, &reply) {
            Ok(sample) => return Ok(Reading { sent, received, sample }),
            Err(Invalid(why)) => last = format!("invalid reply: {why}"),
        }
    }
    Err(last)
}

// ---------------------------------------------------------------------------------------
// Agreement

struct Interval<'a> {
    /// Microseconds since the Unix epoch, at one common instant.
    lo: i128,
    hi: i128,
    operator: &'a str,
}

/// The intersection of the intervals overlapping where the most distinct operators agree.
fn agree(intervals: &[Interval], min_agreeing: usize) -> Result<(i128, i128), String> {
    let answered = intervals.iter().map(|i| i.operator).collect::<BTreeSet<_>>().len();
    let mut best = 0;
    let mut hull = None;
    // The most-overlapped region of a set of intervals starts at one of their lower ends.
    for point in intervals.iter().map(|i| i.lo) {
        let members: Vec<&Interval> = intervals.iter().filter(|i| i.lo <= point && point <= i.hi).collect();
        let operators = members.iter().map(|i| i.operator).collect::<BTreeSet<_>>().len();
        let lo = members.iter().map(|i| i.lo).max().unwrap_or(point);
        let hi = members.iter().map(|i| i.hi).min().unwrap_or(point);
        if operators > best {
            best = operators;
            hull = Some((lo, hi));
        } else if operators == best {
            hull = hull.map(|(a, b): (i128, i128)| (a.min(lo), b.max(hi)));
        }
    }
    let needed = min_agreeing.max(1);
    if best < needed {
        return Err(format!("{best} roughtime operators agree, {needed} needed ({answered} answered)"));
    }
    if 2 * best <= answered {
        return Err(format!("{best} of {answered} roughtime operators agree: no strict majority"));
    }
    hull.ok_or_else(|| "no roughtime reply".to_string())
}

/// `[lo, hi]` in microseconds as a whole-second midpoint and a radius that covers both ends.
fn to_trusted_time(lo: i128, hi: i128) -> Result<TrustedTime, String> {
    const US: i128 = 1_000_000;
    if lo < 0 || hi < lo {
        return Err("roughtime interval empty or before the Unix epoch".into());
    }
    let now = ((lo + hi) / 2).div_euclid(US);
    let radius_us = (hi - now * US).max(now * US - lo);
    let radius = (radius_us + US - 1).div_euclid(US);
    let too_late = |_| "roughtime interval out of range".to_string();
    Ok(TrustedTime { now: u64::try_from(now).map_err(too_late)?, radius: u64::try_from(radius).map_err(too_late)? })
}

// ---------------------------------------------------------------------------------------
// Wire format: a message is a uint32 count N, N-1 uint32 offsets, N uint32 tags (strictly
// ascending), then the values; a packet is `ROUGHTIM`, a uint32 length and one message.
// Everything little-endian.

const fn tag(name: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*name)
}

const SIG: u32 = tag(b"SIG\0");
const VER: u32 = tag(b"VER\0");
const SRV: u32 = tag(b"SRV\0");
const NONC: u32 = tag(b"NONC");
const DELE: u32 = tag(b"DELE");
const TYPE: u32 = tag(b"TYPE");
const PATH: u32 = tag(b"PATH");
const RADI: u32 = tag(b"RADI");
const PUBK: u32 = tag(b"PUBK");
const MIDP: u32 = tag(b"MIDP");
const SREP: u32 = tag(b"SREP");
const VERS: u32 = tag(b"VERS");
const ROOT: u32 = tag(b"ROOT");
const CERT: u32 = tag(b"CERT");
const MINT: u32 = tag(b"MINT");
const MAXT: u32 = tag(b"MAXT");
const INDX: u32 = tag(b"INDX");
const ZZZZ: u32 = tag(b"ZZZZ");

const MAGIC: &[u8; 8] = b"ROUGHTIM";

/// Why a reply was refused. Logged, never returned to callers.
#[derive(Debug, PartialEq, Eq)]
struct Invalid(&'static str);

type Check<T> = Result<T, Invalid>;

struct Message<'a> {
    tags: Vec<u32>,
    values: Vec<&'a [u8]>,
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl<'a> Message<'a> {
    fn parse(buf: &'a [u8]) -> Check<Self> {
        if buf.len() < 4 {
            return Err(Invalid("short message"));
        }
        let n = le32(buf, 0) as usize;
        if n == 0 {
            return Err(Invalid("empty message"));
        }
        let header = n.checked_mul(8).filter(|&h| h <= buf.len()).ok_or(Invalid("short header"))?;
        let body = &buf[header..];
        let mut offsets = vec![0usize];
        offsets.extend((0..n - 1).map(|i| le32(buf, 4 + 4 * i) as usize));
        offsets.push(body.len());
        let tags: Vec<u32> = (0..n).map(|i| le32(buf, 4 * n + 4 * i)).collect();
        if tags.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Invalid("tags not strictly ascending"));
        }
        if offsets.iter().take(n).any(|o| o % 4 != 0) || offsets.windows(2).any(|w| w[0] > w[1]) {
            return Err(Invalid("bad offsets"));
        }
        let values = offsets.windows(2).map(|w| &body[w[0]..w[1]]).collect();
        Ok(Self { tags, values })
    }
    fn get(&self, tag: u32) -> Option<&'a [u8]> {
        self.tags.binary_search(&tag).ok().map(|i| self.values[i])
    }
    fn need(&self, tag: u32, missing: &'static str) -> Check<&'a [u8]> {
        self.get(tag).ok_or(Invalid(missing))
    }
    fn fixed<const N: usize>(&self, tag: u32, bad: &'static str) -> Check<[u8; N]> {
        self.need(tag, bad)?.try_into().map_err(|_| Invalid(bad))
    }
    fn u32(&self, tag: u32, bad: &'static str) -> Check<u32> {
        self.fixed::<4>(tag, bad).map(u32::from_le_bytes)
    }
    fn u64(&self, tag: u32, bad: &'static str) -> Check<u64> {
        self.fixed::<8>(tag, bad).map(u64::from_le_bytes)
    }
}

fn encode(mut pairs: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    pairs.sort_by_key(|p| p.0);
    let mut out = (pairs.len() as u32).to_le_bytes().to_vec();
    let mut offset = 0u32;
    for (_, value) in &pairs[..pairs.len() - 1] {
        offset += value.len() as u32;
        out.extend(offset.to_le_bytes());
    }
    for (tag, _) in &pairs {
        out.extend(tag.to_le_bytes());
    }
    for (_, value) in &pairs {
        out.extend(value);
    }
    out
}

fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend((message.len() as u32).to_le_bytes());
    out.extend(message);
    out
}

fn unframe(packet: &[u8]) -> Check<&[u8]> {
    if packet.len() < 12 || &packet[..8] != MAGIC {
        return Err(Invalid("no ROUGHTIM header"));
    }
    if le32(packet, 8) as usize != packet.len() - 12 {
        return Err(Invalid("packet length mismatch"));
    }
    Ok(&packet[12..])
}

// ---------------------------------------------------------------------------------------
// Profiles

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    /// The first 32 bytes of SHA-512.
    Sha512Trunc,
    /// SHA-512/256 (draft 7).
    Sha512_256,
}

impl Hash {
    fn of(self, parts: &[&[u8]]) -> [u8; 32] {
        fn run<D: Digest>(parts: &[&[u8]]) -> [u8; 32] {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            let out = d.finalize();
            std::array::from_fn(|i| out[i])
        }
        match self {
            Hash::Sha512Trunc => run::<Sha512>(parts),
            Hash::Sha512_256 => run::<Sha512_256>(parts),
        }
    }
}

/// Which side the running hash takes when the current `INDX` bit is 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    /// `H(0x01 || h || node)`: RFC 10049 and drafts 16–19.
    HashFirst,
    /// `H(0x01 || node || h)`: drafts 7–15.
    NodeFirst,
}

/// Whether the Merkle leaf is the whole request packet or only the nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leaf {
    Packet,
    Nonce,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Time {
    /// Seconds since the Unix epoch; `RADI` in seconds.
    UnixSeconds,
    /// Modified Julian Date in the top 3 bytes, microseconds of the day in the low 5; `RADI`
    /// in microseconds (draft 7).
    MjdMicros,
}

/// Where a reply names its version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VersionIn {
    /// `VER` (and the server's `VERS` list, which must contain it) inside the signed `SREP`.
    Srep,
    /// `VER` at the top level, unsigned (drafts up to 11).
    TopLevel,
}

#[derive(Clone, Copy, Debug)]
struct Profile {
    number: u32,
    hash: Hash,
    leaf: Leaf,
    /// Merkle orders accepted without a `TYPE` tag in the reply, and with one. Draft 12's
    /// number covers drafts 12–19, which changed the order at draft 16 (always typed, as
    /// `TYPE` came with draft 14). Draft 7's text gives one order and its pseudocode the
    /// other. Either is safe: `ROOT` is signed and the leaf is ours.
    orders: &'static [Order],
    typed_orders: &'static [Order],
    time: Time,
    response_context: &'static [u8],
    delegation_context: &'static [u8],
    version_in: VersionIn,
    /// The request carries `TYPE = 0`.
    type_request: bool,
    /// The reply must carry `TYPE = 1` (any reply that carries `TYPE` must have 1).
    type_required: bool,
    /// Pad the whole packet (header included) to this size, or else the message to 1024.
    packet_size: Option<usize>,
    /// RFC 10049 forbids `RADI = 0`.
    nonzero_radius: bool,
}

const RFC_RESPONSE: &[u8] = b"Roughtime v1 response signature\0";
const RFC_DELEGATION: &[u8] = b"Roughtime v1 delegation signature\0";
const DRAFT_RESPONSE: &[u8] = b"RoughTime v1 response signature\0";
const DRAFT_DELEGATION: &[u8] = b"RoughTime v1 delegation signature\0";
const DRAFT11_DELEGATION: &[u8] = b"RoughTime v1 delegation signature--\0";

const RFC10049: Profile = Profile {
    number: 0x1,
    hash: Hash::Sha512Trunc,
    leaf: Leaf::Packet,
    orders: &[Order::HashFirst],
    typed_orders: &[Order::HashFirst],
    time: Time::UnixSeconds,
    response_context: RFC_RESPONSE,
    delegation_context: RFC_DELEGATION,
    version_in: VersionIn::Srep,
    type_request: true,
    type_required: true,
    packet_size: None,
    nonzero_radius: true,
};

const DRAFT12: Profile = Profile {
    number: 0x8000_000c,
    orders: &[Order::NodeFirst],
    typed_orders: &[Order::NodeFirst, Order::HashFirst],
    response_context: DRAFT_RESPONSE,
    delegation_context: DRAFT_DELEGATION,
    // Drafts 14–19 need `TYPE` in requests; servers of drafts 12 and 13 ignore it.
    type_required: false,
    packet_size: Some(1024),
    nonzero_radius: false,
    ..RFC10049
};

const DRAFT11: Profile = Profile {
    number: 0x8000_000b,
    leaf: Leaf::Nonce,
    typed_orders: &[Order::NodeFirst],
    delegation_context: DRAFT11_DELEGATION,
    version_in: VersionIn::TopLevel,
    type_request: false,
    ..DRAFT12
};

const DRAFT07: Profile = Profile {
    number: 0x8000_0007,
    hash: Hash::Sha512_256,
    orders: &[Order::NodeFirst, Order::HashFirst],
    typed_orders: &[Order::NodeFirst, Order::HashFirst],
    time: Time::MjdMicros,
    delegation_context: DRAFT_DELEGATION,
    ..DRAFT11
};

/// A verified reply: `MIDP` and `RADI` in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sample {
    midp: i128,
    radius: i128,
}

impl Profile {
    fn of(version: RoughtimeVersion) -> Profile {
        match version {
            RoughtimeVersion::Rfc10049 => RFC10049,
            RoughtimeVersion::Draft12 => DRAFT12,
            RoughtimeVersion::Draft11 => DRAFT11,
            RoughtimeVersion::Draft07 => DRAFT07,
        }
    }

    /// `VER` (this version only), `NONC`, `SRV`, `TYPE` where defined, and `ZZZZ` padding.
    fn request(&self, public_key: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
        let mut pairs = vec![
            (VER, self.number.to_le_bytes().to_vec()),
            (NONC, nonce.to_vec()),
            (SRV, Hash::Sha512Trunc.of(&[&[0xff], public_key]).to_vec()),
        ];
        if self.type_request {
            pairs.push((TYPE, 0u32.to_le_bytes().to_vec()));
        }
        let header = 8 * (pairs.len() + 1);
        let used = header + pairs.iter().map(|p| p.1.len()).sum::<usize>();
        let message_size = self.packet_size.map_or(1024, |p| p - 12);
        pairs.push((ZZZZ, vec![0; message_size.saturating_sub(used) & !3]));
        frame(&encode(pairs))
    }

    fn verify(&self, public_key: &[u8; 32], request: &[u8], nonce: &[u8; 32], packet: &[u8]) -> Check<Sample> {
        let top = Message::parse(unframe(packet)?)?;
        let typed = match top.get(TYPE) {
            Some(_) if top.u32(TYPE, "bad TYPE")? != 1 => return Err(Invalid("TYPE is not 1")),
            Some(_) => true,
            None if self.type_required => return Err(Invalid("no TYPE")),
            None => false,
        };
        // Where the Merkle leaf is the nonce itself, the signed root already binds it, and
        // Cloudflare's draft-11 server leaves `NONC` out.
        match top.get(NONC) {
            Some(echoed) if echoed != nonce => return Err(Invalid("nonce not echoed")),
            None if self.leaf == Leaf::Packet => return Err(Invalid("no NONC")),
            _ => {}
        }
        let srep_bytes = top.need(SREP, "no SREP")?;
        let srep = Message::parse(srep_bytes)?;
        let version = match self.version_in {
            VersionIn::Srep => srep.u32(VER, "bad VER")?,
            VersionIn::TopLevel => top.u32(VER, "bad VER")?,
        };
        if version != self.number {
            return Err(Invalid("not the pinned version"));
        }
        if self.version_in == VersionIn::Srep {
            let vers = srep.need(VERS, "no VERS")?;
            let (listed, rest) = vers.as_chunks::<4>();
            if !rest.is_empty() || listed.len() > 32 || !listed.contains(&version.to_le_bytes()) {
                return Err(Invalid("VERS does not list VER"));
            }
        }

        let cert = Message::parse(top.need(CERT, "no CERT")?)?;
        let dele_bytes = cert.need(DELE, "no DELE")?;
        let dele_signature = cert.fixed::<64>(SIG, "bad CERT SIG")?;
        if !signed(public_key, self.delegation_context, dele_bytes, &dele_signature) {
            return Err(Invalid("delegation signature"));
        }
        let dele = Message::parse(dele_bytes)?;
        let online_key = dele.fixed::<32>(PUBK, "bad PUBK")?;
        if !signed(&online_key, self.response_context, srep_bytes, &top.fixed::<64>(SIG, "bad SIG")?) {
            return Err(Invalid("response signature"));
        }

        let leaf = match self.leaf {
            Leaf::Packet => request,
            Leaf::Nonce => &nonce[..],
        };
        let orders = if typed { self.typed_orders } else { self.orders };
        let root = srep.fixed::<32>(ROOT, "bad ROOT")?;
        merkle(self.hash, leaf, top.u32(INDX, "bad INDX")?, top.need(PATH, "no PATH")?, &root, orders)?;

        let midp = self.timestamp(srep.u64(MIDP, "bad MIDP")?);
        let mint = self.timestamp(dele.u64(MINT, "bad MINT")?);
        let maxt = self.timestamp(dele.u64(MAXT, "bad MAXT")?);
        if !(mint <= midp && midp <= maxt) {
            return Err(Invalid("MIDP outside MINT..MAXT"));
        }
        let radi = srep.u32(RADI, "bad RADI")?;
        if radi == 0 && self.nonzero_radius {
            return Err(Invalid("RADI is 0"));
        }
        let radius = match self.time {
            Time::UnixSeconds => i128::from(radi) * 1_000_000,
            Time::MjdMicros => i128::from(radi),
        };
        Ok(Sample { midp, radius })
    }

    /// Microseconds since the Unix epoch.
    fn timestamp(&self, raw: u64) -> i128 {
        match self.time {
            Time::UnixSeconds => i128::from(raw) * 1_000_000,
            Time::MjdMicros => {
                const UNIX_EPOCH_MJD: i128 = 40_587;
                let day = i128::from(raw >> 40);
                let micros = i128::from(raw & ((1 << 40) - 1));
                (day - UNIX_EPOCH_MJD) * 86_400_000_000 + micros
            }
        }
    }
}

fn signed(key: &[u8; 32], context: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(key) else { return false };
    key.verify_strict(&[context, message].concat(), &Signature::from_bytes(signature)).is_ok()
}

/// RFC 10049 §5.3.1: from `H(0x00 || leaf)` up `PATH` (siblings leaf to root, at most 32),
/// one `INDX` bit per level, least significant first; no bits may remain.
fn merkle(hash: Hash, leaf: &[u8], index: u32, path: &[u8], root: &[u8; 32], orders: &[Order]) -> Check<()> {
    let (nodes, rest) = path.as_chunks::<32>();
    if !rest.is_empty() || nodes.len() > 32 {
        return Err(Invalid("bad PATH"));
    }
    for &order in orders {
        let mut h = hash.of(&[&[0x00], leaf]);
        let mut index = index;
        for node in nodes {
            h = if (index & 1 == 0) == (order == Order::HashFirst) {
                hash.of(&[&[0x01], &h, node])
            } else {
                hash.of(&[&[0x01], node, &h])
            };
            index >>= 1;
        }
        if index == 0 && &h == root {
            return Ok(());
        }
    }
    Err(Invalid("Merkle proof does not lead to ROOT"))
}

#[cfg(test)]
mod tests;

//! Keeps the secret out of anything relayed back to the client: upstreams that
//! echo the key (error messages, debug endpoints, `CONFIG GET`) must not leak it.
//!
//! What is masked, for every needle (the secret and, for HTTP, the rendered header value):
//! - the plain bytes;
//! - one layer of JSON string or URL escaping, any mix per byte: `%XX` in either case (so
//!   `encodeURIComponent`, Python's `quote` with or without `safe`), `+` for a space (forms),
//!   `\uXXXX` with `XX` in either case (Go's `&`, .NET's `+`), and the short
//!   escapes `\"`, `\\`, `\/` (PHP), `\b`, `\f`, `\n`, `\r`, `\t`;
//! - base64, standard and URL-safe, padded or not, at any alignment (inside `Basic` auth, a
//!   JWT, a JSON field), itself escaped as above. The characters at each edge that carry
//!   some of the needle's bits and some of a neighbouring byte's are masked too, whatever the
//!   neighbour (any character whose needle bits are right matches there), so no bit of the
//!   needle stays visible. Needles shorter than `MIN_SECRET_BYTES` get no base64 forms, whose
//!   characters would be a few common ones.
//!
//! Not masked: anything else the upstream computes from the secret (hex, a hash, a substring,
//! double escaping, HTML entities, MIME base64 with line breaks), or compressed data.
//!
//! Masking is visible, so it answers one question for a consumer who can make the upstream
//! return chosen text: is this exact text the secret? That is why secrets shorter than
//! `seal_proto::policy::MIN_SECRET_BYTES` are never sealed: a response listing every candidate
//! of a short length would find them. A needle of any length is still masked: passing an echo
//! through would be worse. Nothing else about the scrubber depends on how much of the text
//! resembles the secret: neither what it releases and when (`Scrubber`), nor the work it does
//! per byte (`Engine`), nor the work of building one (`Scrubber::new`).

use seal_proto::policy::MIN_SECRET_BYTES;
use seal_proto::secret::ct_eq;
use zeroize::{Zeroize, Zeroizing};

/// Streaming scrubber: overwrites every occurrence of any needle, in any of the forms the
/// module lists, with the same number of `*` bytes, including occurrences split across chunk
/// boundaries. Same length on purpose: Postgres, Redis and ClickHouse frames carry length
/// prefixes, so a length-changing replacement would corrupt the protocol.
///
/// What it releases, and when, depends only on how many bytes arrived, never on what they
/// were: it always holds back the last `window` bytes (one less than the longest spelling of
/// any pattern, six bytes per position), whether or not they could start an occurrence, and
/// `flush` releases them all at a protocol message boundary, so a request/response protocol
/// never stalls. A stream with no message boundaries calls `release` when its upstream goes
/// quiet, a moment set by arrival times alone: the held bytes go out and stay as context, so
/// an occurrence that resumes after the pause still has its unsent rest masked (only what went
/// out before the pause is past masking). Holding back only a tail that might be the secret's
/// beginning would frame the output by how much of the secret an echo matched: an upstream
/// that echoes chosen text would then be a prefix oracle for the secret.
///
/// Sees only the bytes as sent: a secret inside compressed data passes, which is why adapters
/// refuse response compression. Patterns, their tables and the match state are zeroized on drop.
pub struct Scrubber {
    /// Each needle and its base64 forms, one byte class per position.
    patterns: Vec<Pattern>,
    /// Every pattern at once, fed each byte as it arrives; `None` without patterns.
    engine: Option<Engine>,
    /// Per pattern: its reversed engine, built at its first complete occurrence, which finds
    /// where that occurrence starts.
    reversed: Vec<Option<Engine>>,
    /// The held-back tail as received (unmasked), so an occurrence that starts in it can still
    /// be masked when it completes.
    carry: Vec<u8>,
    /// Per byte of `carry`: already covered by a complete occurrence.
    carry_masked: Vec<bool>,
    /// How many leading bytes of `carry` went out already (`release`): context only.
    carry_sent: usize,
    /// Bytes always held back: no occurrence still open can start earlier.
    window: usize,
}

pub const MASK: u8 = b'*';

/// The longest spelling of any byte (`\u00XX`).
const LONGEST_SPELLING: usize = 6;

impl Scrubber {
    /// Empty needles are ignored. The work, and the memory it touches, depend only on the
    /// needles' lengths and on which of them equal or contain another, never on their bytes:
    /// the engine's tables are the patterns' classes transposed, a fixed sequence of word
    /// operations, and needles and patterns are compared in constant time. Adapters build one
    /// per connection or response, which a consumer can time.
    pub fn new(needles: Vec<Zeroizing<Vec<u8>>>) -> Self {
        Self::build(needles, false)
    }

    /// `new`, matching every ASCII letter of every form in either case: for text a peer may
    /// have case-folded, such as HTTP header names, which hyper lowercases. Masks more than
    /// `new` does, so only for text where that is harmless.
    pub fn ignoring_ascii_case(needles: Vec<Zeroizing<Vec<u8>>>) -> Self {
        Self::build(needles, true)
    }

    fn build(needles: Vec<Zeroizing<Vec<u8>>>, fold_case: bool) -> Self {
        let mut patterns: Vec<Pattern> = Vec::new();
        let needles: Vec<&[u8]> = needles.iter().map(|n| n.as_slice()).filter(|n| !n.is_empty()).collect();
        // A needle that contains another one with base64 forms needs none of its own: the
        // other's forms already mask every character carrying its bytes.
        let encodes = |n: &[u8]| n.len() >= MIN_SECRET_BYTES;
        let covered =
            |n: &[u8]| needles.iter().fold(false, |any, m| any | (m.len() < n.len() && encodes(m) && contains(n, m)));
        for &needle in &needles {
            let plain = Zeroizing::new(needle.iter().map(|&b| Class::of(b)).collect());
            let encoded = if encodes(needle) && !covered(needle) { base64_patterns(needle) } else { Vec::new() };
            for mut p in std::iter::once(plain).chain(encoded) {
                if fold_case {
                    p.iter_mut().for_each(Class::fold_ascii_case);
                }
                if !patterns.iter().fold(false, |any, q| any | same(q, &p)) {
                    patterns.push(p);
                }
            }
        }
        let longest = patterns.iter().map(|p| p.len() * LONGEST_SPELLING).max().unwrap_or(0);
        let engine = (!patterns.is_empty()).then(|| Engine::new(&patterns, false));
        Self {
            reversed: patterns.iter().map(|_| None).collect(),
            patterns,
            engine,
            carry: Vec::new(),
            carry_masked: Vec::new(),
            carry_sent: 0,
            window: longest.saturating_sub(1),
        }
    }

    /// Feed a chunk; returns bytes safe to forward now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let Some(engine) = self.engine.as_mut() else {
            return chunk.to_vec();
        };
        let mut buf = std::mem::take(&mut self.carry);
        let fresh = buf.len();
        buf.extend_from_slice(chunk);
        let mut masked = std::mem::take(&mut self.carry_masked);
        masked.resize(buf.len(), false);

        // Mask every occurrence as it completes. An occurrence is at most `window + 1` bytes
        // long, so it starts inside `buf`: the carry holds the last `window` bytes since the
        // last message boundary.
        for i in fresh..buf.len() {
            if engine.step(buf[i], true) {
                for q in engine.completed() {
                    let start = start_of(&self.patterns[q], &mut self.reversed[q], &buf[..=i]);
                    masked[start..=i].iter_mut().for_each(|m| *m = true);
                }
            }
        }

        // The release point is fixed by the length alone (module docs).
        let keep = buf.len().saturating_sub(self.window);
        let emit = keep.max(self.carry_sent);
        let out = apply(&buf[self.carry_sent..emit], &masked[self.carry_sent..emit]);
        self.carry = buf[keep..].to_vec();
        self.carry_masked = masked[keep..].to_vec();
        self.carry_sent = emit - keep;
        buf.zeroize();
        out
    }

    /// The upstream went quiet: returns every byte not yet released, scrubbed as far as known,
    /// and keeps the window as context for the next push (module docs).
    pub fn release(&mut self) -> Vec<u8> {
        let out = apply(&self.carry[self.carry_sent..], &self.carry_masked[self.carry_sent..]);
        self.carry_sent = self.carry.len();
        out
    }

    /// Whether bytes are held back that `release` would hand out.
    pub fn holding(&self) -> bool {
        self.carry_sent < self.carry.len()
    }

    /// Protocol message boundary: returns the held-back tail, scrubbed; the next push starts fresh.
    pub fn flush(&mut self) -> Vec<u8> {
        let out = apply(&self.carry[self.carry_sent..], &self.carry_masked[self.carry_sent..]);
        self.carry.zeroize();
        self.carry_masked.clear();
        self.carry_sent = 0;
        if let Some(engine) = self.engine.as_mut() {
            engine.reset();
        }
        out
    }

    /// End of stream: returns the held-back tail, scrubbed.
    pub fn finish(&mut self) -> Vec<u8> {
        self.flush()
    }

    /// Engine steps taken so far, in words: the scan's work, for tests.
    #[cfg(test)]
    fn work(&self) -> u64 {
        self.engine.as_ref().map_or(0, |e| e.work) + self.reversed.iter().flatten().map(|e| e.work).sum::<u64>()
    }

    /// Words the engine's construction built: the build's work, for tests.
    #[cfg(test)]
    fn build_work(&self) -> u64 {
        self.engine.as_ref().map_or(0, |e| e.built)
    }
}

impl Drop for Scrubber {
    fn drop(&mut self) {
        self.carry.zeroize();
    }
}

/// Whether `needle` occurs in `haystack`, comparing every window in constant time.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).fold(false, |found, w| found | ct_eq(w, needle))
}

/// Whether two patterns are the same, comparing every class whole.
fn same(a: &Pattern, b: &Pattern) -> bool {
    let diff = a.iter().zip(b.iter()).fold(0u64, |d, (x, y)| d | x.0.iter().zip(y.0).fold(0, |d, (u, v)| d | (u ^ v)));
    a.len() == b.len() && ct_eq(&diff.to_le_bytes(), &[0; 8])
}

/// Where the occurrence of `pattern` that completes at the end of `buf` starts: the earliest
/// start, when several spellings end there. Runs `pattern`'s reversed engine back from the end
/// for a fixed number of bytes (the longest spelling, or all of `buf` if shorter).
fn start_of(pattern: &Pattern, reversed: &mut Option<Engine>, buf: &[u8]) -> usize {
    let engine = reversed.get_or_insert_with(|| {
        let backwards: Pattern = Zeroizing::new(pattern.iter().rev().copied().collect());
        Engine::new(std::slice::from_ref(&backwards), true)
    });
    engine.reset();
    let end = buf.len() - 1;
    let mut start = end;
    for (k, &b) in buf.iter().rev().take(pattern.len() * LONGEST_SPELLING).enumerate() {
        let done = engine.step(b, k == 0);
        start = if done { end - k } else { start };
    }
    start
}

/// The bytes one position of a pattern matches: a set of 256.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct Class([u64; 4]);

impl Zeroize for Class {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Class {
    fn of(b: u8) -> Self {
        let mut c = Self::default();
        c.add(b);
        c
    }
    fn add(&mut self, b: u8) {
        self.add_if(b, true);
    }
    /// Adds `b` if `yes`, the same work either way.
    fn add_if(&mut self, b: u8, yes: bool) {
        self.0[usize::from(b >> 6)] |= u64::from(yes) << (b & 63);
    }
    /// 1 if it holds `b`, else 0.
    fn has(&self, b: u8) -> u64 {
        self.0[usize::from(b >> 6)] >> (b & 63) & 1
    }
    /// Adds the other case of every ASCII letter it holds, without branching on which.
    fn fold_ascii_case(&mut self) {
        for b in (b'A'..=b'Z').chain(b'a'..=b'z') {
            let other = b ^ 0x20;
            self.0[usize::from(other >> 6)] |= self.has(b) << (other & 63);
        }
    }
    #[cfg(test)]
    fn members(&self) -> impl Iterator<Item = u8> + '_ {
        (0..=255u8).filter(|&b| self.0[usize::from(b >> 6)] >> (b & 63) & 1 == 1)
    }
}

type Pattern = Zeroizing<Vec<Class>>;

/// The base64 forms of `needle`, for each of the three alignments it can have inside encoded
/// data: one position per character that carries any of its bits. A character that also
/// carries a neighbouring byte's bits matches every character agreeing on the needle's bits;
/// each position takes either alphabet, standard or URL-safe.
fn base64_patterns(needle: &[u8]) -> Vec<Pattern> {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    // Per character of a group: the bytes its bits come from and which of its bits each gives.
    const FROM: [(usize, u8, usize, u8); 4] =
        [(0, 0b11_1111, 0, 0), (0, 0b11_0000, 1, 0b00_1111), (1, 0b11_1100, 2, 0b00_0011), (2, 0b11_1111, 2, 0)];
    let mut patterns = Vec::new();
    for lead in 0..3 {
        // `lead` unknown bytes before the needle, zeros after it to finish the last group.
        // Sized up front: a growing buffer would leave unzeroized copies behind.
        let whole = (lead + needle.len()).div_ceil(3) * 3;
        let mut bytes = Zeroizing::new(Vec::with_capacity(whole));
        bytes.resize(lead, 0);
        bytes.extend_from_slice(needle);
        bytes.resize(whole, 0);
        let ours = |i: usize| (lead..lead + needle.len()).contains(&i);
        let mut pattern: Pattern = Zeroizing::new(Vec::with_capacity(whole / 3 * 4));
        for (g, group) in bytes.chunks(3).enumerate() {
            let sextets = [
                group[0] >> 2,
                (group[0] & 0x03) << 4 | group[1] >> 4,
                (group[1] & 0x0f) << 2 | group[2] >> 6,
                group[2] & 0x3f,
            ];
            for (sextet, (a, a_bits, b, b_bits)) in sextets.into_iter().zip(FROM) {
                let known = if ours(3 * g + a) { a_bits } else { 0 } | if ours(3 * g + b) { b_bits } else { 0 };
                if known == 0 {
                    continue;
                }
                // Every sextet value, whichever agree: the same work for any needle bits.
                let mut class = Class::default();
                for v in 0..64u8 {
                    let agrees = v & known == sextet & known;
                    class.add_if(STD[usize::from(v)], agrees);
                    class.add_if(URL[usize::from(v)], agrees);
                }
                pattern.push(class);
            }
        }
        patterns.push(pattern);
    }
    patterns
}

/// Every pattern as one bit-parallel automaton (shift-and over all spelling states): bit `p`
/// of each state vector stands for position `p` of the patterns laid end to end, and each
/// byte costs the same fixed sequence of word operations, over every word, whatever the
/// bytes and however much of a pattern they match. A scan that followed only the partial
/// matches alive (as a list) would take longer the more of an echo resembled the secret,
/// a timing oracle as good as a prefix one once a response repeats a guess. What the step
/// branches on is only the input byte, which the consumer knows.
///
/// A position is reached by one of its byte's spellings, read as a chain of bytes, with a
/// state vector after each byte of the chain but its last (index into a word's `state`):
/// - plain (a member of its class), or `+` for a space: one byte, straight to `done` (0);
/// - `%` hi lo: 1 after `%`, 2 after hi;
/// - `\u00` hi lo: 3 after `\`, 4 after `u`, 5 and 6 after the zeros, 7 after hi;
/// - `\` and a short escape letter: 3 after `\`, shared with the one above.
///
/// Hex digits and the `u` match in either case. A class's escaped spellings take the high
/// digit of any member with the low digit of any member, so at the edge of a base64 form (the
/// only classes with several members) an escaped character that is no member can pass for one:
/// at worst one character too many is masked, next to a complete occurrence.
///
/// Reversed (`reversed`: the pattern's positions back to front, each chain read backwards),
/// the same tables find where an occurrence starts.
struct Engine {
    words: usize,
    reversed: bool,
    /// Per word, bit `p`: position `p` is the first (`.0`) or last (`.1`) of its pattern.
    marks: Vec<(u64, u64)>,
    /// Per pattern, in order: the bit index of its last position.
    last: Vec<usize>,
    /// `words` per row. `plain`: a row per byte, positions that byte spells plainly. `hi`,
    /// `lo`: a row per hex digit (and an empty one), positions with a member whose high or
    /// low digit it is. `short`: a row per short escape letter (and an empty one).
    plain: Zeroizing<Vec<u64>>,
    hi: Zeroizing<Vec<u64>>,
    lo: Zeroizing<Vec<u64>>,
    short: Zeroizing<Vec<u64>>,
    /// `STATE` vectors per word: `done` (position complete), then the chain states.
    state: Zeroizing<Vec<[u64; STATE]>>,
    /// Words stepped, for tests.
    #[cfg(test)]
    work: u64,
    /// Words of positions `new` built tables for, for tests.
    #[cfg(test)]
    built: u64,
}

const STATE: usize = 8;
const SHORT: [(u8, u8); 8] = [
    (b'"', b'"'),
    (b'\\', b'\\'),
    (b'/', b'/'),
    (0x08, b'b'),
    (0x0c, b'f'),
    (b'\n', b'n'),
    (b'\r', b'r'),
    (b'\t', b't'),
];
/// Row of `hi`/`lo` for an input byte: its hex value in either case, 16 for no digit.
const HEX_ROW: [u8; 256] = {
    let mut rows = [16u8; 256];
    let mut b = 0;
    while b < 256 {
        rows[b] = match b as u8 {
            d @ b'0'..=b'9' => d - b'0',
            d @ b'a'..=b'f' => d - b'a' + 10,
            d @ b'A'..=b'F' => d - b'A' + 10,
            _ => 16,
        };
        b += 1;
    }
    rows
};
/// Row of `short` for an input byte: its index in `SHORT` as an escape letter, 8 for none.
const SHORT_ROW: [u8; 256] = {
    let mut rows = [8u8; 256];
    let mut i = 0;
    while i < SHORT.len() {
        rows[SHORT[i].1 as usize] = i as u8;
        i += 1;
    }
    rows
};

impl Engine {
    fn new(patterns: &[Pattern], reversed: bool) -> Self {
        let positions: usize = patterns.iter().map(|p| p.len()).sum();
        let words = positions.div_ceil(64);
        let zeros = |rows: usize| Zeroizing::new(vec![0u64; rows * words]);
        let mut e = Engine {
            words,
            reversed,
            marks: vec![(0, 0); words],
            last: Vec::with_capacity(patterns.len()),
            plain: zeros(256),
            hi: zeros(17),
            lo: zeros(17),
            short: zeros(9),
            state: Zeroizing::new(vec![[0; STATE]; words]),
            #[cfg(test)]
            work: 0,
            #[cfg(test)]
            built: 0,
        };
        let classes: Vec<&Class> = patterns.iter().flat_map(|p| p.iter()).collect();
        let mut p = 0;
        for pattern in patterns {
            e.marks[p / 64].0 |= 1 << (p % 64);
            p += pattern.len();
            e.marks[(p - 1) / 64].1 |= 1 << ((p - 1) % 64);
            e.last.push(p - 1);
        }
        // The tables are the classes transposed, 64 positions by 64 bytes at a time: fixed work
        // per word, whichever bytes the classes hold, and no entry touched for being a member.
        let mut block = Zeroizing::new([0u64; 64]);
        for w in 0..words {
            for quarter in 0..4 {
                for (i, row) in block.iter_mut().enumerate() {
                    *row = classes.get(w * 64 + i).map_or(0, |c| c.0[quarter]);
                }
                transpose(&mut block);
                for (i, &row) in block.iter().enumerate() {
                    e.plain[(quarter * 64 + i) * words + w] = row;
                }
            }
            let plain = |b: usize| e.plain[b * words + w];
            for d in 0..16 {
                e.hi[d * words + w] = (0..16).fold(0, |acc, lo| acc | plain(d << 4 | lo));
                e.lo[d * words + w] = (0..16).fold(0, |acc, hi| acc | plain(hi << 4 | d));
            }
            for (i, &(escaped, _)) in SHORT.iter().enumerate() {
                e.short[i * words + w] = plain(usize::from(escaped));
            }
            // `+` spells a space (forms), after the escapes, which spell members only.
            let space = plain(usize::from(b' '));
            e.plain[usize::from(b'+') * words + w] |= space;
            #[cfg(test)]
            {
                e.built += 1;
            }
        }
        e
    }

    /// Forgets every partial match.
    fn reset(&mut self) {
        self.state.fill([0; STATE]);
    }

    /// Takes byte `c`; an occurrence may start at it if `open`. Returns whether any pattern
    /// completed (`completed` says which).
    fn step(&mut self, c: u8, open: bool) -> bool {
        let words = self.words;
        let plain = &self.plain[usize::from(c) * words..][..words];
        let hi = &self.hi[usize::from(HEX_ROW[usize::from(c)]) * words..][..words];
        let lo = &self.lo[usize::from(HEX_ROW[usize::from(c)]) * words..][..words];
        let short = &self.short[usize::from(SHORT_ROW[usize::from(c)]) * words..][..words];
        let is = |x: u8| if c == x { !0u64 } else { 0 };
        let (pct, slash, zero, u) = (is(b'%'), is(b'\\'), is(b'0'), if c | 0x20 == b'u' { !0u64 } else { 0 });
        let open = if open { !0u64 } else { 0 };
        let mut carry = 0;
        let mut any = 0;
        let tables = plain.iter().zip(hi).zip(lo).zip(short);
        for ((s, &(starts, ends)), (((&plain, &hi), &lo), &short)) in self.state.iter_mut().zip(&self.marks).zip(tables)
        {
            let done = s[0];
            // Positions whose predecessor is complete: shifted along, and every pattern's first.
            let at = ((done << 1 | carry) & !starts) | (starts & open);
            carry = done >> 63;
            if self.reversed {
                // Chains backwards: lo hi `%`; lo hi `0` `0` `u` `\`; letter `\`.
                s[0] = (at & plain) | (s[2] & pct) | ((s[5] | s[6]) & slash);
                s[6] = at & short;
                s[5] = s[4] & u;
                s[4] = s[3] & zero;
                s[3] = s[2] & zero;
                s[2] = s[1] & hi;
                s[1] = at & lo;
            } else {
                s[0] = (at & plain) | ((s[2] | s[7]) & lo) | (s[3] & short);
                s[7] = s[6] & hi;
                s[6] = s[5] & zero;
                s[5] = s[4] & zero;
                s[4] = s[3] & u;
                s[3] = at & slash;
                s[2] = s[1] & hi;
                s[1] = at & pct;
            }
            any |= s[0] & ends;
        }
        #[cfg(test)]
        {
            self.work += words as u64;
        }
        any != 0
    }

    /// The patterns that completed at the last step.
    fn completed(&self) -> impl Iterator<Item = usize> + '_ {
        self.last.iter().enumerate().filter(|(_, &p)| self.state[p / 64][0] >> (p % 64) & 1 == 1).map(|(q, _)| q)
    }
}

/// Transposes a 64 by 64 bit matrix in place (row `r`, column `c` is bit `c` of `m[r]`) by
/// swapping ever smaller blocks across the diagonal: the same steps for any bits.
fn transpose(m: &mut [u64; 64]) {
    let mut j = 32;
    let mut mask = 0x0000_0000_ffff_ffff_u64;
    while j != 0 {
        let mut k = 0;
        while k < 64 {
            let t = ((m[k] >> j) ^ m[k + j]) & mask;
            m[k] ^= t << j;
            m[k + j] ^= t;
            k = (k + j + 1) & !j;
        }
        j >>= 1;
        mask ^= mask << j;
    }
}

fn apply(bytes: &[u8], masked: &[bool]) -> Vec<u8> {
    bytes.iter().zip(masked).map(|(&b, &m)| if m { MASK } else { b }).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Holds `/`, `+`, `&`, `<`, `>`, `=`, `?`, so every escaping differs from the plain bytes.
    const SECRET: &[u8] = b"sk-live/4f+a&b<c>=Z9q?~";

    fn scrubber(needles: &[&[u8]]) -> Scrubber {
        Scrubber::new(needles.iter().map(|n| Zeroizing::new(n.to_vec())).collect())
    }

    /// One way of writing a byte: `bytes[..len]`, compared ASCII-case-insensitively if `fold`.
    struct Spelling {
        bytes: [u8; 6],
        len: usize,
        fold: bool,
    }

    impl Spelling {
        fn accepts(&self, at: usize, b: u8) -> bool {
            let s = self.bytes[at];
            s == b || (self.fold && s.eq_ignore_ascii_case(&b))
        }
    }

    /// How many spellings `spelling` can return per byte.
    const SPELLINGS: usize = 5;

    /// The `n`th spelling of byte `b`, if it has one: plain, `%XX`, `\u00XX`, a short JSON
    /// escape, `+` for a space. What `Engine` matches, written out one spelling at a time.
    fn spelling(b: u8, n: usize) -> Option<Spelling> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let (hi, lo) = (HEX[usize::from(b >> 4)], HEX[usize::from(b & 0x0f)]);
        let (bytes, len, fold) = match n {
            0 => ([b, 0, 0, 0, 0, 0], 1, false),
            1 => ([b'%', hi, lo, 0, 0, 0], 3, true),
            2 => ([b'\\', b'u', b'0', b'0', hi, lo], 6, true),
            3 => {
                let &(_, short) = SHORT.iter().find(|&&(s, _)| s == b)?;
                ([b'\\', short, 0, 0, 0, 0], 2, false)
            }
            4 if b == b' ' => ([b'+', 0, 0, 0, 0, 0], 1, false),
            _ => return None,
        };
        Some(Spelling { bytes, len, fold })
    }

    /// `input` is, as a whole, some spelling of `pattern`, one member of each class.
    fn spelled(input: &[u8], pattern: &[Class]) -> bool {
        let Some((class, rest)) = pattern.split_first() else { return input.is_empty() };
        class.members().flat_map(|b| (0..SPELLINGS).filter_map(move |n| spelling(b, n))).any(|s| {
            input.len() >= s.len && (0..s.len).all(|k| s.accepts(k, input[k])) && spelled(&input[s.len..], rest)
        })
    }

    /// Masks the whole input at once: every byte inside any occurrence of any pattern.
    fn reference(input: &[u8], needles: &[Vec<u8>]) -> Vec<u8> {
        let scrubber = Scrubber::new(needles.iter().cloned().map(Zeroizing::new).collect());
        let mut masked = vec![false; input.len()];
        for p in &scrubber.patterns {
            for start in 0..input.len() {
                for end in start + 1..=input.len() {
                    if spelled(&input[start..end], p) {
                        masked[start..end].iter_mut().for_each(|m| *m = true);
                    }
                }
            }
        }
        apply(input, &masked)
    }

    fn run(s: &mut Scrubber, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(s.push(c));
        }
        out.extend(s.finish());
        out
    }

    /// `before`, `body` masked whole, `after`.
    fn masked(before: &str, body: &str, after: &str) -> Vec<u8> {
        [before.as_bytes(), &vec![MASK; body.len()], after.as_bytes()].concat()
    }

    fn check(needles: &[&[u8]], before: &str, body: &str, after: &str) {
        let input = [before, body, after].concat();
        let mut s = scrubber(needles);
        assert_eq!(run(&mut s, &[input.as_bytes()]), masked(before, body, after), "{input}");
        let mut s = scrubber(needles);
        let bytes: Vec<&[u8]> = input.as_bytes().chunks(1).collect();
        assert_eq!(run(&mut s, &bytes), masked(before, body, after), "{input}, byte by byte");
    }

    #[test]
    fn masks_whole_occurrence() {
        let mut s = scrubber(&[b"sk-secret"]);
        assert_eq!(run(&mut s, &[b"key=sk-secret!"]), b"key=*********!");
    }

    #[test]
    fn masks_occurrence_split_across_chunks() {
        let mut s = scrubber(&[b"sk-secret"]);
        let mut out = s.push(b"error: sk-se");
        out.extend(s.push(b"cret, bye"));
        out.extend(s.finish());
        assert_eq!(out, b"error: *********, bye");
    }

    #[test]
    fn masks_byte_by_byte() {
        let mut s = scrubber(&[b"abc"]);
        let input = b"xxabcabxabc";
        let chunks: Vec<&[u8]> = input.chunks(1).collect();
        assert_eq!(run(&mut s, &chunks), b"xx***abx***");
    }

    #[test]
    fn overlapping_and_multiple_needles() {
        let mut s = scrubber(&[b"aa", b"Bearer aa"]);
        assert_eq!(run(&mut s, &[b"aaa"]), b"***");
        let mut s = scrubber(&[b"aa", b"Bearer aa"]);
        assert_eq!(run(&mut s, &[b"aa", b"a"]), b"***", "overlap across a chunk boundary");
        let mut s = scrubber(&[b"tok", b"Bearer tok"]);
        assert_eq!(run(&mut s, &[b"h: Bear", b"er tok; tok"]), b"h: **********; ***");
    }

    #[test]
    fn empty_needles_are_ignored() {
        let mut s = scrubber(&[b""]);
        assert_eq!(s.push(b"anything"), b"anything");
        assert!(s.finish().is_empty());
    }

    #[test]
    fn flush_releases_tail_and_starts_fresh() {
        let mut s = scrubber(&[b"secret"]);
        assert_eq!(s.push(b"+OK sec"), b"", "the window covers the whole reply");
        assert_eq!(s.flush(), b"+OK sec", "a message boundary releases the tail");
        assert_eq!(s.push(b"ret"), b"", "the next push starts fresh");
        assert_eq!(s.finish(), b"ret");
        assert_eq!(s.push(b"secret"), b"");
        assert_eq!(s.finish(), b"******");
    }

    #[test]
    fn holds_back_a_fixed_window() {
        // Six bytes per byte of the longest pattern, less one: 35 for a six-byte needle.
        let mut s = scrubber(&[b"abcdef"]);
        assert_eq!(s.window, 35);
        let filler = [b'x'; 40];
        assert_eq!(s.push(&filler), &filler[..5]);
        assert_eq!(s.push(b"y"), b"x");
        assert_eq!(s.finish(), [&filler[..34], b"y"].concat());
    }

    #[test]
    fn release_hands_out_the_window_and_keeps_it_as_context() {
        let mut s = scrubber(&[b"sk-secret"]);
        assert_eq!(s.push(b"error: sk-se"), b"");
        assert!(s.holding());
        assert_eq!(s.release(), b"error: sk-se", "a pause sends what is held");
        assert!(!s.holding());
        assert_eq!(s.release(), b"");
        // The occurrence resumes: its unsent rest is still masked.
        let mut out = s.push(b"cret, bye");
        out.extend(s.finish());
        assert_eq!(out, b"****, bye");
        // A whole occurrence after a pause is masked as usual.
        let mut s = scrubber(&[b"sk-secret"]);
        s.push(b"x");
        assert_eq!(s.release(), b"x");
        let mut out = s.push(b" sk-secret y");
        out.extend(s.finish());
        assert_eq!(out, b" ********* y");
    }

    #[test]
    fn release_points_never_depend_on_the_secret() {
        // A prefix oracle: an echo of a guess that matches the secret's beginning must come out
        // in the same pieces as one that does not.
        let secret: &[u8] = b"sk-live-9Qz7wPb3nX2mK8vR4tY6";
        let pieces = |guess: &[u8]| {
            let mut s = scrubber(&[secret]);
            let echo = [b"data: {\"text\": \"".as_slice(), guess, b"\"}\n\n"].concat();
            let mut sizes: Vec<usize> = echo.chunks(7).map(|c| s.push(c).len()).collect();
            sizes.push(s.finish().len());
            sizes
        };
        // Same length, so only the content differs: a wrong last character, nothing alike, and
        // the whole secret but its last character (against the secret itself, which is masked).
        for wrong in [b"sk-live-9Qa".as_slice(), b"xxxxxxxxxxx", b"sk-live-9Qz7wPb3nX2mK8vR4tY5"] {
            let right = pieces(&secret[..wrong.len()]);
            assert_eq!(pieces(wrong), right, "{}", String::from_utf8_lossy(wrong));
        }
    }

    #[test]
    fn scan_work_never_depends_on_the_secret() {
        // A timing oracle: scanning an echo that matches more of the secret must not take
        // longer. Same echo, secrets it matches all but the last byte of, or not at all; and
        // echoes of the same length, matching the secret's start or full of escape starts.
        let secret: &[u8] = b"sk-live-9Qz7wPb3nX2mK8vR4tY6";
        let work = |secret: &[u8], echo: &[u8]| {
            let rendered = [b"Bearer ".as_slice(), secret].concat();
            let mut s = scrubber(&[secret, &rendered]);
            let body: Vec<u8> = echo.iter().copied().cycle().take(64 << 10).collect();
            let out = run(&mut s, &body.chunks(4096).collect::<Vec<_>>());
            assert!(!out.contains(&MASK));
            s.work()
        };
        let echo = [&secret[..secret.len() - 1], b"# "].concat();
        let unrelated = [b"X".as_slice(), &secret[1..]].concat();
        assert_eq!(work(secret, &echo), work(&unrelated, &echo));
        let base = work(secret, &[b'#'; 29]);
        for echo in [
            echo.as_slice(),
            b"sk-live-9Qz7wPb3nX2mK8vR4tY# ",
            b"%%%%%%%%%%%%%%%%%%%%%%%%%%%%%",
            b"\\u00\\u00\\u00\\u00\\u00\\u00\\u00\\u00\\",
        ] {
            assert_eq!(work(secret, echo), base, "{}", String::from_utf8_lossy(echo));
        }
    }

    #[test]
    fn tables_hold_every_member_and_nothing_else() {
        // The transposed tables against the classes, bit by bit.
        let secret: &[u8] = b"sk-live/4f+a&b<c>=Z9q?~ \"\\\n\t";
        let rendered = [b"Bearer ".as_slice(), secret].concat();
        let folded = Scrubber::ignoring_ascii_case(vec![Zeroizing::new(secret.to_vec())]);
        for s in [scrubber(&[secret, &rendered]), folded] {
            let e = s.engine.as_ref().unwrap();
            let classes: Vec<&Class> = s.patterns.iter().flat_map(|p| p.iter()).collect();
            assert!(classes.len() > 64, "more than one word");
            let at = |table: &[u64], row: usize, p: usize| table[row * e.words + p / 64] >> (p % 64) & 1 == 1;
            for (p, class) in classes.iter().enumerate() {
                let members: Vec<u8> = class.members().collect();
                for b in 0..=255u8 {
                    let plain = members.contains(&b) || (b == b'+' && members.contains(&b' '));
                    assert_eq!(at(&e.plain, usize::from(b), p), plain, "plain {b} at {p}");
                }
                for d in 0..17u8 {
                    assert_eq!(at(&e.hi, usize::from(d), p), members.iter().any(|m| m >> 4 == d), "hi {d} at {p}");
                    assert_eq!(at(&e.lo, usize::from(d), p), members.iter().any(|m| m & 15 == d), "lo {d} at {p}");
                }
                for (i, &(escaped, _)) in SHORT.iter().enumerate() {
                    assert_eq!(at(&e.short, i, p), members.contains(&escaped), "short {i} at {p}");
                }
                assert!(!at(&e.short, SHORT.len(), p));
            }
        }
    }

    #[test]
    fn build_work_never_depends_on_the_secret() {
        // Adapters build a scrubber per connection or response, which a consumer can time:
        // secrets of one length must cost the same to build, whatever their bytes. Letters
        // (which case folding doubles), short-escape bytes, bytes whose base64 uses the
        // characters the alphabets differ on, and a secret that repeats its header's prefix.
        let secrets: [&[u8]; 6] = [
            b"sk-live-9Qz7wPb3nX2mK8vR4tY6",
            b"0123456789012345678901234567",
            b"abcdefghijklmnopqrstuvwxyzAB",
            b"\"\\/\x08\x0c\n\r\t\"\\/\x08\x0c\n\r\t\"\\/\x08\x0c\n\r\t\"\\/\x08",
            b"\xfb\xff\xbf\xfb\xff\xbf\xfb\xff\xbf\xfb\xff\xbf\xfb\xff\xbf\xfb\xff\xbf\xfb\xff\xbf\xfb\xff\xbf\xfb\xff\xbf\xfb",
            b"Bearer Bearer Bearer Bearer ",
        ];
        let work = |secret: &[u8], fold: bool| {
            let rendered = [b"Bearer ".as_slice(), secret].concat();
            let needles = vec![Zeroizing::new(secret.to_vec()), Zeroizing::new(rendered)];
            let s = if fold { Scrubber::ignoring_ascii_case(needles) } else { Scrubber::new(needles) };
            (s.build_work(), s.patterns.len(), s.window)
        };
        for fold in [false, true] {
            let base = work(secrets[0], fold);
            assert!(base.0 > 0);
            for secret in &secrets[1..] {
                assert_eq!(secret.len(), secrets[0].len());
                assert_eq!(work(secret, fold), base, "{} (fold {fold})", String::from_utf8_lossy(secret));
            }
        }
    }

    #[test]
    fn masks_json_escapes() {
        // PHP `json_encode`: `/` as `\/`.
        check(&[SECRET], r#"{"key":""#, r"sk-live\/4f+a&b<c>=Z9q?~", r#""}"#);
        // Go `encoding/json`: `&`, `<`, `>` as lowercase `\u00XX`.
        check(&[SECRET], r#"{"key":""#, r"sk-live/4f+a\u0026b\u003cc\u003e=Z9q?~", r#""}"#);
        // .NET `System.Text.Json`: `+` too, uppercase.
        check(&[SECRET], r#"{"key":""#, r"sk-live/4f\u002Ba\u0026b\u003Cc\u003E=Z9q?~", r#""}"#);
        // Every encoder: `"` and `\`, control characters.
        check(&[b"tok\"en\\x\ty"], r#"{"key":""#, r#"tok\"en\\x\ty"#, r#""}"#);
        check(&[b"tok\"en\\x\ty"], r#"{"key":""#, r#"tok"en\x\u0009y"#, r#""}"#);
    }

    #[test]
    fn masks_percent_encoding() {
        check(&[SECRET], "/echo?k=", "sk-live%2F4f%2Ba%26b%3Cc%3E%3DZ9q%3F~", "&x=1");
        check(&[SECRET], "/echo?k=", "sk-live%2f4f%2ba%26b%3cc%3e%3dZ9q%3f~", "&x=1");
        // Python `quote` keeps `/`; some encoders escape letters too.
        check(&[SECRET], "/echo?k=", "%73k-live/4f%2Ba%26b%3Cc%3E%3DZ9q%3F~", "&x=1");
        // A form: `+` for the space of the rendered header.
        check(&[SECRET, b"Bearer sk-live/4f+a&b<c>=Z9q?~"], "h=", "Bearer+sk-live%2F4f%2Ba%26b%3Cc%3E%3DZ9q%3F~", "");
        // A `+` in the secret is not a space.
        let mut s = scrubber(&[SECRET]);
        assert_eq!(run(&mut s, &[b"sk-live/4f a&b<c>=Z9q?~"]), b"sk-live/4f a&b<c>=Z9q?~");
    }

    #[test]
    fn masks_base64_at_every_alignment() {
        // base64(SECRET + "!"), base64("x" + SECRET + "!"), base64("xy" + SECRET + "!"): every
        // character carrying a bit of SECRET is masked, the edge ones shared with `x`, `y` or
        // `!` included; those carrying only neighbouring bits stay.
        check(&[SECRET], "", "c2stbGl2ZS80ZithJmI8Yz49WjlxP34", "h");
        check(&[SECRET], "e", "HNrLWxpdmUvNGYrYSZiPGM+PVo5cT9+", "IQ==");
        check(&[SECRET], "eH", "lzay1saXZlLzRmK2EmYjxjPj1aOXE/fi", "E=");
        // URL-safe, unpadded.
        check(&[SECRET], "e", "HNrLWxpdmUvNGYrYSZiPGM-PVo5cT9-", "IQ");
        check(&[SECRET], "eH", "lzay1saXZlLzRmK2EmYjxjPj1aOXE_fg", "");
        // `Basic base64("user:" + SECRET)`, and the same inside PHP JSON.
        check(&[SECRET], "Authorization: Basic dXNlcj", "pzay1saXZlLzRmK2EmYjxjPj1aOXE/fg", "==");
        check(&[SECRET], r#"{"auth":"Basic dXNlcj"#, r"pzay1saXZlLzRmK2EmYjxjPj1aOXE\/fg", r#"=="}"#);
    }

    /// Standard base64 with padding.
    fn base64(data: &[u8]) -> Vec<u8> {
        const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        for group in data.chunks(3) {
            let b = [group[0], *group.get(1).unwrap_or(&0), *group.get(2).unwrap_or(&0)];
            let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
            for k in 0..4 {
                out.push(if k <= group.len() { STD[(n >> (18 - 6 * k) & 63) as usize] } else { b'=' });
            }
        }
        out
    }

    #[test]
    fn base64_leaves_no_bit_of_the_secret_visible() {
        // Whatever the neighbouring bytes, the characters that carry any of the secret's bits
        // are masked: an echo of an encoded secret shows none of it, not its first or last bits.
        for before in [&b""[..], b"\x00", b"\xff\xff", b"u:", b"user:"] {
            for after in [&b""[..], b"\x00", b"\xff", b"!?"] {
                let encoded = base64(&[before, SECRET, after].concat());
                let first = before.len() * 8 / 6;
                let last = ((before.len() + SECRET.len()) * 8 - 1) / 6;
                let out = run(&mut scrubber(&[SECRET]), &[&encoded]);
                assert!(out[first..=last].iter().all(|&b| b == MASK), "{}", String::from_utf8_lossy(&out));
                assert_eq!(out[..first], encoded[..first]);
                assert_eq!(out[last + 1..], encoded[last + 1..]);
            }
        }
    }

    #[test]
    fn encoded_occurrence_split_across_chunks() {
        let input = b"a=sk-live%2F4f%2Ba%26b%3Cc%3E%3DZ9q%3F~ b=c2stbGl2ZS80ZithJmI8Yz49WjlxP34h";
        let whole = run(&mut scrubber(&[SECRET]), &[input]);
        assert_eq!(&whole[..2], b"a=");
        assert!(whole[2..39].iter().all(|&b| b == MASK));
        for cut in 0..=input.len() {
            let (a, b) = input.split_at(cut);
            assert_eq!(run(&mut scrubber(&[SECRET]), &[a, b]), whole, "cut at {cut}");
        }
        let mut s = scrubber(&[SECRET]);
        let mut out = s.push(b"x sk-live%2");
        out.extend(s.push(b"F4f%2Ba%26b%3Cc%3E%3DZ9q%3F~!"));
        out.extend(s.finish());
        assert_eq!(out, masked("x ", "sk-live%2F4f%2Ba%26b%3Cc%3E%3DZ9q%3F~", "!"), "an escape cut in half");
    }

    #[test]
    fn ignoring_ascii_case_masks_lowercased_forms() {
        let folded = || Scrubber::ignoring_ascii_case(vec![Zeroizing::new(SECRET.to_vec())]);
        let base64 = String::from_utf8(base64(&[SECRET, b"!"].concat())).unwrap();
        for form in [
            "sk-live/4f+a&b<c>=Z9q?~".to_string(),
            "sk-live%2f4f%2ba%26b%3cc%3e%3dz9q%3f~".to_string(),
            base64[..31].to_string(),
        ] {
            let lower = form.to_ascii_lowercase();
            let out = run(&mut folded(), &[lower.as_bytes()]);
            assert!(out.iter().all(|&b| b == MASK), "{lower}: {}", String::from_utf8_lossy(&out));
            assert_ne!(run(&mut scrubber(&[SECRET]), &[lower.as_bytes()]), vec![MASK; lower.len()], "{lower}");
        }
        assert_eq!(run(&mut folded(), &[b"x-sk-live-other"]), b"x-sk-live-other");
    }

    #[test]
    fn short_needles_get_no_base64() {
        // base64("abc") is "YWJj": four common characters, never masked on their own.
        let mut s = scrubber(&[b"abc"]);
        assert_eq!(run(&mut s, &[b"YWJj %61bc"]), b"YWJj *****");
        assert_eq!(scrubber(&[b"abc"]).patterns.len(), 1);
        // The secret and its base64 forms at three alignments, each taking either alphabet.
        assert_eq!(scrubber(&[SECRET]).patterns.len(), 4);
        // A needle holding another one with base64 forms gets none of its own.
        let rendered = [b"Bearer ".as_slice(), SECRET].concat();
        assert_eq!(scrubber(&[SECRET, &rendered]).patterns.len(), 5);
    }

    fn needle() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(prop_oneof![Just(b'a'), Just(b'b'), Just(b'/'), Just(b' ')], 1..6)
    }

    /// Plain bytes, spellings of them and pieces of spellings.
    fn input() -> impl Strategy<Value = Vec<u8>> {
        let piece = prop_oneof![
            Just(&b"a"[..]),
            Just(&b"b"[..]),
            Just(&b"/"[..]),
            Just(&b" "[..]),
            Just(&b"x"[..]),
            Just(&b"+"[..]),
            Just(&b"%"[..]),
            Just(&b"\\"[..]),
            Just(&b"%61"[..]),
            Just(&b"%2f"[..]),
            Just(&b"%2F"[..]),
            Just(&b"%20"[..]),
            Just(&b"\\/"[..]),
            Just(&b"\\u0062"[..]),
            Just(&b"\\u002F"[..]),
        ];
        proptest::collection::vec(piece, 0..40).prop_map(|pieces| pieces.concat())
    }

    proptest! {
        #[test]
        fn chunked_equals_whole(
            needles in proptest::collection::vec(needle(), 1..4),
            input in input(),
            cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..8),
        ) {
            let mut points: Vec<usize> = cuts.iter().map(|c| c.index(input.len() + 1)).collect();
            points.sort_unstable();
            let mut chunks = Vec::new();
            let mut last = 0;
            for p in points {
                chunks.push(&input[last..p]);
                last = p;
            }
            chunks.push(&input[last..]);

            // The longest spelling is six bytes per needle byte.
            let longest = 6 * needles.iter().map(Vec::len).max().unwrap();
            let mut s = Scrubber::new(needles.iter().cloned().map(Zeroizing::new).collect());
            let mut out = Vec::new();
            let mut fed = 0;
            for c in &chunks {
                out.extend(s.push(c));
                fed += c.len();
                // No stall: only a tail shorter than the longest spelling is ever held.
                prop_assert!(fed - out.len() < longest);
            }
            out.extend(s.finish());
            prop_assert_eq!(out, reference(&input, &needles));
        }

        #[test]
        fn release_points_depend_on_lengths_only(
            needles in proptest::collection::vec(needle(), 1..3),
            a in input(),
            b in input(),
            cuts in proptest::collection::vec(1usize..9, 1..40),
        ) {
            let n = a.len().min(b.len());
            let pieces = |input: &[u8]| {
                let mut s = Scrubber::new(needles.iter().cloned().map(Zeroizing::new).collect());
                let (mut at, mut sizes) = (0, Vec::new());
                for &c in cuts.iter().cycle() {
                    if at >= n { break; }
                    let end = (at + c).min(n);
                    sizes.push(s.push(&input[at..end]).len());
                    at = end;
                }
                sizes.push(s.finish().len());
                sizes
            };
            prop_assert_eq!(pieces(&a[..n]), pieces(&b[..n]));
        }

        #[test]
        fn flush_never_holds_and_preserves_length(
            needles in proptest::collection::vec(needle(), 1..4),
            messages in proptest::collection::vec(input(), 0..6),
        ) {
            let mut s = Scrubber::new(needles.iter().cloned().map(Zeroizing::new).collect());
            for m in &messages {
                let mut out = s.push(m);
                out.extend(s.flush());
                // Each message is scrubbed on its own and released whole at its boundary.
                prop_assert_eq!(out, reference(m, &needles));
            }
        }
    }
}

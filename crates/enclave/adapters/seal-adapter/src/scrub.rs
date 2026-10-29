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
//!   JWT, a JSON field), itself escaped as above. Only the stable core is masked: the one or
//!   two characters at each edge that also carry neighbouring bytes stay. Needles shorter
//!   than `MIN_SECRET_BYTES` get no base64 forms, whose cores would be a few common characters.
//!
//! Not masked: anything else the upstream computes from the secret (hex, a hash, a substring,
//! double escaping, HTML entities, MIME base64 with line breaks), or compressed data.
//!
//! Masking is visible, so it answers one question for a consumer who can make the upstream
//! return chosen text: is this exact text the secret? That is why secrets shorter than
//! `seal_proto::policy::MIN_SECRET_BYTES` are never sealed: a response listing every candidate
//! of a short length would find them. A needle of any length is still masked: passing an echo
//! through would be worse.

use seal_proto::policy::MIN_SECRET_BYTES;
use zeroize::{Zeroize, Zeroizing};

/// Streaming scrubber: overwrites every occurrence of any needle, in any of the forms the
/// module lists, with the same number of `*` bytes, including occurrences split across chunk
/// boundaries. Same length on purpose: Postgres, Redis and ClickHouse frames carry length
/// prefixes, so a length-changing replacement would corrupt the protocol. Holds back only a
/// tail that could still become an occurrence (shorter than the longest spelling: six bytes
/// per byte of a needle or base64 core), and `flush` releases it at a protocol message boundary, so a
/// request/response protocol never stalls on a reply that happens to end like the start of
/// the secret. Sees only the bytes as sent: a secret inside compressed data passes, which is
/// why adapters refuse response compression. Needles are zeroized on drop.
pub struct Scrubber {
    /// Each needle and its base64 cores, matched byte by byte in any spelling.
    patterns: Vec<Zeroizing<Vec<u8>>>,
    /// The held-back tail as received (unmasked), so an occurrence that starts in it is still
    /// found when the rest arrives.
    carry: Vec<u8>,
    /// Per byte of `carry`: already covered by a complete occurrence.
    carry_masked: Vec<bool>,
    /// Scratch for `scan`, kept to avoid an allocation per byte.
    active: Vec<Partial>,
    next: Vec<Partial>,
}

pub const MASK: u8 = b'*';

impl Scrubber {
    /// Empty needles are ignored.
    pub fn new(needles: Vec<Zeroizing<Vec<u8>>>) -> Self {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        for needle in needles.into_iter().filter(|n| !n.is_empty()) {
            let cores = if needle.len() >= MIN_SECRET_BYTES { base64_cores(&needle) } else { Vec::new() };
            for p in std::iter::once(needle).chain(cores) {
                if !patterns.contains(&p) {
                    patterns.push(p);
                }
            }
        }
        Self { patterns, carry: Vec::new(), carry_masked: Vec::new(), active: Vec::new(), next: Vec::new() }
    }

    /// Feed a chunk; returns bytes safe to forward now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.patterns.is_empty() {
            return chunk.to_vec();
        }
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let mut masked = std::mem::take(&mut self.carry_masked);
        masked.resize(buf.len(), false);

        // Mask every complete occurrence and find the earliest start of one still open.
        let mut emit = buf.len();
        for pattern in &self.patterns {
            if let Some(start) = scan(pattern, &buf, &mut masked, &mut self.active, &mut self.next) {
                emit = emit.min(start);
            }
        }

        let out = apply(&buf[..emit], &masked[..emit]);
        self.carry = buf[emit..].to_vec();
        self.carry_masked = masked[emit..].to_vec();
        buf.zeroize();
        out
    }

    /// Protocol message boundary: returns the held-back tail, scrubbed; the next push starts fresh.
    pub fn flush(&mut self) -> Vec<u8> {
        let out = apply(&self.carry, &self.carry_masked);
        self.carry.zeroize();
        self.carry_masked.clear();
        out
    }

    /// End of stream: returns the held-back tail, scrubbed.
    pub fn finish(&mut self) -> Vec<u8> {
        self.flush()
    }
}

impl Drop for Scrubber {
    fn drop(&mut self) {
        self.carry.zeroize();
    }
}

/// The base64 characters that depend only on the needle's bytes, for each of the three
/// alignments the needle can have inside encoded data, standard and URL-safe alphabets.
fn base64_cores(needle: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut cores = Vec::new();
    for lead in 0..3 {
        // `lead` unknown bytes before the needle, zeros after it to finish the last group.
        // Sized up front: a growing buffer would leave unzeroized copies behind.
        let whole = (lead + needle.len()).div_ceil(3) * 3;
        let mut bytes = Zeroizing::new(Vec::with_capacity(whole));
        bytes.resize(lead, 0);
        bytes.extend_from_slice(needle);
        bytes.resize(whole, 0);
        let mut core = Zeroizing::new(Vec::with_capacity(whole / 3 * 4));
        for (g, group) in bytes.chunks(3).enumerate() {
            let sextets = [
                group[0] >> 2,
                (group[0] & 0x03) << 4 | group[1] >> 4,
                (group[1] & 0x0f) << 2 | group[2] >> 6,
                group[2] & 0x3f,
            ];
            // The bytes each character's six bits come from.
            let from = [(0, 0), (0, 1), (1, 2), (2, 2)];
            for (sextet, (lo, hi)) in sextets.into_iter().zip(from) {
                if 3 * g + lo >= lead && 3 * g + hi < lead + needle.len() {
                    core.push(STD[usize::from(sextet)]);
                }
            }
        }
        let url = Zeroizing::new(
            core.iter()
                .map(|&c| match c {
                    b'+' => b'-',
                    b'/' => b'_',
                    c => c,
                })
                .collect::<Vec<u8>>(),
        );
        if url != core {
            cores.push(url);
        }
        cores.push(core);
    }
    cores
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

/// The `n`th spelling of byte `b`, if it has one: plain, `%XX`, `\u00XX`, a short JSON escape,
/// `+` for a space.
fn spelling(b: u8, n: usize) -> Option<Spelling> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let (hi, lo) = (HEX[usize::from(b >> 4)], HEX[usize::from(b & 0x0f)]);
    let (bytes, len, fold) = match n {
        0 => ([b, 0, 0, 0, 0, 0], 1, false),
        1 => ([b'%', hi, lo, 0, 0, 0], 3, true),
        2 => ([b'\\', b'u', b'0', b'0', hi, lo], 6, true),
        3 => {
            let short = match b {
                b'"' | b'\\' | b'/' => b,
                0x08 => b'b',
                0x0c => b'f',
                b'\n' => b'n',
                b'\r' => b'r',
                b'\t' => b't',
                _ => return None,
            };
            ([b'\\', short, 0, 0, 0, 0], 2, false)
        }
        4 if b == b' ' => ([b'+', 0, 0, 0, 0, 0], 1, false),
        _ => return None,
    };
    Some(Spelling { bytes, len, fold })
}

/// A started occurrence: `pattern[..pos]` is complete from `start`, and `at` bytes of the
/// `spelling`th spelling of `pattern[pos]` are matched (`at == 0`: none chosen yet).
#[derive(Clone, Copy)]
struct Partial {
    start: usize,
    pos: usize,
    spelling: usize,
    at: usize,
}

/// Marks every occurrence of `pattern` in `buf` and returns the start of the earliest one
/// still open at the end of `buf`.
fn scan(
    pattern: &[u8],
    buf: &[u8],
    masked: &mut [bool],
    active: &mut Vec<Partial>,
    next: &mut Vec<Partial>,
) -> Option<usize> {
    let first = pattern[0];
    active.clear();
    for (i, &b) in buf.iter().enumerate() {
        next.clear();
        let opens = b == first || b == b'%' || b == b'\\' || (first == b' ' && b == b'+');
        let fresh = opens.then_some(Partial { start: i, pos: 0, spelling: 0, at: 0 });
        for p in active.iter().copied().chain(fresh) {
            let tries = if p.at == 0 { 0..SPELLINGS } else { p.spelling..p.spelling + 1 };
            for n in tries {
                let Some(s) = spelling(pattern[p.pos], n) else { continue };
                if !s.accepts(p.at, b) {
                    continue;
                }
                let step = if p.at + 1 < s.len {
                    Partial { spelling: n, at: p.at + 1, ..p }
                } else if p.pos + 1 < pattern.len() {
                    Partial { pos: p.pos + 1, spelling: 0, at: 0, ..p }
                } else {
                    masked[p.start..=i].iter_mut().for_each(|m| *m = true);
                    continue;
                };
                // Two starts in the same state complete together: keep the earlier.
                match next.iter_mut().find(|q| (q.pos, q.spelling, q.at) == (step.pos, step.spelling, step.at)) {
                    Some(q) => q.start = q.start.min(step.start),
                    None => next.push(step),
                }
            }
        }
        std::mem::swap(active, next);
    }
    active.iter().map(|p| p.start).min()
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

    /// `input` is, as a whole, some spelling of `pattern`.
    fn spelled(input: &[u8], pattern: &[u8]) -> bool {
        let Some((&b, rest)) = pattern.split_first() else { return input.is_empty() };
        (0..SPELLINGS).filter_map(|n| spelling(b, n)).any(|s| {
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
        assert_eq!(out, b"error: ", "holds back only the possible prefix");
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
        assert_eq!(s.push(b"+OK sec"), b"+OK ");
        assert_eq!(s.flush(), b"sec", "a message boundary releases the tail");
        assert_eq!(s.push(b"ret"), b"ret", "the next push starts fresh");
        assert!(s.finish().is_empty());
        assert_eq!(s.push(b"secret"), b"******");
    }

    #[test]
    fn holds_back_less_than_longest_needle() {
        let mut s = scrubber(&[b"abcdef"]);
        assert_eq!(s.push(b"abcde"), b"");
        assert_eq!(s.push(b"x"), b"abcdex");
        assert_eq!(s.push(b"%6"), b"", "could become `%61`");
        assert_eq!(s.push(b"2"), b"%62");
    }

    #[test]
    fn masks_json_escapes() {
        // PHP `json_encode`: `/` as `\/`.
        check(&[SECRET], r#"{"key":""#, r"sk-live\/4f+a&b<c>=Z9q?~", r#""}"#);
        // Go `encoding/json`: `&`, `<`, `>` as lowercase `\u00XX`.
        check(&[SECRET], r#"{"key":""#, r"sk-live/4f+a&b<c>=Z9q?~", r#""}"#);
        // .NET `System.Text.Json`: `+` too, uppercase.
        check(&[SECRET], r#"{"key":""#, r"sk-live/4f+a&b<c>=Z9q?~", r#""}"#);
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
        // base64(SECRET + "!"), base64("x" + SECRET + "!"), base64("xy" + SECRET + "!"): the
        // edge characters that also carry `x`, `y` or `!` stay.
        check(&[SECRET], "", "c2stbGl2ZS80ZithJmI8Yz49WjlxP3", "4h");
        check(&[SECRET], "eH", "NrLWxpdmUvNGYrYSZiPGM+PVo5cT9+", "IQ==");
        check(&[SECRET], "eHl", "zay1saXZlLzRmK2EmYjxjPj1aOXE/f", "iE=");
        // URL-safe, unpadded.
        check(&[SECRET], "eH", "NrLWxpdmUvNGYrYSZiPGM-PVo5cT9-", "");
        check(&[SECRET], "eHl", "zay1saXZlLzRmK2EmYjxjPj1aOXE_f", "g");
        // `Basic base64("user:" + SECRET)`, and the same inside PHP JSON.
        check(&[SECRET], "Authorization: Basic dXNlcjp", "zay1saXZlLzRmK2EmYjxjPj1aOXE/f", "g==");
        check(&[SECRET], r#"{"auth":"Basic dXNlcjp"#, r"zay1saXZlLzRmK2EmYjxjPj1aOXE\/f", r#"g=="}"#);
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
        assert_eq!(s.push(b"x sk-live%2"), b"x ", "holds an escape cut in half");
        assert_eq!(s.push(b"F4f%2Ba%26b%3Cc%3E%3DZ9q%3F~!"), masked("", "sk-live%2F4f%2Ba%26b%3Cc%3E%3DZ9q%3F~", "!"));
    }

    #[test]
    fn short_needles_get_no_base64() {
        // base64("abc") is "YWJj": four common characters, never masked on their own.
        let mut s = scrubber(&[b"abc"]);
        assert_eq!(run(&mut s, &[b"YWJj %61bc"]), b"YWJj *****");
        assert_eq!(scrubber(&[b"abc"]).patterns.len(), 1);
        // The secret and three base64 cores, two of them also URL-safe: the third has no `+` or `/`.
        assert_eq!(scrubber(&[SECRET]).patterns.len(), 6);
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

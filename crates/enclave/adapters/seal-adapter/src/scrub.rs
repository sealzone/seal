//! Keeps the secret out of anything relayed back to the client: upstreams that
//! echo the key (error messages, debug endpoints, `CONFIG GET`) must not leak it.
//!
//! Masking is visible, so it answers one question for a consumer who can make the upstream
//! return chosen text: is this exact text the secret? That is why secrets shorter than
//! `seal_proto::policy::MIN_SECRET_BYTES` are never sealed: a response listing every candidate
//! of a short length would find them. A needle of any length is still masked: passing an echo
//! through would be worse.

use zeroize::{Zeroize, Zeroizing};

/// Streaming scrubber: overwrites every occurrence of any needle (the secret
/// and, for HTTP, the rendered header value) with the same number of `*`
/// bytes, including occurrences split across chunk boundaries. Same length on
/// purpose: Postgres, Redis and ClickHouse frames carry length prefixes, so a
/// length-changing replacement would corrupt the protocol. Holds back only a tail that is a
/// prefix of some needle (never more than `longest needle - 1` bytes), and `flush` releases it
/// at a protocol message boundary, so a request/response protocol never stalls on a reply
/// that happens to end like the start of the secret. Sees only plain bytes: a secret inside
/// compressed or encoded data passes, which is why adapters refuse response compression.
/// Needles are zeroized on drop.
pub struct Scrubber {
    needles: Vec<Zeroizing<Vec<u8>>>,
    /// The held-back tail as received (unmasked), so an occurrence that starts in it is still
    /// found when the rest arrives.
    carry: Vec<u8>,
    /// Per byte of `carry`: already covered by a complete occurrence.
    carry_masked: Vec<bool>,
    /// Knuth-Morris-Pratt failure table per needle: `fail[i]` is the length of the longest
    /// proper prefix of `needle[..=i]` that is also its suffix.
    fail: Vec<Zeroizing<Vec<usize>>>,
}

pub const MASK: u8 = b'*';

impl Scrubber {
    /// Empty needles are ignored.
    pub fn new(needles: Vec<Zeroizing<Vec<u8>>>) -> Self {
        let needles: Vec<_> = needles.into_iter().filter(|n| !n.is_empty()).collect();
        let fail = needles.iter().map(|n| failure_table(n)).collect();
        Self { needles, carry: Vec::new(), carry_masked: Vec::new(), fail }
    }

    /// Feed a chunk; returns bytes safe to forward now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.needles.is_empty() {
            return chunk.to_vec();
        }
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let mut masked = std::mem::take(&mut self.carry_masked);
        masked.resize(buf.len(), false);

        // Mask every complete occurrence and find the longest tail that could still become one.
        let mut hold = 0;
        for (needle, fail) in self.needles.iter().zip(&self.fail) {
            let state = scan(needle, fail, &buf, &mut masked);
            hold = hold.max(state);
        }

        let emit = buf.len() - hold;
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

fn failure_table(needle: &[u8]) -> Zeroizing<Vec<usize>> {
    let mut fail = Zeroizing::new(vec![0; needle.len()]);
    let mut k = 0;
    for i in 1..needle.len() {
        while k > 0 && needle[i] != needle[k] {
            k = fail[k - 1];
        }
        if needle[i] == needle[k] {
            k += 1;
        }
        fail[i] = k;
    }
    fail
}

/// Marks every occurrence of `needle` in `buf` and returns the length of the longest suffix
/// of `buf` that is a proper prefix of `needle`.
fn scan(needle: &[u8], fail: &[usize], buf: &[u8], masked: &mut [bool]) -> usize {
    let mut q = 0;
    for (i, &b) in buf.iter().enumerate() {
        while q > 0 && b != needle[q] {
            q = fail[q - 1];
        }
        if b == needle[q] {
            q += 1;
        }
        if q == needle.len() {
            masked[i + 1 - q..=i].iter_mut().for_each(|m| *m = true);
            q = fail[q - 1];
        }
    }
    q
}

fn apply(bytes: &[u8], masked: &[bool]) -> Vec<u8> {
    bytes.iter().zip(masked).map(|(&b, &m)| if m { MASK } else { b }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn scrubber(needles: &[&[u8]]) -> Scrubber {
        Scrubber::new(needles.iter().map(|n| Zeroizing::new(n.to_vec())).collect())
    }

    /// Masks the whole input at once: every byte inside any occurrence of any needle.
    fn reference(input: &[u8], needles: &[Vec<u8>]) -> Vec<u8> {
        let mut masked = vec![false; input.len()];
        for n in needles.iter().filter(|n| !n.is_empty()) {
            if n.len() > input.len() {
                continue;
            }
            for start in 0..=input.len() - n.len() {
                if &input[start..start + n.len()] == n.as_slice() {
                    masked[start..start + n.len()].iter_mut().for_each(|m| *m = true);
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
    }

    fn needle() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(prop_oneof![Just(b'a'), Just(b'b'), Just(b'c')], 1..6)
    }

    fn input() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(prop_oneof![Just(b'a'), Just(b'b'), Just(b'c'), Just(b'x')], 0..80)
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

            let longest = needles.iter().map(Vec::len).max().unwrap();
            let mut s = Scrubber::new(needles.iter().cloned().map(Zeroizing::new).collect());
            let mut out = Vec::new();
            let mut fed = 0;
            for c in &chunks {
                out.extend(s.push(c));
                fed += c.len();
                // No stall: only a tail shorter than the longest needle is ever held.
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

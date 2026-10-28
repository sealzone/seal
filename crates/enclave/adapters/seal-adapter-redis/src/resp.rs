//! RESP2/RESP3 framing: client commands in, upstream replies streamed out.
//!
//! - `CommandReader` takes client commands (arrays of bulk strings, or inline lines) from a
//!   buffer, within `MAX_ARGS`, `MAX_BULK`, `MAX_COMMAND_BYTES` and `MAX_INLINE`. Inline
//!   lines are split on ASCII whitespace; one with a quote is refused, because Redis would
//!   unquote it and the adapter re-encodes every command as an array before forwarding, so
//!   what it checked is exactly what the upstream runs.
//! - `ReplyScanner` finds where each upstream reply ends without buffering it: bulk payloads
//!   are skipped by length, so a reply of any size streams through. It knows every RESP3 type
//!   (attributes are part of the reply they precede) except streamed strings and aggregates
//!   (`$?`, `*?`), which Redis never sends. Header lines are bounded by `MAX_LINE` and nesting
//!   by `MAX_DEPTH`.
//!
//! Malformed input is a `FrameError`, never a panic.

use bytes::{Buf, BytesMut};

/// Arguments in one command (Redis's own limit).
pub const MAX_ARGS: usize = 1 << 20;
/// Bytes in one argument.
pub const MAX_BULK: usize = 64 << 20;
/// One command in memory: argument bytes plus `ARG_OVERHEAD` per argument.
pub const MAX_COMMAND_BYTES: usize = 96 << 20;
/// Accounting cost of an argument beyond its bytes.
const ARG_OVERHEAD: usize = 32;
/// An inline command line (Redis's own limit).
pub const MAX_INLINE: usize = 64 << 10;
/// A reply header line: a simple string, an error, a number or a length.
pub const MAX_LINE: usize = 64 << 10;
/// Nested aggregates in one reply.
pub const MAX_DEPTH: usize = 128;
/// Bytes of a length or count line in a command.
const MAX_HEADER: usize = 32;
/// Longest first element of a reply aggregate (or start of a simple reply) kept as its tag.
pub const TAG_MAX: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("Protocol error: {0}")]
pub struct FrameError(pub &'static str);

/// `*N` then N `$len` arguments.
pub fn encode_command<A: AsRef<[u8]>>(args: &[A]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + args.iter().map(|a| a.as_ref().len() + 16).sum::<usize>());
    encode_into(&mut out, args);
    out
}

pub fn encode_into<A: AsRef<[u8]>>(out: &mut Vec<u8>, args: &[A]) {
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        let a = a.as_ref();
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
}

/// Decimal integer, optional leading `-`, at most 20 characters.
fn parse_int(s: &[u8]) -> Option<i64> {
    let (neg, digits) = match s.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, s),
    };
    if digits.is_empty() || digits.len() > 19 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut v: i64 = 0;
    for d in digits {
        v = v.checked_mul(10)?.checked_add(i64::from(d - b'0'))?;
    }
    Some(if neg { -v } else { v })
}

/// The line starting at `buf[0]` up to its CRLF: `(content, bytes including CRLF)`, `None`
/// if incomplete, an error if longer than `max` or ended by a bare LF.
fn line(buf: &[u8], max: usize) -> Result<Option<(&[u8], usize)>, FrameError> {
    let window = &buf[..buf.len().min(max + 2)];
    match window.iter().position(|&b| b == b'\n') {
        Some(i) if i >= 1 && window[i - 1] == b'\r' => Ok(Some((&window[..i - 1], i + 1))),
        Some(_) => Err(FrameError("expected CRLF")),
        None if buf.len() >= max + 2 => Err(FrameError("line too long")),
        None => Ok(None),
    }
}

/// Client commands, taken from the front of a buffer as they complete.
#[derive(Debug, Default)]
pub struct CommandReader {
    partial: Option<Partial>,
}

#[derive(Debug)]
struct Partial {
    left: usize,
    args: Vec<Vec<u8>>,
    total: usize,
}

impl CommandReader {
    /// The next complete, non-empty command, removing its bytes from `buf`; `Ok(None)` when
    /// more bytes are needed. Empty commands (`*0`, `*-1`, blank inline lines) are skipped,
    /// as Redis does.
    pub fn next(&mut self, buf: &mut BytesMut) -> Result<Option<Vec<Vec<u8>>>, FrameError> {
        loop {
            if self.partial.is_none() {
                let Some(&first) = buf.first() else { return Ok(None) };
                if first != b'*' {
                    match inline(buf)? {
                        None => return Ok(None),
                        Some(args) if args.is_empty() => continue,
                        Some(args) => return Ok(Some(args)),
                    }
                }
                let Some((header, used)) = line(&buf[1..], MAX_HEADER)? else { return Ok(None) };
                let n = parse_int(header).ok_or(FrameError("invalid multibulk length"))?;
                if n > MAX_ARGS as i64 {
                    return Err(FrameError("invalid multibulk length"));
                }
                buf.advance(1 + used);
                if n <= 0 {
                    continue;
                }
                let left = n as usize;
                self.partial = Some(Partial { left, args: Vec::with_capacity(left.min(64)), total: 0 });
            }
            let partial = self.partial.as_mut().expect("set above");
            while partial.left > 0 {
                let Some(&first) = buf.first() else { return Ok(None) };
                if first != b'$' {
                    return Err(FrameError("expected '$'"));
                }
                let Some((header, used)) = line(&buf[1..], MAX_HEADER)? else { return Ok(None) };
                let len = parse_int(header)
                    .filter(|&l| (0..=MAX_BULK as i64).contains(&l))
                    .ok_or(FrameError("invalid bulk length"))? as usize;
                if partial.total + len + ARG_OVERHEAD > MAX_COMMAND_BYTES {
                    return Err(FrameError("command too large"));
                }
                let need = 1 + used + len + 2;
                if buf.len() < need {
                    buf.reserve(need - buf.len());
                    return Ok(None);
                }
                if &buf[need - 2..need] != b"\r\n" {
                    return Err(FrameError("expected CRLF after bulk"));
                }
                buf.advance(1 + used);
                partial.args.push(buf.split_to(len).to_vec());
                buf.advance(2);
                partial.total += len + ARG_OVERHEAD;
                partial.left -= 1;
            }
            return Ok(self.partial.take().map(|p| p.args));
        }
    }
}

/// One inline line, split on ASCII whitespace.
fn inline(buf: &mut BytesMut) -> Result<Option<Vec<Vec<u8>>>, FrameError> {
    let window = &buf[..buf.len().min(MAX_INLINE + 1)];
    let Some(end) = window.iter().position(|&b| b == b'\n') else {
        return if buf.len() > MAX_INLINE { Err(FrameError("too big inline request")) } else { Ok(None) };
    };
    let line = buf.split_to(end + 1);
    let text = &line[..end];
    if text.iter().any(|&b| b == b'"' || b == b'\'') {
        return Err(FrameError("quoted inline commands are not supported, use RESP"));
    }
    Ok(Some(
        text.split(|b| b.is_ascii_whitespace() || *b == 0x0b).filter(|a| !a.is_empty()).map(<[u8]>::to_vec).collect(),
    ))
}

/// What the scanner learned about a reply.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameInfo {
    /// The reply's type byte (after any attribute): `+`, `-`, `*`, `>`, `%`, ...; 0 until known.
    pub kind: u8,
    /// For an aggregate, its first element when that is a bulk or simple string of at most
    /// `TAG_MAX` bytes (pub/sub frames start with `message`, `subscribe`, ...). For a simple
    /// string or error, its first `TAG_MAX` bytes.
    pub tag: Option<Vec<u8>>,
    /// For an aggregate, its third element when that is an integer (the subscription count in
    /// pub/sub confirmations).
    pub third: Option<i64>,
}

impl FrameInfo {
    pub fn is_error(&self) -> bool {
        matches!(self.kind, b'-' | b'!')
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Type,
    Line(u8),
    Blob { left: u64 },
    BlobCr,
    BlobLf,
}

#[derive(Debug)]
struct Level {
    left: u64,
    attribute: bool,
}

/// Streams over upstream replies, one at a time, reporting where each ends.
#[derive(Debug)]
pub struct ReplyScanner {
    state: State,
    line: Vec<u8>,
    stack: Vec<Level>,
    info: FrameInfo,
    /// Elements of the top-level aggregate completed so far.
    children: u64,
    /// Bytes of the current blob kept for the tag, when it is the top aggregate's first element.
    capture: Option<Vec<u8>>,
}

impl Default for ReplyScanner {
    fn default() -> Self {
        Self {
            state: State::Type,
            line: Vec::new(),
            stack: Vec::new(),
            info: FrameInfo::default(),
            children: 0,
            capture: None,
        }
    }
}

impl ReplyScanner {
    /// What is known so far about the reply being scanned.
    pub fn current(&self) -> &FrameInfo {
        &self.info
    }

    /// Scans `input` up to the end of the current reply. Returns the bytes used and, when the
    /// reply ended at the last of them, what it was; the scanner then starts on the next reply.
    pub fn feed(&mut self, input: &[u8]) -> Result<(usize, Option<FrameInfo>), FrameError> {
        let mut i = 0;
        while i < input.len() {
            let done = match self.state {
                State::Type => {
                    let t = input[i];
                    i += 1;
                    if !b"+-:$*_#,(!=%~>|".contains(&t) {
                        return Err(FrameError("unknown reply type"));
                    }
                    if self.stack.is_empty() && t != b'|' {
                        self.info.kind = t;
                    }
                    self.line.clear();
                    self.state = State::Line(t);
                    false
                }
                State::Line(t) => {
                    let rest = &input[i..];
                    let (take, end) = match rest.iter().position(|&b| b == b'\n') {
                        Some(p) => (p + 1, true),
                        None => (rest.len(), false),
                    };
                    if self.line.len() + take > MAX_LINE + 2 {
                        return Err(FrameError("reply line too long"));
                    }
                    self.line.extend_from_slice(&rest[..take]);
                    i += take;
                    if !end {
                        continue;
                    }
                    if self.line.len() < 2 || self.line[self.line.len() - 2] != b'\r' {
                        return Err(FrameError("expected CRLF"));
                    }
                    self.line.truncate(self.line.len() - 2);
                    self.header(t)?
                }
                State::Blob { left } => {
                    let take = (input.len() - i).min(usize::try_from(left).unwrap_or(usize::MAX));
                    if let Some(capture) = &mut self.capture {
                        capture.extend_from_slice(&input[i..i + take]);
                    }
                    i += take;
                    let left = left - take as u64;
                    self.state = if left == 0 { State::BlobCr } else { State::Blob { left } };
                    false
                }
                State::BlobCr | State::BlobLf => {
                    let want = if self.state == State::BlobCr { b'\r' } else { b'\n' };
                    if input[i] != want {
                        return Err(FrameError("expected CRLF after blob"));
                    }
                    i += 1;
                    if self.state == State::BlobCr {
                        self.state = State::BlobLf;
                        false
                    } else {
                        if let Some(capture) = self.capture.take() {
                            self.info.tag = Some(capture);
                        }
                        self.state = State::Type;
                        self.value_done(false)
                    }
                }
            };
            if done {
                self.children = 0;
                return Ok((i, Some(std::mem::take(&mut self.info))));
            }
        }
        Ok((i, None))
    }

    /// Index of the value starting now among the top aggregate's elements, if it is one.
    fn top_child(&self) -> Option<u64> {
        (self.stack.len() == 1 && !self.stack[0].attribute).then_some(self.children)
    }

    /// A header line for type `t` is complete; returns whether the reply ended.
    fn header(&mut self, t: u8) -> Result<bool, FrameError> {
        self.state = State::Type;
        let child = self.top_child();
        let line = std::mem::take(&mut self.line);
        let result = (|| match t {
            b'+' | b'-' => {
                if self.stack.is_empty() {
                    self.info.tag = Some(line[..line.len().min(TAG_MAX)].to_vec());
                } else if child == Some(0) && t == b'+' && line.len() <= TAG_MAX {
                    self.info.tag = Some(line.clone());
                }
                Ok(self.value_done(false))
            }
            b':' => {
                let v = parse_int(&line).ok_or(FrameError("invalid integer"))?;
                if child == Some(2) {
                    self.info.third = Some(v);
                }
                Ok(self.value_done(false))
            }
            b'(' => {
                parse_big(&line).ok_or(FrameError("invalid big number"))?;
                Ok(self.value_done(false))
            }
            b',' => {
                if line.is_empty() {
                    return Err(FrameError("invalid double"));
                }
                Ok(self.value_done(false))
            }
            b'_' => {
                if !line.is_empty() {
                    return Err(FrameError("invalid null"));
                }
                Ok(self.value_done(false))
            }
            b'#' => {
                if line != b"t" && line != b"f" {
                    return Err(FrameError("invalid boolean"));
                }
                Ok(self.value_done(false))
            }
            b'$' | b'!' | b'=' => {
                let len = parse_int(&line).ok_or(FrameError("invalid blob length"))?;
                if len == -1 && t == b'$' {
                    return Ok(self.value_done(false));
                }
                let len = u64::try_from(len).map_err(|_| FrameError("invalid blob length"))?;
                if child == Some(0) && t == b'$' && len <= TAG_MAX as u64 {
                    self.capture = Some(Vec::with_capacity(len as usize));
                }
                self.state = if len == 0 { State::BlobCr } else { State::Blob { left: len } };
                Ok(false)
            }
            _ => {
                // Aggregates: `*`, `~`, `>`, `%`, `|`.
                let n = parse_int(&line).ok_or(FrameError("invalid aggregate length"))?;
                if n == -1 && t == b'*' {
                    return Ok(self.value_done(false));
                }
                let n = u64::try_from(n).map_err(|_| FrameError("invalid aggregate length"))?;
                let pairs = matches!(t, b'%' | b'|');
                let left = if pairs { n.checked_mul(2).ok_or(FrameError("invalid aggregate length"))? } else { n };
                if left == 0 {
                    return Ok(self.value_done(t == b'|'));
                }
                if self.stack.len() >= MAX_DEPTH {
                    return Err(FrameError("reply nested too deeply"));
                }
                self.stack.push(Level { left, attribute: t == b'|' });
                Ok(false)
            }
        })();
        self.line = line;
        result
    }

    /// A value (an attribute when `attribute`) ended; returns whether the whole reply did.
    fn value_done(&mut self, mut attribute: bool) -> bool {
        loop {
            let depth = self.stack.len();
            let Some(level) = self.stack.last_mut() else {
                // An attribute before the reply is not the reply.
                return !attribute;
            };
            if attribute {
                return false;
            }
            level.left -= 1;
            if depth == 1 && !level.attribute {
                self.children += 1;
            }
            if level.left > 0 {
                return false;
            }
            attribute = self.stack.pop().is_some_and(|l| l.attribute);
        }
    }
}

fn parse_big(s: &[u8]) -> Option<()> {
    let digits = s.strip_prefix(b"-").unwrap_or(s);
    (!digits.is_empty() && digits.iter().all(u8::is_ascii_digit)).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn read_all(input: &[u8], splits: &[usize]) -> Result<Vec<Vec<Vec<u8>>>, FrameError> {
        let mut reader = CommandReader::default();
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        let mut at = 0;
        for &s in splits.iter().chain(std::iter::once(&input.len())) {
            let s = s.clamp(at, input.len());
            buf.extend_from_slice(&input[at..s]);
            at = s;
            while let Some(cmd) = reader.next(&mut buf)? {
                out.push(cmd);
            }
        }
        Ok(out)
    }

    #[test]
    fn commands() {
        let input = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n*0\r\nPING\r\n  \r\nset a  b\n*-1\r\n*1\r\n$0\r\n\r\n";
        let got = read_all(input, &[]).unwrap();
        let want: Vec<Vec<Vec<u8>>> = vec![
            vec![b"GET".to_vec(), b"k".to_vec()],
            vec![b"PING".to_vec()],
            vec![b"set".to_vec(), b"a".to_vec(), b"b".to_vec()],
            vec![b"".to_vec()],
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn command_errors() {
        for (bad, why) in [
            (&b"*2\r\n:1\r\n"[..], "expected '$'"),
            (b"*x\r\n", "invalid multibulk length"),
            (b"*1\r\n$-1\r\n", "invalid bulk length"),
            (b"*1\r\n$3\r\nabcXY", "expected CRLF after bulk"),
            (b"*1\n", "expected CRLF"),
            (b"GET \"a b\"\r\n", "quoted inline commands are not supported, use RESP"),
            (b"*1048577\r\n", "invalid multibulk length"),
            (b"*1\r\n$67108865\r\n", "invalid bulk length"),
        ] {
            assert_eq!(read_all(bad, &[]), Err(FrameError(why)), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn size_limits() {
        let long_inline = vec![b'a'; MAX_INLINE + 1];
        assert_eq!(read_all(&long_inline, &[]), Err(FrameError("too big inline request")));
        let mut ok_inline = vec![b'a'; MAX_INLINE - 1];
        ok_inline.push(b'\n');
        assert_eq!(read_all(&ok_inline, &[]).unwrap().len(), 1);
        assert_eq!(read_all(b"*111111111111111111111111111111111\r\n", &[]), Err(FrameError("line too long")));
        // Two maximal arguments exceed the command budget.
        let header = format!("*2\r\n${MAX_BULK}\r\n");
        let mut big = header.into_bytes();
        big.extend(std::iter::repeat_n(b'x', MAX_BULK));
        big.extend_from_slice(format!("\r\n${MAX_BULK}\r\n").as_bytes());
        assert_eq!(read_all(&big, &[]), Err(FrameError("command too large")));
    }

    #[test]
    fn incomplete_bulk_reserves_and_waits() {
        let mut reader = CommandReader::default();
        let mut buf = BytesMut::from(&b"*1\r\n$10\r\nabc"[..]);
        assert_eq!(reader.next(&mut buf), Ok(None));
        buf.extend_from_slice(b"defghij\r\n");
        assert_eq!(reader.next(&mut buf), Ok(Some(vec![b"abcdefghij".to_vec()])));
        assert!(buf.is_empty());
    }

    /// RESP3 values for round trips.
    #[derive(Clone, Debug)]
    enum Value {
        Simple(String),
        Error(String),
        Int(i64),
        Bulk(Vec<u8>),
        NullBulk,
        NullArray,
        Null,
        Bool(bool),
        Double(String),
        Big(String),
        BlobError(Vec<u8>),
        Verbatim(Vec<u8>),
        Array(Vec<Value>),
        Set(Vec<Value>),
        Push(Vec<Value>),
        Map(Vec<(Value, Value)>),
        Attributed(Vec<(Value, Value)>, Box<Value>),
    }

    fn encode(v: &Value, out: &mut Vec<u8>) {
        let agg = |out: &mut Vec<u8>, t: char, items: &[Value]| {
            out.extend_from_slice(format!("{t}{}\r\n", items.len()).as_bytes());
            items.iter().for_each(|i| encode(i, out));
        };
        let pairs = |out: &mut Vec<u8>, t: char, items: &[(Value, Value)]| {
            out.extend_from_slice(format!("{t}{}\r\n", items.len()).as_bytes());
            for (k, v) in items {
                encode(k, out);
                encode(v, out);
            }
        };
        let blob = |out: &mut Vec<u8>, t: char, b: &[u8]| {
            out.extend_from_slice(format!("{t}{}\r\n", b.len()).as_bytes());
            out.extend_from_slice(b);
            out.extend_from_slice(b"\r\n");
        };
        match v {
            Value::Simple(s) => out.extend_from_slice(format!("+{s}\r\n").as_bytes()),
            Value::Error(s) => out.extend_from_slice(format!("-{s}\r\n").as_bytes()),
            Value::Int(i) => out.extend_from_slice(format!(":{i}\r\n").as_bytes()),
            Value::Bulk(b) => blob(out, '$', b),
            Value::NullBulk => out.extend_from_slice(b"$-1\r\n"),
            Value::NullArray => out.extend_from_slice(b"*-1\r\n"),
            Value::Null => out.extend_from_slice(b"_\r\n"),
            Value::Bool(b) => out.extend_from_slice(if *b { b"#t\r\n" } else { b"#f\r\n" }),
            Value::Double(d) => out.extend_from_slice(format!(",{d}\r\n").as_bytes()),
            Value::Big(d) => out.extend_from_slice(format!("({d}\r\n").as_bytes()),
            Value::BlobError(b) => blob(out, '!', b),
            Value::Verbatim(b) => blob(out, '=', b),
            Value::Array(items) => agg(out, '*', items),
            Value::Set(items) => agg(out, '~', items),
            Value::Push(items) => agg(out, '>', items),
            Value::Map(items) => pairs(out, '%', items),
            Value::Attributed(attrs, inner) => {
                pairs(out, '|', attrs);
                encode(inner, out);
            }
        }
    }

    /// What the scanner should report for `v` at the top.
    fn expected_info(v: &Value) -> FrameInfo {
        let kind = |v: &Value| -> u8 {
            match v {
                Value::Simple(_) => b'+',
                Value::Error(_) => b'-',
                Value::Int(_) => b':',
                Value::Bulk(_) | Value::NullBulk => b'$',
                Value::NullArray | Value::Array(_) => b'*',
                Value::Null => b'_',
                Value::Bool(_) => b'#',
                Value::Double(_) => b',',
                Value::Big(_) => b'(',
                Value::BlobError(_) => b'!',
                Value::Verbatim(_) => b'=',
                Value::Set(_) => b'~',
                Value::Push(_) => b'>',
                Value::Map(_) => b'%',
                Value::Attributed(..) => unreachable!(),
            }
        };
        let mut v = v;
        while let Value::Attributed(_, inner) = v {
            v = inner;
        }
        let mut info = FrameInfo { kind: kind(v), ..Default::default() };
        let elements: Vec<&Value> = match v {
            Value::Array(i) | Value::Set(i) | Value::Push(i) => i.iter().collect(),
            Value::Map(p) => p.iter().flat_map(|(k, v)| [k, v]).collect(),
            Value::Simple(s) | Value::Error(s) => {
                info.tag = Some(s.as_bytes()[..s.len().min(TAG_MAX)].to_vec());
                return info;
            }
            _ => return info,
        };
        // Attributes inside an aggregate are not elements.
        fn strip(mut v: &Value) -> &Value {
            while let Value::Attributed(_, inner) = v {
                v = inner;
            }
            v
        }
        let elements: Vec<&Value> = elements.into_iter().map(strip).collect();
        match elements.first() {
            Some(Value::Bulk(b)) if b.len() <= TAG_MAX => info.tag = Some(b.clone()),
            Some(Value::Simple(s)) if s.len() <= TAG_MAX => info.tag = Some(s.as_bytes().to_vec()),
            _ => {}
        }
        if let Some(Value::Int(i)) = elements.get(2) {
            info.third = Some(*i);
        }
        info
    }

    fn line_text() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9 :_.-]{0,40}"
    }

    fn value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            line_text().prop_map(Value::Simple),
            line_text().prop_map(Value::Error),
            any::<i64>().prop_map(Value::Int),
            proptest::collection::vec(any::<u8>(), 0..64).prop_map(Value::Bulk),
            Just(Value::NullBulk),
            Just(Value::NullArray),
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            "-?[0-9]{1,5}(\\.[0-9]{1,3})?|inf|-inf|nan".prop_map(Value::Double),
            "-?[0-9]{1,40}".prop_map(Value::Big),
            proptest::collection::vec(any::<u8>(), 0..16).prop_map(Value::BlobError),
            proptest::collection::vec(any::<u8>(), 4..16).prop_map(Value::Verbatim),
            prop_oneof![Just("message"), Just("subscribe"), Just("pong")]
                .prop_map(|s| Value::Bulk(s.as_bytes().to_vec())),
        ];
        leaf.prop_recursive(4, 48, 6, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Set),
                proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Push),
                proptest::collection::vec((inner.clone(), inner.clone()), 0..4).prop_map(Value::Map),
                (proptest::collection::vec((inner.clone(), inner.clone()), 0..3), inner)
                    .prop_map(|(a, v)| Value::Attributed(a, Box::new(v))),
            ]
        })
    }

    /// Scans `input` fed in pieces cut at `splits`: every reply's end offset and info.
    fn scan(input: &[u8], splits: &[usize]) -> Result<Vec<(usize, FrameInfo)>, FrameError> {
        let mut scanner = ReplyScanner::default();
        let mut cuts: Vec<usize> = splits.iter().map(|&s| s.min(input.len())).collect();
        cuts.push(input.len());
        cuts.sort_unstable();
        let mut out = Vec::new();
        let mut at = 0;
        for cut in cuts {
            while at < cut {
                let (n, done) = scanner.feed(&input[at..cut])?;
                assert!(n > 0 && at + n <= cut);
                at += n;
                if let Some(info) = done {
                    out.push((at, info));
                }
            }
        }
        Ok(out)
    }

    proptest! {
        #[test]
        fn command_round_trip(
            commands in proptest::collection::vec(proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 1..6), 1..6),
            splits in proptest::collection::vec(0usize..2000, 0..8),
        ) {
            let mut input = Vec::new();
            for c in &commands {
                encode_into(&mut input, c);
            }
            let mut splits = splits;
            splits.sort_unstable();
            prop_assert_eq!(read_all(&input, &splits).unwrap(), commands);
        }

        #[test]
        fn inline_round_trip(words in proptest::collection::vec("[a-zA-Z0-9_:.-]{1,12}", 1..6), crlf in any::<bool>()) {
            let mut input = words.join(" ").into_bytes();
            input.extend_from_slice(if crlf { b"\r\n" } else { b"\n" });
            let want: Vec<Vec<u8>> = words.iter().map(|w| w.as_bytes().to_vec()).collect();
            prop_assert_eq!(read_all(&input, &[]).unwrap(), vec![want]);
        }

        #[test]
        fn truncated_command_waits(args in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..20), 1..5), cut in any::<prop::sample::Index>()) {
            let input = encode_command(&args);
            let cut = cut.index(input.len());
            let mut buf = BytesMut::from(&input[..cut]);
            prop_assert_eq!(CommandReader::default().next(&mut buf), Ok(None));
        }

        #[test]
        fn garbage_commands_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300), splits in proptest::collection::vec(0usize..300, 0..4)) {
            let mut splits = splits;
            splits.sort_unstable();
            let _ = read_all(&bytes, &splits);
            let mut star = b"*3\r\n".to_vec();
            star.extend_from_slice(&bytes);
            let _ = read_all(&star, &splits);
        }

        #[test]
        fn reply_round_trip(values in proptest::collection::vec(value(), 1..5), splits in proptest::collection::vec(0usize..4000, 0..10)) {
            let mut input = Vec::new();
            let mut want = Vec::new();
            for v in &values {
                encode(v, &mut input);
                want.push((input.len(), expected_info(v)));
            }
            prop_assert_eq!(scan(&input, &splits).unwrap(), want);
        }

        #[test]
        fn truncated_reply_never_ends(v in value(), cut in any::<prop::sample::Index>()) {
            let mut input = Vec::new();
            encode(&v, &mut input);
            let cut = cut.index(input.len());
            prop_assert_eq!(scan(&input[..cut], &[]).unwrap(), vec![]);
        }

        #[test]
        fn garbage_replies_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300), splits in proptest::collection::vec(0usize..300, 0..4)) {
            let _ = scan(&bytes, &splits);
            for prefix in [&b"*3\r\n"[..], b"%2\r\n", b"|1\r\n", b">2\r\n$7\r\nmessage\r\n"] {
                let mut input = prefix.to_vec();
                input.extend_from_slice(&bytes);
                let _ = scan(&input, &splits);
            }
        }
    }

    #[test]
    fn reply_errors() {
        for bad in [
            &b"?\r\n"[..],
            b"$?\r\n",
            b"*?\r\n",
            b":12a\r\n",
            b"$3\r\nabcd\r\n",
            b"#x\r\n",
            b"_x\r\n",
            b"%-1\r\n",
            b"+ok\n",
            b"$-2\r\n",
        ] {
            assert!(scan(bad, &[]).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let deep: Vec<u8> = b"*1\r\n".repeat(MAX_DEPTH + 1);
        assert_eq!(scan(&deep, &[]), Err(FrameError("reply nested too deeply")));
        let mut long = b"+".to_vec();
        long.extend(std::iter::repeat_n(b'a', MAX_LINE + 3));
        assert_eq!(scan(&long, &[]), Err(FrameError("reply line too long")));
    }

    #[test]
    fn large_bulk_streams_without_buffering() {
        let mut scanner = ReplyScanner::default();
        assert_eq!(scanner.feed(b"$1000000000\r\n").unwrap(), (13, None));
        for _ in 0..10 {
            assert_eq!(scanner.feed(&[b'x'; 1000]).unwrap(), (1000, None));
        }
        assert!(scanner.line.capacity() < 64);
    }

    #[test]
    fn pubsub_frames() {
        let got = scan(
            b">3\r\n$9\r\nsubscribe\r\n$2\r\nch\r\n:1\r\n*3\r\n$7\r\nmessage\r\n$2\r\nch\r\n$2\r\nhi\r\n",
            &[5, 30],
        )
        .unwrap();
        assert_eq!(got[0].1, FrameInfo { kind: b'>', tag: Some(b"subscribe".to_vec()), third: Some(1) });
        assert_eq!(got[1].1, FrameInfo { kind: b'*', tag: Some(b"message".to_vec()), third: None });
    }
}

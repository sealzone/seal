//! Which commands the adapter refuses, and how commands are summarized for telemetry and
//! detectors.

/// `Completion::action` and `Observation::action`: the upper-cased command name when it is
/// at most this long and made of letters, digits and `._-|:`; `OTHER` otherwise.
const ACTION_MAX: usize = 32;
/// `Observation::content` keeps at most this many bytes of the command line.
pub const CONTENT_MAX: usize = 4096;

/// The fixed text of a refusal, or `None` to forward the command. `db` is the destination's.
pub fn refusal(args: &[Vec<u8>], db: u8) -> Option<&'static str> {
    const AUTHENTICATED: &str = "the connection is already authenticated by Seal";
    const OTHER_DB: &str = "the command reaches beyond the destination's database";
    const CONNECTION: &str = "the command changes the connection in a way Seal cannot relay";
    const ADMIN: &str = "server administration is not allowed through Seal";

    let name = args.first()?;
    let is = |n: &str| name.eq_ignore_ascii_case(n.as_bytes());
    let arg = |i: usize| args.get(i).map(Vec::as_slice).unwrap_or_default();
    let arg_is = |i: usize, n: &str| arg(i).eq_ignore_ascii_case(n.as_bytes());
    let this_db = |v: &[u8]| v == db.to_string().as_bytes();

    if is("AUTH") || (is("HELLO") && hello_has_auth(args)) {
        return Some(AUTHENTICATED);
    }
    if is("SELECT") {
        return (args.len() != 2 || !this_db(arg(1))).then_some(OTHER_DB);
    }
    if is("COPY") {
        // Options start after the two keys, as Redis parses them.
        let mut i = 3;
        while i < args.len() {
            if arg_is(i, "DB") {
                if !this_db(arg(i + 1)) {
                    return Some(OTHER_DB);
                }
                i += 1;
            }
            i += 1;
        }
        return None;
    }
    if ["SWAPDB", "MOVE", "FLUSHALL", "MIGRATE"].iter().any(|n| is(n)) {
        return Some(OTHER_DB);
    }
    if ["RESET", "MONITOR", "SYNC", "PSYNC", "REPLCONF"].iter().any(|n| is(n)) {
        return Some(CONNECTION);
    }
    if is("CLIENT") {
        if arg_is(1, "REPLY") && !(args.len() == 3 && arg_is(2, "ON")) {
            return Some(CONNECTION);
        }
        if ["KILL", "PAUSE", "UNPAUSE"].iter().any(|s| arg_is(1, s)) {
            return Some(ADMIN);
        }
        return None;
    }
    if ["ACL", "CONFIG", "MODULE", "DEBUG", "SHUTDOWN", "REPLICAOF", "SLAVEOF", "FAILOVER"].iter().any(|n| is(n)) {
        return Some(ADMIN);
    }
    None
}

/// `HELLO [protover [AUTH user pass] [SETNAME name]]` names `AUTH` as an option. Options are
/// read as Redis reads them, so a client name of `AUTH` is not one; after an unknown option
/// Redis fails the whole command, so the rest is not read.
pub fn hello_has_auth(args: &[Vec<u8>]) -> bool {
    let mut i = 2;
    while i < args.len() {
        let opt = &args[i];
        if opt.eq_ignore_ascii_case(b"AUTH") {
            return true;
        }
        if opt.eq_ignore_ascii_case(b"SETNAME") {
            i += 2;
        } else {
            return false;
        }
    }
    false
}

/// The action for `name`: see `ACTION_MAX`.
pub fn action(name: &[u8]) -> String {
    let ok = !name.is_empty()
        && name.len() <= ACTION_MAX
        && name.iter().all(|b| b.is_ascii_alphanumeric() || b"._-|:".contains(b));
    if ok {
        String::from_utf8_lossy(name).to_ascii_uppercase()
    } else {
        "OTHER".to_string()
    }
}

/// The command line for detectors: arguments as sent, separated by spaces, cut at
/// `CONTENT_MAX` bytes. The secret cannot be in it (the client never has it), and the
/// commands that carry a Seal credential (`AUTH`, `HELLO … AUTH`) are never observed.
pub fn content(args: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        let room = CONTENT_MAX.saturating_sub(out.len());
        out.extend_from_slice(&a[..a.len().min(room)]);
        if out.len() >= CONTENT_MAX {
            break;
        }
    }
    out.truncate(CONTENT_MAX);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(line: &str) -> Vec<Vec<u8>> {
        line.split(' ').map(|a| a.as_bytes().to_vec()).collect()
    }

    #[test]
    fn refused() {
        for line in [
            "AUTH x",
            "auth user x",
            "HELLO 3 AUTH u p",
            "hello 2 SETNAME n auth u p",
            "SELECT 0",
            "SELECT 02",
            "select 2 3",
            "SELECT",
            "SWAPDB 2 0",
            "MOVE k 0",
            "COPY a b DB 0",
            "COPY a b REPLACE db 5",
            "FLUSHALL",
            "MIGRATE h 6379 k 0 1000",
            "RESET",
            "MONITOR",
            "SYNC",
            "PSYNC ? -1",
            "REPLCONF listening-port 1",
            "CLIENT REPLY OFF",
            "client reply skip",
            "CLIENT REPLY",
            "CLIENT KILL ID 1",
            "CLIENT PAUSE 100",
            "CLIENT UNPAUSE",
            "ACL SETUSER x",
            "CONFIG GET requirepass",
            "MODULE LOAD x",
            "DEBUG SLEEP 1",
            "SHUTDOWN",
            "REPLICAOF h 1",
            "SLAVEOF h 1",
            "FAILOVER",
        ] {
            assert!(refusal(&cmd(line), 2).is_some(), "{line}");
        }
    }

    #[test]
    fn forwarded() {
        for line in [
            "GET k",
            "SET auth x",
            "SELECT 2",
            "HELLO",
            "HELLO 3",
            "HELLO 3 SETNAME AUTH",
            "HELLO 3 FOO AUTH u p",
            "COPY a b",
            "COPY DB DB REPLACE",
            "COPY a b DB 2 REPLACE",
            "CLIENT REPLY ON",
            "CLIENT SETNAME kill",
            "CLIENT LIST",
            "FLUSHDB",
            "EVAL x 0",
            "SUBSCRIBE acl",
        ] {
            assert_eq!(refusal(&cmd(line), 2), None, "{line}");
        }
    }

    #[test]
    fn actions() {
        assert_eq!(action(b"get"), "GET");
        assert_eq!(action(b"JSON.GET"), "JSON.GET");
        assert_eq!(action(b""), "OTHER");
        assert_eq!(action(b"a b"), "OTHER");
        assert_eq!(action(&[b'x'; 33]), "OTHER");
        assert_eq!(action("gét".as_bytes()), "OTHER");
    }

    #[test]
    fn content_is_bounded() {
        assert_eq!(content(&cmd("SET k v")), b"SET k v");
        let big = vec![b"SET".to_vec(), b"k".to_vec(), vec![b'v'; 10_000], b"EX".to_vec()];
        let c = content(&big);
        assert_eq!(c.len(), CONTENT_MAX);
        assert!(c.starts_with(b"SET k vvv"));
    }
}

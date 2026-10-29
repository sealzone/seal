//! Per-request policy checks shared by adapters.

use seal_proto::policy::{Destination, HttpPath, SecretPolicy};
use seal_proto::ErrorCode;

/// HTTP: method allowed, parsed literal HttpPath inside the destination prefix
/// on a segment boundary, and outside denied prefixes. Query is handled separately.
/// Never decode or reinterpret the path after this check.
impl HttpPolicy {
    /// `PolicyDenied` unless all of:
    /// - the destination is `Https`;
    /// - `method` is in `HttpRules::methods` (exact, case-sensitive), or that set is empty;
    /// - `path` is inside the destination's `path_prefix`;
    /// - `path` is inside none of `HttpRules::deny_path_prefixes`;
    /// - when the policy restricts paths (a destination prefix other than `/`, or a denied
    ///   prefix), `path` has no `;` after the destination prefix.
    ///
    /// "Inside a prefix" compares the bytes on a segment boundary: `/v1` covers `/v1`
    /// and `/v1/chat`, not `/v10`; a destination prefix `/v1/` covers `/v1/chat`, not `/v1`,
    /// while a denied prefix `/v1/keys/` covers `/v1/keys` too. A denied prefix also covers
    /// the path followed by a `.` (`/v1/keys` covers `/v1/keys.json`), since servers with
    /// format suffixes route those to the same handler. The destination prefix matches
    /// exactly; denied prefixes ignore ASCII case, since many servers do. Servers that strip
    /// `;params` from segments (`/v1/keys;x`, `/v1/x/..;/keys`) are why `;` is refused.
    pub fn check(policy: &SecretPolicy, method: &str, path: &HttpPath) -> Result<(), ErrorCode> {
        let Destination::Https { path_prefix, .. } = policy.destination() else {
            return Err(ErrorCode::PolicyDenied);
        };
        let path = path.as_str();
        if !within(path, path_prefix, false) {
            return Err(ErrorCode::PolicyDenied);
        }
        let restricted = path_prefix != "/" || policy.http().is_some_and(|r| !r.deny_path_prefixes.is_empty());
        if restricted && path[path_prefix.len()..].contains(';') {
            return Err(ErrorCode::PolicyDenied);
        }
        if let Some(rules) = policy.http() {
            if !rules.methods.is_empty() && !rules.methods.contains(method) {
                return Err(ErrorCode::PolicyDenied);
            }
            if rules.deny_path_prefixes.iter().any(|deny| denied(path, deny)) {
                return Err(ErrorCode::PolicyDenied);
            }
        }
        Ok(())
    }
}

pub struct HttpPolicy;

/// Denied prefixes err on the side of denying: `/v1/keys/` also covers `/v1/keys`, and
/// `/v1/keys` covers `/v1/keys.json`, which servers with format suffixes (Rails `(.:format)`,
/// Spring's suffix match) route to `/v1/keys`.
fn denied(path: &str, deny: &str) -> bool {
    let trimmed = deny.trim_end_matches('/');
    within(path, deny, true) || (!trimmed.is_empty() && within(path, trimmed, true))
}

/// `path` equals `prefix` or continues it after a `/`; with `fold_case` (denied prefixes),
/// ASCII case is ignored and a `.` after the prefix is a boundary too.
fn within(path: &str, prefix: &str, fold_case: bool) -> bool {
    let rest = match path.get(..prefix.len()) {
        Some(head) if head == prefix || (fold_case && head.eq_ignore_ascii_case(prefix)) => &path[prefix.len()..],
        _ => return false,
    };
    rest.is_empty() || prefix.ends_with('/') || rest.starts_with('/') || (fold_case && rest.starts_with('.'))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use seal_proto::policy::{HttpRules, Injection};
    use seal_proto::AppName;

    use super::*;

    fn policy(to: &str, methods: &[&str], deny: &[&str]) -> SecretPolicy {
        let p = SecretPolicy::new(to, [AppName::new("checkout").unwrap()]).unwrap();
        if methods.is_empty() && deny.is_empty() {
            return p;
        }
        let rules = HttpRules {
            methods: methods.iter().map(|m| m.to_string()).collect::<BTreeSet<_>>(),
            deny_path_prefixes: deny.iter().map(|d| d.to_string()).collect(),
        };
        p.with_http(Injection::default(), rules).unwrap()
    }

    fn check(p: &SecretPolicy, method: &str, path: &str) -> Result<(), ErrorCode> {
        HttpPolicy::check(p, method, &HttpPath::parse(path).unwrap())
    }

    #[test]
    fn root_prefix_allows_everything() {
        let p = policy("https://api.example.com", &[], &[]);
        assert_eq!(check(&p, "GET", "/"), Ok(()));
        assert_eq!(check(&p, "DELETE", "/anything/at/all"), Ok(()));
    }

    #[test]
    fn prefix_on_segment_boundary() {
        let p = policy("https://api.example.com/v1", &[], &[]);
        assert_eq!(check(&p, "GET", "/v1"), Ok(()));
        assert_eq!(check(&p, "GET", "/v1/"), Ok(()));
        assert_eq!(check(&p, "POST", "/v1/chat/completions"), Ok(()));
        assert_eq!(check(&p, "GET", "/v10"), Err(ErrorCode::PolicyDenied));
        assert_eq!(check(&p, "GET", "/v1x/chat"), Err(ErrorCode::PolicyDenied));
        assert_eq!(check(&p, "GET", "/"), Err(ErrorCode::PolicyDenied));
        assert_eq!(check(&p, "GET", "/v2/chat"), Err(ErrorCode::PolicyDenied));
        assert_eq!(check(&p, "GET", "/V1/chat"), Err(ErrorCode::PolicyDenied), "case-sensitive");
    }

    #[test]
    fn trailing_slash_prefix() {
        let p = policy("https://api.example.com/v1/", &[], &[]);
        assert_eq!(check(&p, "GET", "/v1/"), Ok(()));
        assert_eq!(check(&p, "GET", "/v1/models"), Ok(()));
        assert_eq!(check(&p, "GET", "/v1"), Err(ErrorCode::PolicyDenied));
    }

    #[test]
    fn methods() {
        let p = policy("https://api.example.com/v1", &["GET", "POST"], &[]);
        assert_eq!(check(&p, "GET", "/v1/models"), Ok(()));
        assert_eq!(check(&p, "POST", "/v1/chat"), Ok(()));
        assert_eq!(check(&p, "DELETE", "/v1/models"), Err(ErrorCode::PolicyDenied));
        assert_eq!(check(&p, "get", "/v1/models"), Err(ErrorCode::PolicyDenied), "methods are case-sensitive");
    }

    #[test]
    fn denied_prefixes() {
        let p = policy("https://api.example.com/v1", &[], &["/v1/keys", "/v1/admin/"]);
        assert_eq!(check(&p, "GET", "/v1/models"), Ok(()));
        assert_eq!(check(&p, "POST", "/v1/keys"), Err(ErrorCode::PolicyDenied));
        assert_eq!(check(&p, "POST", "/v1/keys/new"), Err(ErrorCode::PolicyDenied));
        assert_eq!(check(&p, "GET", "/v1/keystore"), Ok(()), "segment boundary");
        assert_eq!(check(&p, "GET", "/v1/admin/users"), Err(ErrorCode::PolicyDenied));
        assert_eq!(
            check(&p, "GET", "/v1/admin"),
            Err(ErrorCode::PolicyDenied),
            "a trailing slash still denies the bare path"
        );
        assert_eq!(check(&p, "GET", "/v1/administrator"), Ok(()));
    }

    #[test]
    fn denied_prefixes_ignore_case() {
        let p = policy("https://api.example.com/v1", &[], &["/v1/keys"]);
        assert_eq!(check(&p, "GET", "/v1/KEYS"), Err(ErrorCode::PolicyDenied));
        assert_eq!(check(&p, "GET", "/v1/Keys/1"), Err(ErrorCode::PolicyDenied));
        assert_eq!(check(&p, "GET", "/v1/KEYSTORE"), Ok(()), "segment boundary");
        assert_eq!(check(&p, "GET", "/V1/keys"), Err(ErrorCode::PolicyDenied), "the destination prefix stays exact");
    }

    #[test]
    fn denied_prefixes_cover_format_suffixes() {
        let p = policy("https://api.example.com/v1", &[], &["/v1/keys", "/v1/admin/"]);
        for path in ["/v1/keys.json", "/v1/KEYS.xml", "/v1/keys.", "/v1/keys.json/x", "/v1/admin.json"] {
            assert_eq!(check(&p, "GET", path), Err(ErrorCode::PolicyDenied), "{path}");
        }
        assert_eq!(check(&p, "GET", "/v1/keystore.json"), Ok(()), "still a segment boundary");
        assert_eq!(check(&p, "GET", "/v1/models.json"), Ok(()));
        let dotted = policy("https://api.example.com/v1.0", &[], &[]);
        assert_eq!(check(&dotted, "GET", "/v1.0/models"), Ok(()));
        let exact = policy("https://api.example.com/v1", &[], &[]);
        assert_eq!(
            check(&exact, "GET", "/v1.json"),
            Err(ErrorCode::PolicyDenied),
            "the destination prefix stays exact"
        );
    }

    #[test]
    fn semicolons_refused_when_paths_are_restricted() {
        let deny = policy("https://api.example.com", &[], &["/v1/keys"]);
        let prefix = policy("https://api.example.com/v1", &[], &[]);
        let open = policy("https://api.example.com", &[], &[]);
        for path in ["/v1/keys;x", "/v1/keys;x/new", "/v1/models;x", "/v1/x/..;/keys"] {
            assert_eq!(check(&deny, "GET", path), Err(ErrorCode::PolicyDenied), "{path}");
            assert_eq!(check(&prefix, "GET", path), Err(ErrorCode::PolicyDenied), "{path}");
            assert_eq!(check(&open, "GET", path), Ok(()), "{path}: nothing to bypass");
        }
        let in_prefix = policy("https://api.example.com/v1;v=2", &[], &[]);
        assert_eq!(check(&in_prefix, "GET", "/v1;v=2/models"), Ok(()), "the destination's own `;`");
        assert_eq!(check(&in_prefix, "GET", "/v1;v=2/models;x"), Err(ErrorCode::PolicyDenied));
    }

    #[test]
    fn non_http_destination_denied() {
        let p = SecretPolicy::new("postgres://app@db/orders", [AppName::new("checkout").unwrap()]).unwrap();
        assert_eq!(check(&p, "GET", "/"), Err(ErrorCode::PolicyDenied));
    }

    #[test]
    fn ambiguous_paths_never_reach_the_check() {
        for bad in ["/v1/%6Beys", "/v1/../keys", "/v1//keys", "/v1/./keys", "v1", "/v1?x", "/v1\\keys"] {
            assert!(HttpPath::parse(bad).is_err(), "{bad}");
        }
    }
}

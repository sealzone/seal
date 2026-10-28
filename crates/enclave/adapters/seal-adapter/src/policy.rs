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
    /// - `path` is inside none of `HttpRules::deny_path_prefixes`.
    ///
    /// "Inside a prefix" compares the literal bytes on a segment boundary: `/v1` covers `/v1`
    /// and `/v1/chat`, not `/v10`; a destination prefix `/v1/` covers `/v1/chat`, not `/v1`,
    /// while a denied prefix `/v1/keys/` covers `/v1/keys` too.
    pub fn check(policy: &SecretPolicy, method: &str, path: &HttpPath) -> Result<(), ErrorCode> {
        let Destination::Https { path_prefix, .. } = policy.destination() else {
            return Err(ErrorCode::PolicyDenied);
        };
        let path = path.as_str();
        if !within(path, path_prefix) {
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

/// Denied prefixes err on the side of denying: `/v1/keys/` also covers `/v1/keys`.
fn denied(path: &str, deny: &str) -> bool {
    let trimmed = deny.trim_end_matches('/');
    within(path, deny) || (!trimmed.is_empty() && within(path, trimmed))
}

/// `path` equals `prefix` or continues it after a `/`.
fn within(path: &str, prefix: &str) -> bool {
    match path.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => prefix.ends_with('/') || rest.starts_with('/'),
        None => false,
    }
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

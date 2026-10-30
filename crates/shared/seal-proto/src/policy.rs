//! Blob policy: everything sealed into a blob at `seal()` time.
//!
//! Destination and injection are fixed for the life of a blob. Nothing,
//! including the tenant admin key, can change them without resealing,
//! which requires the plaintext. That is what makes a stolen admin key mean
//! "use", never "extract".

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::session::{ConsumerTier, PlatformTier};
use crate::{AppName, ProtoError, UnixTime};

/// Where a secret may be sent. Parsed from the `to=` URL.
///
/// Every destination is reached over TLS verified against the CA bundle baked
/// into the enclave image. Plain-TCP destinations do not exist in this type.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum Destination {
    /// `https://host[:port][/path-prefix]`. Requests outside the prefix are denied.
    Https { host: String, port: u16, path_prefix: String },
    /// `postgres://user@host[:port]/database`. Always TLS upstream.
    Postgres { host: String, port: u16, user: String, database: String },
    /// `clickhouse://user@host[:port][/database]`, the native protocol over TLS (default port 9440).
    /// ClickHouse over HTTP is an `Https` destination with `header="X-ClickHouse-Key"`.
    ClickHouse { host: String, port: u16, user: String, database: Option<String> },
    /// `rediss://[user@]host[:port][/db]`. `redis://` (plain TCP) is refused.
    Redis { host: String, port: u16, user: Option<String>, db: u8 },
}

impl Destination {
    pub fn parse(to: &str) -> Result<Self, ProtoError> {
        let u = url::Url::parse(to).map_err(|e| ProtoError::invalid("to", e.to_string()))?;
        let host = u
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| ProtoError::invalid("to", "missing host"))?
            .to_ascii_lowercase();
        if u.password().is_some() {
            return Err(ProtoError::invalid("to", "never put a password in `to`; pass it as the secret"));
        }
        if u.query().is_some() || u.fragment().is_some() {
            return Err(ProtoError::invalid("to", "query strings and fragments are not allowed"));
        }
        let user = (!u.username().is_empty()).then(|| u.username().to_string());
        if let Some(user) = &user {
            literal_name("user", user)?;
        }
        let path = u.path().trim_start_matches('/').to_string();
        if !path.is_empty() {
            literal_name("database", &path.replace('/', ""))?;
        }
        let need_user = |p: &str| {
            user.clone().ok_or_else(|| ProtoError::invalid("to", format!("{p} needs a user: {p}://user@host")))
        };
        match u.scheme() {
            "https" => {
                if user.is_some() {
                    return Err(ProtoError::invalid("to", "https destinations take no user"));
                }
                let prefix = if u.path().is_empty() { "/".to_string() } else { u.path().to_string() };
                Ok(Destination::Https { host, port: u.port().unwrap_or(443), path_prefix: prefix })
            }
            "postgres" | "postgresql" => {
                if path.is_empty() || path.contains('/') {
                    return Err(ProtoError::invalid("to", "postgres needs exactly one database: postgres://user@host/db"));
                }
                Ok(Destination::Postgres { host, port: u.port().unwrap_or(5432), user: need_user("postgres")?, database: path })
            }
            "clickhouse" => Ok(Destination::ClickHouse {
                host,
                port: u.port().unwrap_or(9440),
                user: need_user("clickhouse")?,
                database: (!path.is_empty()).then_some(path),
            }),
            "rediss" => {
                let db = if path.is_empty() {
                    0
                } else {
                    path.parse().map_err(|_| ProtoError::invalid("to", "redis db must be a number"))?
                };
                Ok(Destination::Redis { host, port: u.port().unwrap_or(6379), user, db })
            }
            "http" | "redis" | "postgres+plain" => Err(ProtoError::invalid(
                "to",
                "plain-TCP destinations are refused: the path to them runs through an untrusted host. Use https, rediss, postgres (TLS) or clickhouse (TLS)",
            )),
            other => Err(ProtoError::Unsupported(format!(
                "destination scheme `{other}` (supported: https, postgres, clickhouse, rediss; others need the Custom plan)"
            ))),
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            Destination::Https { .. } => Protocol::Http,
            Destination::Postgres { .. } => Protocol::Postgres,
            Destination::ClickHouse { .. } => Protocol::ClickHouse,
            Destination::Redis { .. } => Protocol::Redis,
        }
    }

    pub fn host(&self) -> &str {
        match self {
            Destination::Https { host, .. }
            | Destination::Postgres { host, .. }
            | Destination::ClickHouse { host, .. }
            | Destination::Redis { host, .. } => host,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Destination::Https { port, .. }
            | Destination::Postgres { port, .. }
            | Destination::ClickHouse { port, .. }
            | Destination::Redis { port, .. } => *port,
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Destination::Https { host, port, path_prefix } => write!(f, "https://{host}:{port}{path_prefix}"),
            Destination::Postgres { host, port, user, database } => {
                write!(f, "postgres://{user}@{host}:{port}/{database}")
            }
            Destination::ClickHouse { host, port, user, database } => {
                write!(f, "clickhouse://{user}@{host}:{port}")?;
                if let Some(d) = database {
                    write!(f, "/{d}")?;
                }
                Ok(())
            }
            Destination::Redis { host, port, user, db } => {
                write!(f, "rediss://")?;
                if let Some(u) = user {
                    write!(f, "{u}@")?;
                }
                write!(f, "{host}:{port}/{db}")
            }
        }
    }
}

/// User and database names travel into upstream handshakes as written, so they must be
/// unambiguous: visible ASCII, no percent-encoding (the URL keeps `%40` encoded, and the
/// adapter would forward it literally), at most 63 bytes. This also refuses names that start
/// with a space, which ClickHouse reserves for login markers.
fn literal_name(field: &'static str, name: &str) -> Result<(), ProtoError> {
    let ok = (1..=63).contains(&name.len()) && name.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b'%');
    if ok {
        Ok(())
    } else {
        Err(ProtoError::invalid(field, "1-63 visible ASCII characters, no percent-encoding"))
    }
}

/// The wire protocol an adapter speaks. One adapter per protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http,
    Postgres,
    ClickHouse,
    Redis,
}

/// Where the secret goes in an HTTP request. Headers only; body or query
/// placement needs a custom image (Custom plan).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Injection {
    /// Header name, lowercase. Default `authorization`.
    pub header: String,
    /// Header value template containing exactly one `{key}`. Default `Bearer {key}`.
    pub format: String,
}

impl Default for Injection {
    fn default() -> Self {
        Injection { header: "authorization".into(), format: "Bearer {key}".into() }
    }
}

impl Injection {
    pub fn new(header: &str, format: Option<&str>) -> Result<Self, ProtoError> {
        let header = header.trim().to_ascii_lowercase();
        let valid_token =
            !header.is_empty() && header.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        if !valid_token {
            return Err(ProtoError::invalid("header", "not a valid HTTP header name"));
        }
        const FORBIDDEN: &[&str] =
            &["host", "content-length", "transfer-encoding", "connection", "cookie", "te", "upgrade"];
        if FORBIDDEN.contains(&header.as_str()) {
            return Err(ProtoError::invalid("header", format!("`{header}` cannot carry a secret")));
        }
        let format = match format {
            Some(f) => f.to_string(),
            None if header == "authorization" => "Bearer {key}".into(),
            None => "{key}".into(),
        };
        if format.matches("{key}").count() != 1 || !format.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(ProtoError::invalid(
                "format",
                "must contain `{key}` exactly once and visible ASCII/spaces only",
            ));
        }
        Ok(Injection { header, format })
    }

    /// The header value with the secret in place. Zeroized on drop.
    pub fn render(&self, secret: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
        let (before, after) = self.format.split_once("{key}").expect("validated: exactly one {key}");
        let mut out = zeroize::Zeroizing::new(Vec::with_capacity(before.len() + secret.len() + after.len()));
        out.extend_from_slice(before.as_bytes());
        out.extend_from_slice(secret);
        out.extend_from_slice(after.as_bytes());
        out
    }
}

/// SHA-256 of an upstream certificate's SubjectPublicKeyInfo DER. Text form
/// `sha256/<base64>`, as `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SpkiPin(#[serde(with = "crate::codec::array_b64")] pub [u8; 32]);

impl std::str::FromStr for SpkiPin {
    type Err = ProtoError;
    /// `sha256/<base64>`, standard alphabet with padding (the HPKP and `curl --pinnedpubkey` form).
    fn from_str(s: &str) -> Result<Self, ProtoError> {
        use base64::Engine;
        let b64 = s.strip_prefix("sha256/").ok_or_else(|| ProtoError::invalid("pin", "expected sha256/<base64>"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| ProtoError::invalid("pin", "not base64"))?;
        let digest = bytes.try_into().map_err(|_| ProtoError::invalid("pin", "a SHA-256 digest is 32 bytes"))?;
        Ok(SpkiPin(digest))
    }
}

impl fmt::Display for SpkiPin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use base64::Engine;
        write!(f, "sha256/{}", base64::engine::general_purpose::STANDARD.encode(self.0))
    }
}

/// Pins per policy: room for the current key and the next ones during a rotation, and a
/// bound on blob size (the first pin adds about 54 characters to the blob text, each further one about 45).
pub const MAX_PINS: usize = 4;

/// The shortest secret Seal seals. Adapters mask every echo of the secret in what they relay
/// back (`seal_adapter::scrub`), so a consumer who can make the upstream return chosen text
/// learns whether that text contains the secret: one response listing every string of a short
/// secret's length finds it, and a short secret also turns up in ordinary data, which masking
/// then corrupts. Sixteen bytes put a random secret out of reach of that search; a guessable
/// secret of any length is not protected by it.
pub const MIN_SECRET_BYTES: usize = 16;

/// Everything a blob's holder is allowed to do. Sealed into the blob; its
/// digest is part of the blob AEAD's associated data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PolicyWire", into = "PolicyWire")]
pub struct SecretPolicy {
    destination: Destination,
    /// Apps whose workloads may start sessions with the blob. Never empty: there is no default.
    apps: BTreeSet<AppName>,
    /// Hard end date, enforced by the enclave on every copy of the blob. `None` = no end date.
    expires_at: Option<UnixTime>,
    /// HTTP only. `None` for non-HTTP destinations.
    injection: Option<Injection>,
    /// HTTP only: extra request rules on top of the destination's path prefix.
    http: Option<HttpRules>,
    /// Upstream key pins. Empty = the baked roots alone decide. Otherwise the upstream's
    /// chain must also verify against the baked roots AND contain a certificate (leaf,
    /// intermediate or root) whose key is pinned. Pin a CA key to survive leaf renewals.
    /// Guards against a misissued certificate for the destination host.
    pins: BTreeSet<SpkiPin>,
    /// Weakest platform the blob may be opened on. `None` = every platform the tenant enables.
    /// The enclave adds DEK wraps only for the tenant's platforms at or above it, so enabling a
    /// weaker platform later never exposes this blob there.
    min_platform: Option<PlatformTier>,
    /// Weakest consumer tier the blob may be used at. `None` = Base. `Hardened` means the
    /// session must stay inside the SDK's channel and the endpoint must present verified
    /// integrity evidence at every start and extend, so the blob stops working within one
    /// extend of the endpoint's attestation going silent.
    min_tier: Option<ConsumerTier>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRules {
    /// Allowed methods, uppercase. Empty = any.
    pub methods: BTreeSet<String>,
    /// Paths denied even inside the prefix (e.g. key-management endpoints).
    pub deny_path_prefixes: BTreeSet<String>,
}

impl SecretPolicy {
    /// One policy shared by the SDK, blob and adapters. Defaults to Bearer injection for HTTP.
    pub fn new(to: &str, apps: impl IntoIterator<Item = AppName>) -> Result<Self, ProtoError> {
        let destination = Destination::parse(to)?;
        let injection = matches!(destination, Destination::Https { .. }).then(Injection::default);
        let policy = Self {
            destination,
            apps: apps.into_iter().collect(),
            expires_at: None,
            injection,
            http: None,
            pins: BTreeSet::new(),
            min_platform: None,
            min_tier: None,
        };
        policy.validate()?;
        Ok(policy)
    }
    pub fn with_expiry(mut self, expires_at: UnixTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
    pub fn with_http(mut self, injection: Injection, rules: HttpRules) -> Result<Self, ProtoError> {
        self.injection = Some(injection);
        self.http = Some(rules);
        self.validate()?;
        Ok(self)
    }
    pub fn with_min_platform(mut self, tier: PlatformTier) -> Self {
        self.min_platform = Some(tier);
        self
    }
    /// `--hardened-only`: the blob may only be used by sessions at or above `tier`.
    pub fn with_min_tier(mut self, tier: ConsumerTier) -> Self {
        self.min_tier = Some(tier);
        self
    }
    pub fn with_pins(mut self, pins: impl IntoIterator<Item = SpkiPin>) -> Result<Self, ProtoError> {
        self.pins = pins.into_iter().collect();
        self.validate()?;
        Ok(self)
    }
    pub fn destination(&self) -> &Destination {
        &self.destination
    }
    pub fn apps(&self) -> &BTreeSet<AppName> {
        &self.apps
    }
    pub fn expires_at(&self) -> Option<UnixTime> {
        self.expires_at
    }
    pub fn injection(&self) -> Option<&Injection> {
        self.injection.as_ref()
    }
    pub fn http(&self) -> Option<&HttpRules> {
        self.http.as_ref()
    }
    pub fn pins(&self) -> &BTreeSet<SpkiPin> {
        &self.pins
    }
    pub fn min_platform(&self) -> Option<PlatformTier> {
        self.min_platform
    }
    pub fn min_tier(&self) -> Option<ConsumerTier> {
        self.min_tier
    }

    /// Checks the secret can travel where the policy sends it, at seal time,
    /// so a bad secret fails loudly once instead of on every request.
    /// At least `MIN_SECRET_BYTES`, for every destination.
    /// HTTP header: visible ASCII and spaces only, at most 8192 bytes.
    /// Database passwords: at most 1024 bytes, no NUL.
    pub fn validate_secret(&self, secret: &[u8]) -> Result<(), ProtoError> {
        if secret.len() < MIN_SECRET_BYTES {
            return Err(ProtoError::invalid(
                "secret",
                format!("shorter than {MIN_SECRET_BYTES} bytes: responses masking it could reveal it"),
            ));
        }
        let printable = |max: usize| secret.len() <= max && secret.iter().all(|b| (0x20..0x7f).contains(b));
        let ok = match self.destination {
            Destination::Https { .. } => printable(8192),
            // SCRAM normalizes the password (SASLprep) on every upstream login: printable ASCII
            // takes one path whatever the characters, anything else branches per character in
            // ways a host watching the enclave could follow, as often as an app opens connections.
            Destination::Postgres { .. } => printable(1024),
            _ => secret.len() <= 1024 && !secret.contains(&0),
        };
        if ok {
            Ok(())
        } else {
            Err(ProtoError::invalid("secret", "not valid for this destination's credential slot"))
        }
    }

    /// Validates the invariants every component relies on.
    pub fn validate(&self) -> Result<(), ProtoError> {
        // Deserialization must validate nested objects too, not just constructors.
        if Destination::parse(&self.destination.to_string())? != self.destination {
            return Err(ProtoError::invalid("destination", "must be normalized"));
        }
        if let Some(injection) = &self.injection {
            if Injection::new(&injection.header, Some(&injection.format))? != *injection {
                return Err(ProtoError::invalid("injection", "must be normalized"));
            }
        }

        if let Destination::Https { path_prefix, .. } = &self.destination {
            HttpPath::parse(path_prefix)?;
        }
        if let Some(rules) = &self.http {
            rules.validate()?;
        }
        if self.pins.len() > MAX_PINS {
            return Err(ProtoError::invalid("pins", format!("at most {MAX_PINS}")));
        }
        if self.apps.is_empty() {
            return Err(ProtoError::invalid(
                "apps",
                "name at least one app; a blob never works for an app you did not name",
            ));
        }
        match (&self.destination, &self.injection) {
            (Destination::Https { .. }, None) => {
                Err(ProtoError::invalid("injection", "https destinations need an injection"))
            }
            (Destination::Https { .. }, Some(_)) => Ok(()),
            (_, Some(_)) => Err(ProtoError::invalid("header", "header placement applies to https destinations only")),
            (_, None) if self.http.is_some() => {
                Err(ProtoError::invalid("http", "http rules apply to https destinations only"))
            }
            (_, None) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_destinations() {
        assert_eq!(
            Destination::parse("https://api.openai.com").unwrap(),
            Destination::Https { host: "api.openai.com".into(), port: 443, path_prefix: "/".into() }
        );
        assert_eq!(
            Destination::parse("postgres://app@orders-db:5432/orders").unwrap(),
            Destination::Postgres {
                host: "orders-db".into(),
                port: 5432,
                user: "app".into(),
                database: "orders".into()
            }
        );
        assert!(matches!(
            Destination::parse("clickhouse://app@ch/events").unwrap(),
            Destination::ClickHouse { port: 9440, .. }
        ));
        assert!(matches!(
            Destination::parse("rediss://cache:6380").unwrap(),
            Destination::Redis { db: 0, user: None, .. }
        ));
        assert!(Destination::parse("redis://cache").is_err());
        assert!(Destination::parse("http://x").is_err());
        assert!(Destination::parse("postgres+plain://app@db/x").is_err());
        assert!(Destination::parse("postgres://app:pw@db/x").is_err());
        assert!(Destination::parse("postgres://db/x").is_err());
        assert!(Destination::parse("postgres://a%40b@db/x").is_err(), "percent-encoded user");
        assert!(Destination::parse("clickhouse://%20INTERSERVER@ch/x").is_err(), "login marker");
        assert!(Destination::parse("postgres://app@db/or%2Fders").is_err(), "percent-encoded database");
    }

    #[test]
    fn secrets_have_a_floor_and_fit_their_slot() {
        let checkout = || [crate::AppName::new("checkout").unwrap()];
        let http = SecretPolicy::new("https://api.example.com", checkout()).unwrap();
        let pg = SecretPolicy::new("postgres://app@db/orders", checkout()).unwrap();
        let floor = vec![b'k'; MIN_SECRET_BYTES];
        for policy in [&http, &pg] {
            assert!(policy.validate_secret(&floor).is_ok());
            assert!(policy.validate_secret(&floor[1..]).is_err(), "one byte short");
            assert!(policy.validate_secret(b"").is_err());
        }
        assert!(http.validate_secret(&[b'k'; 8193]).is_err());
        assert!(http.validate_secret(b"sk-live-0123456\n").is_err(), "not a header value");
        assert!(pg.validate_secret(&[b'k'; 1025]).is_err());
        assert!(pg.validate_secret(b"pg-password-0123\0").is_err());
        assert!(pg.validate_secret("pg-pässword-0123".as_bytes()).is_err(), "non-ASCII: SASLprep branches on it");
        assert!(pg.validate_secret(b"pg-password\t0123").is_err(), "control characters too");
        assert!(pg.validate_secret(b"pg password ~!@#$%^&*()").is_ok());
    }

    #[test]
    fn injection_rules() {
        assert_eq!(&**Injection::new("X-Api-Key", None).unwrap().render(b"k"), b"k");
        assert_eq!(&**Injection::new("Authorization", Some("Token {key}")).unwrap().render(b"k"), b"Token k");
        assert!(Injection::new("Host", None).is_err());
        assert!(Injection::new("x", Some("no placeholder")).is_err());
    }
}

// Preserve the existing wire shape while making every decode validate invariants.
#[derive(Serialize, Deserialize)]
struct PolicyWire {
    destination: Destination,
    apps: BTreeSet<AppName>,
    expires_at: Option<UnixTime>,
    injection: Option<Injection>,
    http: Option<HttpRules>,
    /// Omitted when empty, so unpinned blobs do not grow.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pins: BTreeSet<SpkiPin>,
    /// Omitted when unset, like `pins`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min_platform: Option<PlatformTier>,
    /// Omitted when unset, like `pins`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min_tier: Option<ConsumerTier>,
}
impl TryFrom<PolicyWire> for SecretPolicy {
    type Error = ProtoError;
    fn try_from(w: PolicyWire) -> Result<Self, Self::Error> {
        let policy = Self {
            destination: w.destination,
            apps: w.apps,
            expires_at: w.expires_at,
            injection: w.injection,
            http: w.http,
            pins: w.pins,
            min_platform: w.min_platform,
            min_tier: w.min_tier,
        };
        policy.validate()?;
        Ok(policy)
    }
}
impl From<SecretPolicy> for PolicyWire {
    fn from(p: SecretPolicy) -> Self {
        Self {
            destination: p.destination,
            apps: p.apps,
            expires_at: p.expires_at,
            injection: p.injection,
            http: p.http,
            pins: p.pins,
            min_platform: p.min_platform,
            min_tier: p.min_tier,
        }
    }
}

/// Literal ASCII path contract for v1. Reject ambiguous encodings instead of
/// allowing policy and adapters to interpret them differently. Parse the URL path
/// separately from its query; adapters must not forward paths rejected here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpPath(String);
impl HttpPath {
    pub fn parse(path: &str) -> Result<Self, ProtoError> {
        if !path.starts_with('/')
            || path.contains(['%', '?', '#', '\\'])
            || !path.bytes().all(|b| (0x21..0x7f).contains(&b))
            || path.split('/').any(|s| s == "." || s == "..")
            || path.contains("//")
        {
            return Err(ProtoError::invalid("path", "expected an unambiguous absolute ASCII path"));
        }
        Ok(Self(path.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl HttpRules {
    pub fn validate(&self) -> Result<(), ProtoError> {
        for method in &self.methods {
            if method.is_empty()
                || !method
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b))
            {
                return Err(ProtoError::invalid("method", "expected an uppercase HTTP method token"));
            }
        }
        for path in &self.deny_path_prefixes {
            HttpPath::parse(path)?;
        }
        Ok(())
    }
}

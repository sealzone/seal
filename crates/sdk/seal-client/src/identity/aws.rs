//! AWS workload identity (feature `aws`): a presigned STS `GetCallerIdentity` request whose
//! signed headers include `X-Seal-Binding: hex(labeled_digest(PROOF_CONTEXT_LABEL, ctx))`.
//! The enclave replays it to STS, so only a holder of the role's credentials can make one,
//! and only for this context. Credentials come from the default AWS chain (environment, web
//! identity, container, instance role); the query-string SigV4 is computed here on
//! `aws_sigv4`'s key derivation and signature, so no SDK client is involved.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use seal_proto::identity::{IdentityProof, ProofContext, PROOF_CONTEXT_LABEL};
use seal_proto::Bearer;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Env, IdentityProvider};
use crate::{BoxFuture, ClientError};

const STS_HOST: &str = "sts.amazonaws.com";
const STS_REGION: &str = "us-east-1";
/// The enclave accepts at most 900.
const PRESIGN_EXPIRES_SECS: u64 = 60;
/// Environment variables that mean the default chain has something to find.
const HINTS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_PROFILE",
];

/// Resolved credentials. The secret zeroizes on drop.
pub(crate) struct Creds {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

type CredsFn = Arc<dyn Fn() -> BoxFuture<'static, Result<Creds, ClientError>> + Send + Sync>;

/// An IAM role, proven by a presigned STS `GetCallerIdentity`.
pub struct AwsIdentity {
    credentials: CredsFn,
    clock: fn() -> SystemTime,
}

impl AwsIdentity {
    /// The default AWS credential chain, resolved again for every proof (it caches).
    pub async fn from_env() -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let chain = config.credentials_provider();
        let credentials: CredsFn = Arc::new(move || {
            let chain = chain.clone();
            Box::pin(async move {
                let chain = chain.ok_or_else(|| ClientError::NoIdentity("aws: no credentials provider".into()))?;
                let c = chain
                    .as_ref()
                    .provide_credentials()
                    .await
                    .map_err(|e| ClientError::NoIdentity(format!("aws: {e}")))?;
                Ok(Creds {
                    access_key_id: c.access_key_id().to_string(),
                    secret_access_key: Zeroizing::new(c.secret_access_key().to_string()),
                    session_token: c.session_token().map(|t| Zeroizing::new(t.to_string())),
                })
            })
        });
        Self { credentials, clock: SystemTime::now }
    }

    /// With a hint in the environment, the chain; otherwise the chain only if it resolves
    /// within a short wait (an instance or container role).
    pub(crate) async fn detect(env: &dyn Env) -> Option<Self> {
        let hinted = HINTS.iter().any(|h| env.var(h).is_some());
        if !hinted && !env.probes_network() {
            return None;
        }
        let aws = Self::from_env().await;
        if hinted {
            return Some(aws);
        }
        match tokio::time::timeout(Duration::from_secs(2), (aws.credentials)()).await {
            Ok(Ok(_)) => Some(aws),
            _ => None,
        }
    }
}

#[async_trait]
impl IdentityProvider for AwsIdentity {
    fn kind(&self) -> &'static str {
        "aws-role"
    }
    async fn prove(&self, ctx: &ProofContext) -> Result<IdentityProof, ClientError> {
        let creds = (self.credentials)().await?;
        let binding = hex::encode(seal_proto::codec::labeled_digest(PROOF_CONTEXT_LABEL, ctx));
        Ok(get_caller_identity(&creds, &binding, (self.clock)()))
    }
}

/// The presigned `GET https://sts.amazonaws.com/?Action=GetCallerIdentity&…` proof.
fn get_caller_identity(creds: &Creds, binding_hex: &str, time: SystemTime) -> IdentityProof {
    let request = Presign {
        host: STS_HOST,
        path: "/",
        region: STS_REGION,
        service: "sts",
        params: vec![("Action", "GetCallerIdentity".into()), ("Version", "2011-06-15".into())],
        headers: vec![("x-seal-binding", binding_hex.to_string())],
        payload_hash: &hex::encode(Sha256::digest(b"")),
        expires_secs: PRESIGN_EXPIRES_SECS,
        time,
    };
    let query = request.signed_query(creds);
    IdentityProof::AwsSigV4 {
        method: "GET".into(),
        url: format!("https://{STS_HOST}/?{query}"),
        headers: vec![
            ("host".into(), Bearer::new(STS_HOST.into())),
            ("x-seal-binding".into(), Bearer::new(binding_hex.to_string())),
        ],
        body: String::new(),
    }
}

/// A GET to presign with SigV4 in the query string. `host` is always signed.
struct Presign<'a> {
    host: &'a str,
    path: &'a str,
    region: &'a str,
    service: &'a str,
    params: Vec<(&'static str, String)>,
    /// Lowercase names besides `host`, all signed.
    headers: Vec<(&'static str, String)>,
    payload_hash: &'a str,
    expires_secs: u64,
    time: SystemTime,
}

impl Presign<'_> {
    /// The canonical query string followed by `&X-Amz-Signature=…`.
    fn signed_query(&self, creds: &Creds) -> String {
        let (date_time, date) = amz_date(self.time);
        let scope = format!("{date}/{}/{}/aws4_request", self.region, self.service);
        let mut headers: Vec<(&str, &str)> = vec![("host", self.host)];
        headers.extend(self.headers.iter().map(|(n, v)| (*n, v.as_str())));
        headers.sort();
        let signed_headers = headers.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(";");

        let mut params: Vec<(String, String)> = self.params.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        params.push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
        params.push(("X-Amz-Credential".into(), format!("{}/{scope}", creds.access_key_id)));
        params.push(("X-Amz-Date".into(), date_time.clone()));
        params.push(("X-Amz-Expires".into(), self.expires_secs.to_string()));
        params.push(("X-Amz-SignedHeaders".into(), signed_headers.clone()));
        if let Some(token) = &creds.session_token {
            params.push(("X-Amz-Security-Token".into(), token.to_string()));
        }
        let mut encoded: Vec<(String, String)> = params.iter().map(|(k, v)| (uri_encode(k), uri_encode(v))).collect();
        encoded.sort();
        let query = encoded.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");

        let canonical_headers: String = headers.iter().map(|(n, v)| format!("{n}:{}\n", v.trim())).collect();
        let canonical_request =
            format!("GET\n{}\n{query}\n{canonical_headers}\n{signed_headers}\n{}", self.path, self.payload_hash);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{date_time}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let key =
            aws_sigv4::sign::v4::generate_signing_key(&creds.secret_access_key, self.time, self.region, self.service);
        let signature = aws_sigv4::sign::v4::calculate_signature(key, string_to_sign.as_bytes());
        format!("{query}&X-Amz-Signature={signature}")
    }
}

/// SigV4 URI encoding: everything but `A-Za-z0-9-_.~` as `%XX`.
fn uri_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `(YYYYMMDD'T'HHMMSS'Z', YYYYMMDD)` in UTC.
fn amz_date(time: SystemTime) -> (String, String) {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Days since 1970-01-01 to a civil date (H. Hinnant's algorithm), for non-negative days.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    let date = format!("{year:04}{month:02}{day:02}");
    (format!("{date}T{:02}{:02}{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60), date)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_creds(token: Option<&str>) -> Creds {
        Creds {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: Zeroizing::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
            session_token: token.map(|t| Zeroizing::new(t.into())),
        }
    }

    #[test]
    fn dates() {
        assert_eq!(amz_date(UNIX_EPOCH), ("19700101T000000Z".into(), "19700101".into()));
        let t = UNIX_EPOCH + Duration::from_secs(1_369_353_600);
        assert_eq!(amz_date(t), ("20130524T000000Z".into(), "20130524".into()));
        let t = UNIX_EPOCH + Duration::from_secs(1_709_210_096);
        assert_eq!(amz_date(t).0, "20240229T123456Z");
    }

    /// AWS's published query-string example ("Authenticating Requests: Using Query
    /// Parameters", Signature Version 4): presigned GET of `examplebucket/test.txt`.
    #[test]
    fn aws_presigned_url_example() {
        let request = Presign {
            host: "examplebucket.s3.amazonaws.com",
            path: "/test.txt",
            region: "us-east-1",
            service: "s3",
            params: vec![],
            headers: vec![],
            payload_hash: "UNSIGNED-PAYLOAD",
            expires_secs: 86_400,
            time: UNIX_EPOCH + Duration::from_secs(1_369_353_600),
        };
        assert_eq!(
            request.signed_query(&example_creds(None)),
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
             &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
    }

    #[tokio::test]
    async fn proof_has_the_shape_the_enclave_accepts() {
        let aws = AwsIdentity {
            credentials: Arc::new(|| Box::pin(async { Ok(example_creds(Some("FQoG/token+x="))) })),
            clock: || UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        };
        let ctx = crate::identity::tests::ctx(crate::identity::tests::acme());
        let IdentityProof::AwsSigV4 { method, url, headers, body } = aws.prove(&ctx).await.unwrap() else { panic!() };
        assert_eq!((method.as_str(), body.as_str()), ("GET", ""));
        // The enclave replays exactly this URL, so it must be in canonical form.
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.as_str(), url);
        assert_eq!((parsed.host_str(), parsed.path()), (Some(STS_HOST), "/"));
        let q: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
        let get = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("Action"), Some("GetCallerIdentity"));
        assert_eq!(get("Version"), Some("2011-06-15"));
        assert_eq!(get("X-Amz-SignedHeaders"), Some("host;x-seal-binding"));
        assert_eq!(get("X-Amz-Expires"), Some("60"));
        assert_eq!(get("X-Amz-Security-Token"), Some("FQoG/token+x="));
        assert_eq!(get("X-Amz-Credential"), Some("AKIAIOSFODNN7EXAMPLE/20270115/us-east-1/sts/aws4_request"));
        assert_eq!(get("X-Amz-Signature").map(str::len), Some(64));
        let binding = hex::encode(seal_proto::codec::labeled_digest(PROOF_CONTEXT_LABEL, &ctx));
        let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.expose())).collect();
        assert_eq!(headers, [("host", STS_HOST), ("x-seal-binding", binding.as_str())]);
    }
}

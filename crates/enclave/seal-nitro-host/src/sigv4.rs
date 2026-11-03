//! The deployment proof: an STS `GetCallerIdentity` presigned (SigV4 in the query string) with
//! the instance role's credentials, as `seal_authz` checks and replays it. It signs `host` and
//! `x-seal-binding`, which is hex(`DeploymentBinding { nonce }.digest()`) for the nonce the
//! enclave sent: the binding seal-client's request proofs carry for their context, so a proof
//! answers one enclave request and nothing else. The query is built in
//! SigV4's canonical form, which is also the URL's canonical form, so the enclave replays
//! exactly the URL signed. Key derivation and the signature are `aws_sigv4`'s, as in
//! seal-client's `AwsIdentity`, whose canonical request this repeats.

use std::time::{SystemTime, UNIX_EPOCH};

use seal_proto::identity::{DeploymentBinding, IdentityProof};
use seal_proto::Bearer;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Valid this long after signing. The enclave replays it at once; it accepts at most 900.
pub const EXPIRES_SECS: u64 = 60;

/// Role credentials. The secret and the token zeroize on drop.
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

/// Which STS endpoint the proof names: the global one (signed for `us-east-1`), or a region's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sts {
    pub host: String,
    pub region: String,
}

impl Sts {
    pub fn global() -> Self {
        Self { host: "sts.amazonaws.com".into(), region: "us-east-1".into() }
    }

    /// `sts.<region>.amazonaws.com` (`.com.cn` in China), for a region such as `eu-central-1`.
    pub fn regional(region: &str) -> Result<Self, String> {
        let parts: Vec<&str> = region.split('-').collect();
        let valid = parts.len() >= 3
            && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
            && parts.last().is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()));
        if !valid {
            return Err(format!("{region:?} is not an AWS region"));
        }
        let suffix = if region.starts_with("cn-") { "amazonaws.com.cn" } else { "amazonaws.com" };
        Ok(Self { host: format!("sts.{region}.{suffix}"), region: region.into() })
    }
}

/// The presigned `GET https://<sts host>/?Action=GetCallerIdentity&…` bound to `nonce`, signed
/// at `time`.
pub fn get_caller_identity(creds: &Credentials, sts: &Sts, nonce: [u8; 32], time: SystemTime) -> IdentityProof {
    let binding = hex::encode(DeploymentBinding { nonce }.digest());
    let query = signed_query_for(
        creds,
        &sts.host,
        "/",
        &sts.region,
        "sts",
        &[("Action", "GetCallerIdentity"), ("Version", "2011-06-15")],
        &[("x-seal-binding", &binding)],
        time,
        EXPIRES_SECS,
        &hex::encode(Sha256::digest(b"")),
    );
    IdentityProof::AwsSigV4 {
        method: "GET".into(),
        url: format!("https://{}/?{query}", sts.host),
        headers: vec![("host".into(), Bearer::new(sts.host.clone())), ("x-seal-binding".into(), Bearer::new(binding))],
        body: String::new(),
    }
}

/// The canonical query string of a GET to `host` + `path` signing `host` and `headers`,
/// followed by `&X-Amz-Signature=…`.
#[allow(clippy::too_many_arguments)]
fn signed_query_for(
    creds: &Credentials,
    host: &str,
    path: &str,
    region: &str,
    service: &str,
    params: &[(&str, &str)],
    headers: &[(&str, &str)],
    time: SystemTime,
    expires_secs: u64,
    payload_hash: &str,
) -> String {
    let (date_time, date) = amz_date(time);
    let scope = format!("{date}/{region}/{service}/aws4_request");
    // `host` and `headers` (lowercase names), all signed, sorted by name.
    let mut signed: Vec<(&str, &str)> = vec![("host", host)];
    signed.extend_from_slice(headers);
    signed.sort();
    let signed_headers = signed.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(";");
    let canonical_headers: String = signed.iter().map(|(n, v)| format!("{n}:{}\n", v.trim())).collect();
    let mut all: Vec<(String, String)> = params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    all.push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
    all.push(("X-Amz-Credential".into(), format!("{}/{scope}", creds.access_key_id)));
    all.push(("X-Amz-Date".into(), date_time.clone()));
    all.push(("X-Amz-Expires".into(), expires_secs.to_string()));
    all.push(("X-Amz-SignedHeaders".into(), signed_headers.clone()));
    if let Some(token) = &creds.session_token {
        all.push(("X-Amz-Security-Token".into(), token.to_string()));
    }
    let mut encoded: Vec<(String, String)> = all.iter().map(|(k, v)| (uri_encode(k), uri_encode(v))).collect();
    encoded.sort();
    let query = encoded.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");

    let canonical_request = format!("GET\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{date_time}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let key = aws_sigv4::sign::v4::generate_signing_key(&creds.secret_access_key, time, region, service);
    let signature = aws_sigv4::sign::v4::calculate_signature(key, string_to_sign.as_bytes());
    format!("{query}&X-Amz-Signature={signature}")
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
    use std::time::Duration;

    use super::*;

    pub(crate) fn example_creds(token: Option<&str>) -> Credentials {
        Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: Zeroizing::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
            session_token: token.map(|t| Zeroizing::new(t.into())),
        }
    }

    #[test]
    fn dates() {
        assert_eq!(amz_date(UNIX_EPOCH), ("19700101T000000Z".into(), "19700101".into()));
        let t = UNIX_EPOCH + Duration::from_secs(1_709_210_096);
        assert_eq!(amz_date(t).0, "20240229T123456Z");
    }

    /// AWS's published query-string example ("Authenticating Requests: Using Query
    /// Parameters", Signature Version 4): presigned GET of `examplebucket/test.txt`.
    #[test]
    fn aws_presigned_url_example() {
        let query = signed_query_for(
            &example_creds(None),
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            "us-east-1",
            "s3",
            &[],
            &[],
            UNIX_EPOCH + Duration::from_secs(1_369_353_600),
            86_400,
            "UNSIGNED-PAYLOAD",
        );
        assert_eq!(
            query,
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
             &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
    }

    #[test]
    fn regions() {
        assert_eq!(Sts::regional("eu-central-1").unwrap().host, "sts.eu-central-1.amazonaws.com");
        assert_eq!(Sts::regional("us-gov-west-1").unwrap().host, "sts.us-gov-west-1.amazonaws.com");
        assert_eq!(Sts::regional("cn-north-1").unwrap().host, "sts.cn-north-1.amazonaws.com.cn");
        for bad in ["", "us", "us-east", "US-EAST-1", "us-east-x", "us-east-1.evil.com", "us--1"] {
            assert!(Sts::regional(bad).is_err(), "{bad}");
        }
    }

    /// The shape `seal_authz` accepts for a deployment proof (its module docs): canonical URL,
    /// an STS host, only known parameters, presigned once for STS, `host` and the binding signed,
    /// at most 900 s.
    #[test]
    fn proofs_have_the_shape_the_enclave_accepts() {
        let time = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        for sts in [Sts::global(), Sts::regional("eu-west-2").unwrap()] {
            let proof = get_caller_identity(&example_creds(Some("FQoG/token+x==")), &sts, [9; 32], time);
            let IdentityProof::AwsSigV4 { method, url, headers, body } = proof else { panic!("not SigV4") };
            assert_eq!((method.as_str(), body.as_str()), ("GET", ""));
            let parsed = url::Url::parse(&url).unwrap();
            assert_eq!(parsed.as_str(), url, "replayed exactly as signed, so canonical");
            assert_eq!(
                (parsed.scheme(), parsed.host_str(), parsed.port(), parsed.path()),
                ("https", Some(sts.host.as_str()), None, "/")
            );
            let q: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
            let names: Vec<&str> = q.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(
                names,
                [
                    "Action",
                    "Version",
                    "X-Amz-Algorithm",
                    "X-Amz-Credential",
                    "X-Amz-Date",
                    "X-Amz-Expires",
                    "X-Amz-Security-Token",
                    "X-Amz-SignedHeaders",
                    "X-Amz-Signature"
                ]
            );
            let get = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
            assert_eq!(get("Action"), Some("GetCallerIdentity"));
            assert_eq!(get("X-Amz-SignedHeaders"), Some("host;x-seal-binding"));
            assert_eq!(get("X-Amz-Expires"), Some("60"));
            assert_eq!(get("X-Amz-Security-Token"), Some("FQoG/token+x=="));
            let credential = format!("AKIAIOSFODNN7EXAMPLE/20270115/{}/sts/aws4_request", sts.region);
            assert_eq!(get("X-Amz-Credential"), Some(credential.as_str()));
            assert_eq!(get("X-Amz-Signature").map(str::len), Some(64));
            let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.expose())).collect();
            let binding = hex::encode(DeploymentBinding { nonce: [9; 32] }.digest());
            assert_eq!(headers, [("host", sts.host.as_str()), ("x-seal-binding", binding.as_str())]);
        }
    }
}

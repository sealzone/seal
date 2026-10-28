//! AWS proofs: a SigV4-signed STS `GetCallerIdentity` request, replayed by the enclave.
//!
//! Before anything is sent the request must be: `GET` or `POST` to `https://<sts host>/`
//! (the URL in canonical form, header values printable ASCII)
//! where the host is `sts.amazonaws.com`, `sts.<region>.amazonaws.com` or
//! `sts.<region>.amazonaws.com.cn` (no port other than 443, no credentials, no fragment);
//! `Action=GetCallerIdentity` (and `Version=2011-06-15` if given), with only known query and
//! form parameters and headers, none repeated; signed once, either presigned
//! (`X-Amz-Signature` in the query, `X-Amz-Expires` at most 900) or with an `Authorization`
//! header, `AWS4-HMAC-SHA256` for service `sts`, `host` among the signed headers; and, for a
//! request proof, `x-seal-binding` among the signed headers with the value hex(context digest).
//! STS answers JSON when asked with `Accept: application/json` (as EKS's aws-iam-authenticator
//! relies on for presigned requests), so the enclave sends that header and reads
//! `GetCallerIdentityResponse.GetCallerIdentityResult.{Account, Arn, UserId}`. Only roles
//! count: `UserId` must be `AROA…:<session>`, and the identity's `role_arn` is the IAM role
//! ARN rebuilt from the assumed-role ARN (without the role's path, which that ARN does not carry).

use seal_proto::identity::WorkloadIdentity;
use seal_proto::Bearer;
use serde::Deserialize;

use crate::AuthzError;

const BINDING_HEADER: &str = "x-seal-binding";
const MAX_PRESIGN_EXPIRES_SECS: u64 = 900;
const ALLOWED_PARAMS: &[&str] = &[
    "action",
    "version",
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-expires",
    "x-amz-signedheaders",
    "x-amz-signature",
    "x-amz-security-token",
];
const ALLOWED_HEADERS: &[&str] = &[
    "host",
    "authorization",
    "content-type",
    "accept",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
    BINDING_HEADER,
];

/// A checked request, ready to replay.
#[derive(Debug)]
pub(crate) struct StsCall {
    pub(crate) post: bool,
    pub(crate) url: String,
    /// Lowercase names; never `host` (the client sets it from the URL).
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: String,
}

fn bad(reason: &'static str) -> AuthzError {
    AuthzError::BadProof(reason)
}

/// `sts.amazonaws.com` or a regional STS endpoint.
pub(crate) fn is_sts_host(host: &str) -> bool {
    if host == "sts.amazonaws.com" {
        return true;
    }
    let region = host.strip_prefix("sts.").and_then(|r| {
        r.strip_suffix(".amazonaws.com")
            .or_else(|| r.strip_suffix(".amazonaws.com.cn").filter(|r| r.starts_with("cn-")))
    });
    region.is_some_and(|r| {
        let parts: Vec<&str> = r.split('-').collect();
        parts.len() >= 3
            && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
            && parts.last().is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Lowercase name → value, refusing repeats and names outside `allowed`.
fn unique(
    pairs: impl Iterator<Item = (String, String)>,
    allowed: &[&str],
    out: &mut Vec<(String, String)>,
    what: &'static str,
) -> Result<(), AuthzError> {
    for (name, value) in pairs {
        let name = name.to_ascii_lowercase();
        if !allowed.contains(&name.as_str()) {
            return Err(bad(what));
        }
        if out.iter().any(|(n, _)| *n == name) {
            return Err(bad("a parameter or header is repeated"));
        }
        out.push((name, value));
    }
    Ok(())
}

fn get<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// The credential scope `<key id>/<date>/<region>/sts/aws4_request`.
fn check_credential(credential: &str) -> Result<(), AuthzError> {
    let parts: Vec<&str> = credential.split('/').collect();
    match parts.as_slice() {
        [key, date, region, "sts", "aws4_request"] if !key.is_empty() && date.len() == 8 && !region.is_empty() => {
            Ok(())
        }
        _ => Err(bad("SigV4 credential scope is not for STS")),
    }
}

/// `Credential=…, SignedHeaders=…, Signature=…` of an `Authorization` header.
fn authorization_signed_headers(value: &str) -> Result<String, AuthzError> {
    let rest = value.strip_prefix("AWS4-HMAC-SHA256 ").ok_or(bad("Authorization is not AWS4-HMAC-SHA256"))?;
    let mut fields: Vec<(&str, &str)> = Vec::new();
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=').ok_or(bad("malformed Authorization"))?;
        if fields.iter().any(|(n, _)| *n == k) {
            return Err(bad("malformed Authorization"));
        }
        fields.push((k, v));
    }
    let field = |k| fields.iter().find(|(n, _)| *n == k).map(|(_, v)| *v).ok_or(bad("malformed Authorization"));
    check_credential(field("Credential")?)?;
    field("Signature")?;
    Ok(field("SignedHeaders")?.to_string())
}

/// Checks a proof before it is replayed; `binding` is the context digest a request proof
/// must carry in a signed `X-Seal-Binding`.
pub(crate) fn check(
    method: &str,
    url: &str,
    headers: &[(String, Bearer)],
    body: &str,
    binding: Option<&[u8; 32]>,
) -> Result<StsCall, AuthzError> {
    let post = match method {
        "GET" => false,
        "POST" => true,
        _ => return Err(bad("STS request method must be GET or POST")),
    };
    let parsed = url::Url::parse(url).map_err(|_| bad("STS request URL does not parse"))?;
    // Only the canonical form, so the URL replayed is exactly the one checked here.
    if parsed.as_str() != url {
        return Err(bad("STS request URL is not in canonical form"));
    }
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    if parsed.scheme() != "https"
        || !is_sts_host(&host)
        || parsed.port().is_some_and(|p| p != 443)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(bad("STS request is not for an STS endpoint"));
    }

    let mut params = Vec::new();
    unique(parsed.query_pairs().into_owned(), ALLOWED_PARAMS, &mut params, "STS request has an unknown parameter")?;
    if post {
        unique(
            url::form_urlencoded::parse(body.as_bytes()).into_owned(),
            &["action", "version"],
            &mut params,
            "STS request body has an unknown parameter",
        )?;
    } else if !body.is_empty() {
        return Err(bad("a GET STS request has no body"));
    }
    if get(&params, "action") != Some("GetCallerIdentity") {
        return Err(bad("STS request is not GetCallerIdentity"));
    }
    if get(&params, "version").is_some_and(|v| v != "2011-06-15") {
        return Err(bad("STS request has an unknown version"));
    }

    if headers.iter().any(|(_, v)| !v.expose().bytes().all(|b| (0x20..0x7f).contains(&b))) {
        return Err(bad("STS request has a malformed header value"));
    }
    let mut hdrs = Vec::new();
    unique(
        headers.iter().map(|(n, v)| (n.clone(), v.expose().to_string())),
        ALLOWED_HEADERS,
        &mut hdrs,
        "STS request has an unknown header",
    )?;
    if get(&hdrs, "host").is_some_and(|h| !h.eq_ignore_ascii_case(&host)) {
        return Err(bad("STS request Host disagrees with its URL"));
    }
    if get(&hdrs, "accept").is_some_and(|a| a != "application/json") {
        return Err(bad("STS request asks for another format"));
    }

    let signed_headers = match (get(&hdrs, "authorization"), get(&params, "x-amz-signature")) {
        (Some(auth), None) => {
            if params.iter().any(|(n, _)| n.starts_with("x-amz-") && n != "x-amz-security-token") {
                return Err(bad("STS request is signed twice"));
            }
            authorization_signed_headers(auth)?
        }
        (None, Some(_)) => {
            if get(&params, "x-amz-algorithm") != Some("AWS4-HMAC-SHA256") {
                return Err(bad("presigned STS request is not AWS4-HMAC-SHA256"));
            }
            check_credential(get(&params, "x-amz-credential").ok_or(bad("presigned STS request has no credential"))?)?;
            let expires = get(&params, "x-amz-expires").map(str::parse::<u64>);
            if matches!(expires, Some(Err(_))) || matches!(expires, Some(Ok(e)) if e > MAX_PRESIGN_EXPIRES_SECS) {
                return Err(bad("presigned STS request lives too long"));
            }
            get(&params, "x-amz-signedheaders").ok_or(bad("presigned STS request names no signed headers"))?.to_string()
        }
        _ => return Err(bad("STS request must be signed exactly once")),
    };
    let signed: Vec<&str> = signed_headers.split(';').collect();
    if !signed.contains(&"host") {
        return Err(bad("STS request does not sign its host"));
    }
    if let Some(digest) = binding {
        if !signed.contains(&BINDING_HEADER) {
            return Err(bad("X-Seal-Binding is not a signed header"));
        }
        let value = get(&hdrs, BINDING_HEADER).ok_or(bad("STS request has no X-Seal-Binding"))?;
        if !value.eq_ignore_ascii_case(&hex::encode(digest)) {
            return Err(bad("X-Seal-Binding is for another context"));
        }
    }
    if post && get(&hdrs, "content-type").is_none() {
        return Err(bad("a POST STS request needs its content type"));
    }

    let mut out: Vec<(String, String)> = hdrs.into_iter().filter(|(n, _)| n != "host").collect();
    if get(&out, "accept").is_none() {
        out.push(("accept".into(), "application/json".into()));
    }
    Ok(StsCall { post, url: url.to_string(), headers: out, body: body.to_string() })
}

#[derive(Deserialize)]
struct Response {
    #[serde(rename = "GetCallerIdentityResponse")]
    response: Inner,
}
#[derive(Deserialize)]
struct Inner {
    #[serde(rename = "GetCallerIdentityResult")]
    result: Identity,
}
#[derive(Deserialize)]
struct Identity {
    #[serde(rename = "Account")]
    account: String,
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "UserId")]
    user_id: String,
}

/// The role identity in a 200 `GetCallerIdentity` JSON response.
pub(crate) fn parse_response(body: &[u8]) -> Result<WorkloadIdentity, AuthzError> {
    let r: Response =
        serde_json::from_slice(body).map_err(|_| bad("STS response is not a GetCallerIdentity result"))?;
    let Identity { account, arn, user_id } = r.response.result;
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("STS response has a malformed account"));
    }
    let (role_id, _session) = user_id.split_once(':').ok_or(bad("STS caller is not an assumed role"))?;
    if !role_id.starts_with("AROA")
        || role_id.len() < 16
        || !role_id.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(bad("STS caller is not an assumed role"));
    }
    // arn:<partition>:sts::<account>:assumed-role/<role>/<session>
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    let ["arn", partition, "sts", "", arn_account, resource] = parts.as_slice() else {
        return Err(bad("STS response has a malformed ARN"));
    };
    let mut res = resource.splitn(3, '/');
    let (Some("assumed-role"), Some(role), Some(session)) = (res.next(), res.next(), res.next()) else {
        return Err(bad("STS caller is not an assumed role"));
    };
    if *arn_account != account
        || role.is_empty()
        || session.is_empty()
        || !matches!(*partition, "aws" | "aws-cn" | "aws-us-gov")
    {
        return Err(bad("STS response has a malformed ARN"));
    }
    Ok(WorkloadIdentity::AwsRole {
        role_arn: format!("arn:{partition}:iam::{account}:role/{role}"),
        account,
        role_id: role_id.to_string(),
    })
}

/// Sends the checked request to STS and reads the caller.
pub(crate) async fn replay(https: &seal_net::HttpsClient, call: &StsCall) -> Result<WorkloadIdentity, AuthzError> {
    let headers: Vec<(&str, &str)> = call.headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    let result = if call.post {
        https.post(&call.url, &headers, call.body.as_bytes()).await
    } else {
        https.get(&call.url, &headers).await
    };
    let (status, body) = result.map_err(|e| AuthzError::Unavailable(format!("STS: {e}")))?;
    match status {
        200 => parse_response(&body),
        400..=499 => Err(bad("STS refused the signed request")),
        _ => Err(AuthzError::Unavailable(format!("STS: HTTP {status}"))),
    }
}

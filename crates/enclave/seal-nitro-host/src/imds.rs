//! The instance role's credentials from IMDSv2 (`169.254.169.254`, plain HTTP on the
//! instance): a session token (`PUT /latest/api/token`), the role's name
//! (`GET /latest/meta-data/iam/security-credentials/`), then its credentials (`GET …/<role>`).
//! Fetched again for every proof: proofs are asked for once per enclave boot.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use zeroize::Zeroizing;

use crate::sigv4::Credentials;

pub const IMDS: SocketAddr =
    SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(169, 254, 169, 254), 80));
/// One request, whole exchange.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Largest answer read.
const MAX_ANSWER: usize = 64 * 1024;
const CREDENTIALS_PATH: &str = "/latest/meta-data/iam/security-credentials/";

/// IMDSv2 at `address`.
#[derive(Clone, Debug)]
pub struct Imds {
    address: SocketAddr,
}

impl Default for Imds {
    fn default() -> Self {
        Self { address: IMDS }
    }
}

impl Imds {
    /// IMDS at another address (tests).
    pub fn at(address: SocketAddr) -> Self {
        Self { address }
    }

    /// The instance role's current credentials.
    pub async fn credentials(&self) -> anyhow::Result<Credentials> {
        let token = self
            .request("PUT", "/latest/api/token", &[("x-aws-ec2-metadata-token-ttl-seconds", "60")])
            .await
            .context("IMDSv2 token")?;
        let token = Zeroizing::new(String::from_utf8(token).map_err(|_| anyhow!("IMDSv2 token is not text"))?);
        let auth = [("x-aws-ec2-metadata-token", token.as_str())];
        let roles = self.request("GET", CREDENTIALS_PATH, &auth).await.context("the instance profile's role")?;
        let roles = String::from_utf8(roles).map_err(|_| anyhow!("the role name is not text"))?;
        let role = roles.lines().next().map(str::trim).unwrap_or_default();
        if role.is_empty() || !role.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b)) {
            bail!("the instance has no usable instance profile role ({role:?})");
        }
        let body =
            self.request("GET", &format!("{CREDENTIALS_PATH}{role}"), &auth).await.context("role credentials")?;
        parse_credentials(&body)
    }

    /// One request: the body of a 200, else an error naming the status.
    async fn request(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> anyhow::Result<Vec<u8>> {
        let mut request = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, self.address.ip().to_string());
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(Full::new(Bytes::new()))?;
        let exchange = async {
            let stream = tokio::net::TcpStream::connect(self.address).await?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
            let conn = tokio::spawn(conn);
            let answer = async {
                let response = sender.send_request(request).await?;
                let status = response.status().as_u16();
                let body =
                    Limited::new(response.into_body(), MAX_ANSWER).collect().await.map_err(|e| anyhow!("{e}"))?;
                anyhow::Ok((status, body.to_bytes().to_vec()))
            }
            .await;
            conn.abort();
            answer
        };
        let (status, body) = tokio::time::timeout(TIMEOUT, exchange).await.map_err(|_| anyhow!("IMDS timed out"))??;
        if status != 200 {
            bail!("IMDS answered {status} to {method} {path}");
        }
        Ok(body)
    }
}

/// `{"Code": "Success", "AccessKeyId", "SecretAccessKey", "Token", …}`.
fn parse_credentials(body: &[u8]) -> anyhow::Result<Credentials> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Answer {
        code: String,
        access_key_id: String,
        secret_access_key: String,
        token: Option<String>,
    }
    let answer: Answer = serde_json::from_slice(body).map_err(|_| anyhow!("IMDS role credentials are not JSON"))?;
    if answer.code != "Success" {
        bail!("IMDS role credentials: {}", answer.code);
    }
    // Moved, not copied, into their zeroizing wrappers.
    let (secret, token) = (Zeroizing::new(answer.secret_access_key), answer.token.map(Zeroizing::new));
    if answer.access_key_id.is_empty() || secret.is_empty() {
        bail!("IMDS role credentials are empty");
    }
    Ok(Credentials { access_key_id: answer.access_key_id, secret_access_key: secret, session_token: token })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// A fake IMDSv2: records each request's method, path and token header.
    pub(crate) async fn fake_imds(code: &'static str) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let log = log.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let log = log.clone();
                        async move {
                            let token =
                                req.headers().get("x-aws-ec2-metadata-token").map(|v| v.to_str().unwrap().to_owned());
                            let ttl = req.headers().get("x-aws-ec2-metadata-token-ttl-seconds").is_some();
                            log.lock().unwrap().push(format!("{} {} {token:?}", req.method(), req.uri().path()));
                            let (status, body) = match (req.method().as_str(), req.uri().path(), token.as_deref()) {
                                ("PUT", "/latest/api/token", None) if ttl => (200, "tok-123".to_string()),
                                ("GET", CREDENTIALS_PATH, Some("tok-123")) => (200, "seal-parent\n".to_string()),
                                ("GET", "/latest/meta-data/iam/security-credentials/seal-parent", Some("tok-123")) => (
                                    200,
                                    serde_json::json!({
                                        "Code": code,
                                        "LastUpdated": "2026-11-02T00:00:00Z",
                                        "Type": "AWS-HMAC",
                                        "AccessKeyId": "ASIAEXAMPLE",
                                        "SecretAccessKey": "secret",
                                        "Token": "session-token",
                                        "Expiration": "2026-11-02T06:00:00Z",
                                    })
                                    .to_string(),
                                ),
                                _ => (401, String::new()),
                            };
                            let response =
                                hyper::Response::builder().status(status).body(Full::new(Bytes::from(body))).unwrap();
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (addr, seen)
    }

    #[tokio::test]
    async fn credentials_from_imdsv2() {
        let (addr, seen) = fake_imds("Success").await;
        let creds = Imds::at(addr).credentials().await.unwrap();
        assert_eq!(creds.access_key_id, "ASIAEXAMPLE");
        assert_eq!(creds.secret_access_key.as_str(), "secret");
        assert_eq!(creds.session_token.as_deref().map(String::as_str), Some("session-token"));
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "PUT /latest/api/token None",
                "GET /latest/meta-data/iam/security-credentials/ Some(\"tok-123\")",
                "GET /latest/meta-data/iam/security-credentials/seal-parent Some(\"tok-123\")",
            ]
        );
    }

    #[tokio::test]
    async fn imds_failures() {
        let (addr, _) = fake_imds("Expired").await;
        let Err(e) = Imds::at(addr).credentials().await else { panic!("expired credentials taken") };
        assert!(e.to_string().contains("Expired"), "{e}");
        // Nobody listening.
        let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        assert!(Imds::at(unused).credentials().await.is_err());
        for bad in [&b"{}"[..], b"not json", br#"{"Code":"Success","AccessKeyId":"","SecretAccessKey":"x"}"#] {
            assert!(parse_credentials(bad).is_err());
        }
    }
}

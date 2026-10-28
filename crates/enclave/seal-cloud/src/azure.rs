//! Azure confidential containers on ACI: the pin from `SEAL_TENANT`, the deployment identity from the group's
//! managed identity, TCP egress through the subnet's NAT gateway, Roughtime for time.
//!
//! - **Tenant pin**: the container's `SEAL_TENANT` (`<tenant>@<root id>`), which the release's container policy
//!   allows through one anchored re2 env rule. The rule, not the value, is in `host_data`, so every customer's
//!   group has the release's measurement; the value is deployer-set and unattested, and only narrows what the
//!   enclave serves.
//! - **Deployment proof**: a managed-identity token from IMDS (`169.254.169.254`, plain HTTP, `Metadata: true`)
//!   for an audience the tenant's Azure `deployments` entries name, the same audience rule
//!   `seal_authz::DeploymentVerifier` checks. With several audiences, the token whose `tid` and `oid` an entry
//!   for that audience names is used, else the first audience's. The group carries exactly one managed identity
//!   (Seal's template assigns it), so the request names none. IMDS is the host's, so the token counts only once
//!   the verifier has checked its signature.
//! - **Network**: `seal_net::TcpDialer` and `seal_net::UdpDatagrams`; Roughtime's default servers.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use seal_authz::DeploymentProof;
use seal_proto::identity::{IdentityMatcher, IdentityProof, OidcProvider};
use seal_proto::{Bearer, TenantPin};
use seal_tee::roughtime::{default_servers, RoughtimeClock, DEFAULT_MIN_AGREEING};
use seal_tee::{Attestor, Clock};

use crate::CloudError;

const IMDS_ADDRESS: (&str, u16) = ("169.254.169.254", 80);
const TOKEN_PATH: &str = "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=";
/// One IMDS request, whole exchange.
const IMDS_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest IMDS answer read.
const MAX_ANSWER: usize = 64 * 1024;
/// Token requests per audience. IMDS answers 404, 410, 429 and 5xx while the identity is still being attached;
/// those and failed connections are retried after 1, 2, 4 and 8 s.
const ATTEMPTS: u32 = 5;

/// An ACI confidential container group.
pub struct Aci {
    pub(crate) attestor: Attestor,
    pub(crate) clock: Clock,
    pub(crate) dialer: Arc<dyn seal_net::Dialer>,
    pub(crate) pin: TenantPin,
    identity: ManagedIdentity,
}

impl Aci {
    /// Around the attestor `Attestor::detect` chose, with the pin from `SEAL_TENANT`.
    pub(crate) fn from_env(attestor: seal_tee::azure::SnpAciAttestor) -> Result<Self, CloudError> {
        let dialer: Arc<dyn seal_net::Dialer> = Arc::new(seal_net::TcpDialer);
        let clock = RoughtimeClock::new(default_servers(), DEFAULT_MIN_AGREEING, Arc::new(seal_net::UdpDatagrams));
        Ok(Self {
            attestor: Attestor::AzureSnpAci(attestor),
            clock: Clock::Roughtime(clock),
            pin: crate::tenant_pin(std::env::var(crate::TENANT_VAR).ok())?,
            identity: ManagedIdentity::new(dialer.clone()),
            dialer,
        })
    }

    pub(crate) async fn deployment(
        &self,
        deployments: &BTreeSet<IdentityMatcher>,
    ) -> Result<DeploymentProof, CloudError> {
        self.identity.proof(deployments).await
    }
}

/// The group's managed identity, through IMDS.
pub(crate) struct ManagedIdentity {
    dialer: Arc<dyn seal_net::Dialer>,
    address: (String, u16),
}

impl ManagedIdentity {
    pub(crate) fn new(dialer: Arc<dyn seal_net::Dialer>) -> Self {
        Self::at(dialer, IMDS_ADDRESS.0, IMDS_ADDRESS.1)
    }

    /// IMDS at `host:port` (tests).
    pub(crate) fn at(dialer: Arc<dyn seal_net::Dialer>, host: &str, port: u16) -> Self {
        Self { dialer, address: (host.to_owned(), port) }
    }

    /// The token for the audience chosen as the module docs say.
    pub(crate) async fn proof(&self, deployments: &BTreeSet<IdentityMatcher>) -> Result<DeploymentProof, CloudError> {
        let audiences: BTreeSet<&str> = deployments
            .iter()
            .filter_map(|m| match m {
                IdentityMatcher::Azure { audience, .. } => Some(audience.as_str()),
                _ => None,
            })
            .collect();
        if audiences.is_empty() {
            return Err(CloudError::Deployment("the tenant's deployments name no Azure managed identity".into()));
        }
        let mut first = None;
        for audience in &audiences {
            let token = self.token(audience).await?;
            if audiences.len() == 1 || names(deployments, audience, &token) {
                return Ok(oidc(token));
            }
            first.get_or_insert(token);
        }
        Ok(oidc(first.expect("at least one audience")))
    }

    /// An access token for `audience`, retried as `ATTEMPTS` says.
    pub(crate) async fn token(&self, audience: &str) -> Result<Bearer, CloudError> {
        let resource: String = url::form_urlencoded::byte_serialize(audience.as_bytes()).collect();
        let path = format!("{TOKEN_PATH}{resource}");
        let mut delay = Duration::from_secs(1);
        let mut attempt = 1;
        loop {
            let failure = match self.get(&path).await {
                Ok((200, body)) => return access_token(&body),
                Ok((status, _)) if !retried(status) => {
                    return Err(CloudError::Deployment(format!("IMDS token for {audience}: HTTP {status}")))
                }
                Ok((status, _)) => format!("HTTP {status}"),
                Err(e) => e,
            };
            if attempt == ATTEMPTS {
                return Err(CloudError::Deployment(format!("IMDS token for {audience}: {failure}")));
            }
            tracing::debug!(%audience, attempt, %failure, "IMDS token request failed; retrying");
            tokio::time::sleep(delay).await;
            delay *= 2;
            attempt += 1;
        }
    }

    /// One `GET` with `Metadata: true`: the status and at most `MAX_ANSWER` bytes of body.
    async fn get(&self, path: &str) -> Result<(u16, Vec<u8>), String> {
        let (host, port) = (&self.address.0, self.address.1);
        let request = hyper::Request::get(path)
            .header(hyper::header::HOST, host.as_str())
            .header("metadata", "true")
            .body(Empty::<hyper::body::Bytes>::new())
            .map_err(|e| e.to_string())?;
        let exchange = async {
            let stream = self.dialer.dial(host, port).await.map_err(|e| e.to_string())?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| e.to_string())?;
            let conn = tokio::spawn(conn);
            let answer = async {
                let response = sender.send_request(request).await.map_err(|e| e.to_string())?;
                let status = response.status().as_u16();
                let body = Limited::new(response.into_body(), MAX_ANSWER).collect().await.map_err(|e| e.to_string())?;
                Ok((status, body.to_bytes().to_vec()))
            }
            .await;
            conn.abort();
            answer
        };
        tokio::time::timeout(IMDS_TIMEOUT, exchange).await.map_err(|_| "timed out".to_owned())?
    }
}

fn retried(status: u16) -> bool {
    matches!(status, 404 | 410 | 429 | 500..=599)
}

fn access_token(body: &[u8]) -> Result<Bearer, CloudError> {
    #[derive(serde::Deserialize)]
    struct Answer {
        access_token: String,
    }
    let answer: Answer = serde_json::from_slice(body)
        .map_err(|_| CloudError::Deployment("IMDS answered without an access_token".into()))?;
    Ok(Bearer::new(answer.access_token))
}

fn oidc(jwt: Bearer) -> DeploymentProof {
    DeploymentProof::Proof(IdentityProof::Oidc { provider: OidcProvider::Azure, jwt })
}

/// Whether an entry for `audience` names the token's (unverified) `tid` and `oid`.
fn names(deployments: &BTreeSet<IdentityMatcher>, audience: &str, token: &Bearer) -> bool {
    let claims = token
        .expose()
        .split('.')
        .nth(1)
        .and_then(|payload| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok())
        .and_then(|json| serde_json::from_slice::<serde_json::Value>(&json).ok());
    let Some(claims) = claims else { return false };
    let claim = |name: &str| claims.get(name).and_then(serde_json::Value::as_str);
    deployments.iter().any(|m| {
        matches!(m, IdentityMatcher::Azure { entra_tenant, object_id, audience: a, .. }
            if a == audience && claim("tid") == Some(entra_tenant.as_str()) && claim("oid") == Some(object_id.as_str()))
    })
}

#[cfg(test)]
mod tests;

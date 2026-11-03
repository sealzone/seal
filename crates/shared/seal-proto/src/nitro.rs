//! What a Nitro enclave and its parent instance say to each other over vsock. The enclave has
//! no network interface: everything it exchanges with the world goes through the parent, which
//! is untrusted like any host.
//!
//! | Who listens | vsock address | What |
//! | --- | --- | --- |
//! | the parent | `PARENT_CID`:`PARENT_PORT` | the enclave sends a fresh 32-byte nonce; the parent answers one `ParentMessage`, as JSON, and closes |
//! | the parent | `PARENT_CID`:`EGRESS_PORT` | egress: the enclave sends `CONNECT host:port HTTP/1.1`, the parent answers `200` and relays the bytes to and from `host:port` |
//! | the enclave | its CID : the release's `listen` port (8443) | the enclave's one port: the parent relays each TCP connection to it, after a PROXY protocol v2 header naming the client |
//!
//! The enclave reads the first `ParentMessage` at boot: its `tenant` is the replica's tenant
//! pin. Before requesting keys it connects again, with a nonce of its own, and takes that
//! message's `deployment`: a proof whose signed `X-Seal-Binding` is
//! hex(`DeploymentBinding { nonce }.digest()`), which no earlier proof of the role carries, so
//! none can be replayed (`seal_authz::DeploymentVerifier`). A later message naming another
//! tenant is refused.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityProof;
use crate::TenantPin;

/// The parent instance, as an enclave addresses it (`VMADDR_CID_PARENT`).
pub const PARENT_CID: u32 = 3;
/// The parent's port serving `ParentMessage`s.
pub const PARENT_PORT: u32 = 9000;
/// The parent's egress port (`CONNECT host:port`).
pub const EGRESS_PORT: u32 = 9001;
/// What the enclave sends first on `PARENT_PORT`: a nonce of this many bytes, raw.
pub const NONCE_LEN: usize = 32;
/// The largest `ParentMessage` an enclave reads. A presigned request with a session token is
/// about 2 KiB.
pub const MAX_PARENT_MESSAGE: usize = 64 * 1024;
/// The largest `CONNECT` request or response head either side reads.
pub const MAX_CONNECT_HEAD: usize = 4096;

/// What the parent tells its enclave, as JSON. Unattested, like every cloud's tenant pin: the
/// pin can only narrow what the enclave serves, and the proof counts only once STS has answered
/// it (`seal_authz::DeploymentVerifier`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentMessage {
    /// The tenant pin, `<tenant>@<root id>`.
    pub tenant: TenantPin,
    /// An STS `GetCallerIdentity` request the parent presigned with its instance role
    /// (`IdentityProof::AwsSigV4`), signing `host` and `x-seal-binding`, which is
    /// hex(`DeploymentBinding { nonce }.digest()`) for the nonce this connection began with.
    pub deployment: IdentityProof,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bearer;

    #[test]
    fn parent_messages_are_json() {
        let text = format!(
            r#"{{"tenant":"acme@{}","deployment":{{"kind":"aws_sig_v4","method":"GET","url":"https://sts.amazonaws.com/?Action=GetCallerIdentity","headers":[["host","sts.amazonaws.com"]],"body":""}}}}"#,
            "ab".repeat(32)
        );
        let message: ParentMessage = serde_json::from_str(&text).unwrap();
        assert_eq!(message.tenant.to_string(), format!("acme@{}", "ab".repeat(32)));
        let IdentityProof::AwsSigV4 { method, headers, .. } = &message.deployment else { panic!("not SigV4") };
        assert_eq!(method, "GET");
        assert_eq!(headers[0].1, Bearer::new("sts.amazonaws.com".into()));
        assert_eq!(serde_json::to_string(&message).unwrap(), text);
        // Unknown fields and bad pins are refused.
        assert!(serde_json::from_str::<ParentMessage>(&text.replacen('{', r#"{"extra":1,"#, 1)).is_err());
        assert!(serde_json::from_str::<ParentMessage>(&text.replacen("acme@", "acme#", 1)).is_err());
    }
}

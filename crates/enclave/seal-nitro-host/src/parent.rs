//! The parent's messages (`seal_proto::nitro::ParentMessage`): on `PARENT_PORT`, each
//! connection from the enclave sends a `NONCE_LEN`-byte nonce and gets one message, as JSON,
//! and is closed. Its `tenant` is the configured pin; its `deployment` a `GetCallerIdentity`
//! presigned for this connection, bound to its nonce, with the instance role's credentials,
//! fresh from IMDS (`sigv4`, `imds`). When the credentials
//! cannot be had, the connection is closed with nothing sent: the enclave retries at boot, and
//! fails its boot otherwise.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use seal_proto::nitro::{ParentMessage, NONCE_LEN};
use seal_proto::TenantPin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::sigv4::{self, Credentials, Sts};

/// Building and sending one message.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the role's credentials come from: IMDS (`imds::Imds`), or a test's.
#[async_trait]
pub trait CredentialSource: Send + Sync {
    async fn credentials(&self) -> anyhow::Result<Credentials>;
}

#[async_trait]
impl CredentialSource for crate::imds::Imds {
    async fn credentials(&self) -> anyhow::Result<Credentials> {
        crate::imds::Imds::credentials(self).await
    }
}

/// What the parent tells its enclave.
pub struct Messages {
    pub tenant: TenantPin,
    pub sts: Sts,
    pub credentials: Arc<dyn CredentialSource>,
}

impl Messages {
    /// One message, its proof bound to `nonce` and signed now.
    pub async fn message(&self, nonce: [u8; NONCE_LEN]) -> anyhow::Result<Vec<u8>> {
        let creds = self.credentials.credentials().await?;
        let deployment = sigv4::get_caller_identity(&creds, &self.sts, nonce, SystemTime::now());
        Ok(serde_json::to_vec(&ParentMessage { tenant: self.tenant.clone(), deployment })?)
    }
}

/// Serves `messages` on `listener` to `enclave_cid` only.
pub async fn serve(listener: seal_net::vsock::VsockListener, enclave_cid: u32, messages: Arc<Messages>) {
    loop {
        let (mut stream, cid) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "parent message accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if cid != enclave_cid {
            tracing::warn!(cid, "parent message refused: not from the enclave");
            continue;
        }
        let messages = messages.clone();
        tokio::spawn(async move {
            let send = async {
                let mut nonce = [0u8; NONCE_LEN];
                stream.read_exact(&mut nonce).await?;
                let message = messages.message(nonce).await?;
                stream.write_all(&message).await?;
                stream.shutdown().await?;
                anyhow::Ok(())
            };
            match tokio::time::timeout(MESSAGE_TIMEOUT, send).await {
                Ok(Ok(())) => tracing::info!("sent the enclave its pin and a deployment proof"),
                Ok(Err(e)) => tracing::warn!(error = %e, "no message for the enclave"),
                Err(_) => tracing::warn!("the enclave's message timed out"),
            }
        });
    }
}

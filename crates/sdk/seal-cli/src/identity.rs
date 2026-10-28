//! The identities `seal grant` and `seal revoke` name: one subcommand per kind, its flags the
//! provider's immutable ids. This build resolves no names through cloud APIs, so each flag
//! says where its id comes from. Revoking names an identity by its primary id alone.

use std::path::PathBuf;

use anyhow::bail;
use clap::{Args, Subcommand};

use seal_proto::identity::{GitHubScope, HostedMode, IdentityMatcher};
use seal_proto::PublicKey;

#[derive(Args, Debug, Clone)]
pub struct AzureId {
    /// The managed identity's object (principal) id: `az identity show --query principalId`
    #[arg(long, value_name = "OID")]
    pub object_id: String,
    /// Its Entra tenant id: `az identity show --query tenantId`
    #[arg(long, value_name = "ID")]
    pub entra_tenant: String,
    /// The Entra app ID URI the tenant registered for Seal: the audience of its tokens
    #[arg(long, value_name = "URI")]
    pub audience: String,
}

#[derive(Args, Debug, Clone)]
pub struct AwsId {
    /// The IAM role's ARN, arn:aws:iam::ACCOUNT:role/NAME
    #[arg(long, value_name = "ARN", value_parser = role_arn)]
    pub role_arn: String,
    /// The role's unique id (AROA…): `aws iam get-role --query Role.RoleId`
    #[arg(long, value_name = "AROA…")]
    pub role_id: String,
}

#[derive(Args, Debug, Clone)]
pub struct K8sId {
    /// The service account, NAMESPACE/NAME
    #[arg(long, value_name = "NS/NAME", value_parser = namespaced)]
    pub service_account: (String, String),
    /// The cluster's service-account token issuer URL
    #[arg(long, value_name = "URL")]
    pub issuer: String,
    /// The service account's uid: `kubectl get sa NAME -n NS -o jsonpath={.metadata.uid}`
    #[arg(long, value_name = "UID")]
    pub uid: String,
}

#[derive(Args, Debug, Clone)]
pub struct GcpId {
    /// The service account's email
    #[arg(long, value_name = "EMAIL")]
    pub email: String,
    /// Its unique id: `gcloud iam service-accounts describe EMAIL --format 'value(uniqueId)'`
    #[arg(long, value_name = "ID")]
    pub unique_id: String,
}

/// A repository alone is never enough: a workflow proves its environment or its ref.
#[derive(Args, Debug, Clone)]
pub struct GitHubScopeArgs {
    /// Runs in this deployment environment
    #[arg(long, value_name = "NAME", conflicts_with = "git_ref", required_unless_present = "git_ref")]
    pub environment: Option<String>,
    /// Runs on this ref, e.g. refs/heads/main
    #[arg(long = "ref", value_name = "REF", id = "git_ref")]
    pub git_ref: Option<String>,
}

impl GitHubScopeArgs {
    fn scope(&self) -> GitHubScope {
        match (&self.environment, &self.git_ref) {
            (Some(e), _) => GitHubScope::Environment(e.clone()),
            (None, Some(r)) => GitHubScope::Ref(r.clone()),
            (None, None) => unreachable!("clap requires one"),
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct GitHubId {
    /// The repository, OWNER/REPO
    #[arg(long, value_name = "OWNER/REPO", value_parser = repository)]
    pub repo: String,
    #[command(flatten)]
    pub scope: GitHubScopeArgs,
    /// The repository's numeric id: `gh api repos/OWNER/REPO --jq .id`
    #[arg(long, value_name = "N")]
    pub repository_id: u64,
    /// The owner's numeric id: `gh api repos/OWNER/REPO --jq .owner.id`
    #[arg(long, value_name = "N")]
    pub owner_id: u64,
}

#[derive(Args, Debug, Clone)]
pub struct KeyArgs {
    /// Generate a new app key (SEAL_APP_KEY) and grant it
    #[arg(long, conflicts_with = "public", required_unless_present = "public")]
    pub generate: bool,
    /// Write the generated key to FILE (mode 0600); without it the key goes to stdout, which
    /// must not be a terminal
    #[arg(long, value_name = "FILE", requires = "generate")]
    pub out: Option<PathBuf>,
    /// An existing app key, by its Ed25519 public key (hex)
    #[arg(long, value_name = "HEX")]
    pub public: Option<PublicKey>,
}

#[derive(Args, Debug, Clone)]
pub struct ConfidentialSpaceId {
    /// The Google Cloud project number the VM runs in
    #[arg(long, value_name = "N")]
    pub project_number: u64,
    /// The VM's service account email
    #[arg(long, value_name = "EMAIL")]
    pub service_account: String,
}

#[derive(Args, Debug, Clone)]
pub struct Hosted {
    /// Mark it as Seal's hosted replicas of this tenant: they seal, serve sessions and stop
    /// when idle
    #[arg(long)]
    pub hosted: bool,
}

impl Hosted {
    /// The entry's mark: `HostedMode::Sessions` when `--hosted` is given.
    fn mark(&self) -> Option<HostedMode> {
        self.hosted.then_some(HostedMode::Sessions)
    }
}

/// An identity of an app, as granted.
#[derive(Subcommand, Debug, Clone)]
pub enum Workload {
    /// An Azure managed identity
    Azure(AzureId),
    /// An AWS IAM role
    Aws(AwsId),
    /// A Kubernetes service account
    K8s(K8sId),
    /// A Google Cloud service account
    Gcp(GcpId),
    /// A GitHub Actions workflow of a repository, in an environment or on a ref
    Github(GitHubId),
    /// An app key (SEAL_APP_KEY): a new one, or an existing one by public key
    Key(KeyArgs),
}

/// An identity of an app, as revoked: by its primary id.
#[derive(Subcommand, Debug, Clone)]
pub enum WorkloadRef {
    /// An Azure managed identity
    Azure {
        /// The managed identity's object (principal) id
        #[arg(long, value_name = "OID")]
        object_id: String,
    },
    /// An AWS IAM role
    Aws {
        /// The IAM role's ARN
        #[arg(long, value_name = "ARN", value_parser = role_arn)]
        role_arn: String,
    },
    /// A Kubernetes service account
    K8s {
        /// The service account, NAMESPACE/NAME
        #[arg(long, value_name = "NS/NAME", value_parser = namespaced)]
        service_account: (String, String),
    },
    /// A Google Cloud service account
    Gcp {
        /// The service account's email
        #[arg(long, value_name = "EMAIL")]
        email: String,
    },
    /// A GitHub Actions workflow
    Github {
        /// The repository, OWNER/REPO
        #[arg(long, value_name = "OWNER/REPO", value_parser = repository)]
        repo: String,
        #[command(flatten)]
        scope: GitHubScopeArgs,
    },
    /// An app key
    Key {
        /// The app key's Ed25519 public key (hex)
        #[arg(long, value_name = "HEX")]
        public: PublicKey,
    },
}

/// An enclave deployment's identity, as granted.
#[derive(Subcommand, Debug, Clone)]
pub enum Deployment {
    /// Azure confidential containers, by the group's managed identity
    Azure {
        #[command(flatten)]
        id: AzureId,
        #[command(flatten)]
        hosted: Hosted,
    },
    /// AWS Nitro Enclaves, by the parent instance's IAM role
    Aws(AwsId),
    /// A Google Cloud Confidential Space VM, by project and service account
    ConfidentialSpace {
        #[command(flatten)]
        id: ConfidentialSpaceId,
        #[command(flatten)]
        hosted: Hosted,
    },
    /// Sim builds: the identity a sim enclave reports (its SEAL_SIM_DEPLOYMENT)
    #[cfg(feature = "sim")]
    Sim {
        /// A `WorkloadIdentity` as JSON
        identity: String,
        /// The audience, for an Azure identity
        #[arg(long, value_name = "URI")]
        audience: Option<String>,
        #[command(flatten)]
        hosted: Hosted,
    },
}

/// An enclave deployment's identity, as revoked: by its primary id, hosted or not.
#[derive(Subcommand, Debug, Clone)]
pub enum DeploymentRef {
    /// Azure confidential containers
    Azure {
        /// The managed identity's object (principal) id
        #[arg(long, value_name = "OID")]
        object_id: String,
    },
    /// AWS Nitro Enclaves
    Aws {
        /// The IAM role's ARN
        #[arg(long, value_name = "ARN", value_parser = role_arn)]
        role_arn: String,
    },
    /// A Google Cloud Confidential Space VM
    ConfidentialSpace(ConfidentialSpaceId),
    /// Sim builds: the identity a sim enclave reports
    #[cfg(feature = "sim")]
    Sim {
        /// A `WorkloadIdentity` as JSON
        identity: String,
    },
}

fn role_arn(value: &str) -> Result<String, String> {
    if value.starts_with("arn:aws") && value.contains(":role/") {
        Ok(value.to_string())
    } else {
        Err("a role ARN, arn:aws:iam::ACCOUNT:role/NAME".into())
    }
}

fn namespaced(value: &str) -> Result<(String, String), String> {
    match value.split_once('/') {
        Some((a, b)) if !a.is_empty() && !b.is_empty() && !b.contains('/') => Ok((a.to_string(), b.to_string())),
        _ => Err("NAMESPACE/NAME".into()),
    }
}

fn repository(value: &str) -> Result<String, String> {
    namespaced(value).map(|_| value.to_string()).map_err(|_| "OWNER/REPO".into())
}

/// `m` without its hosted mark: the identity alone.
fn identity_of(m: &IdentityMatcher) -> IdentityMatcher {
    match m.clone() {
        IdentityMatcher::Azure { entra_tenant, object_id, audience, .. } => {
            IdentityMatcher::Azure { entra_tenant, object_id, audience, hosted: None }
        }
        IdentityMatcher::ConfidentialSpace { project_number, service_account, .. } => {
            IdentityMatcher::ConfidentialSpace { project_number, service_account, hosted: None }
        }
        other => other,
    }
}

fn azure(id: &AzureId, hosted: Option<HostedMode>) -> IdentityMatcher {
    IdentityMatcher::Azure {
        entra_tenant: id.entra_tenant.clone(),
        object_id: id.object_id.clone(),
        audience: id.audience.clone(),
        hosted,
    }
}

fn aws(id: &AwsId) -> IdentityMatcher {
    IdentityMatcher::AwsRole { role_arn: id.role_arn.clone(), role_id: id.role_id.clone() }
}

fn confidential_space(id: &ConfidentialSpaceId, hosted: Option<HostedMode>) -> IdentityMatcher {
    IdentityMatcher::ConfidentialSpace {
        project_number: id.project_number,
        service_account: id.service_account.clone(),
        hosted,
    }
}

fn app_key(public_key: PublicKey) -> IdentityMatcher {
    IdentityMatcher::AppKey { key_id: seal_crypto::sign::key_id(&public_key), public_key }
}

impl Workload {
    /// The matcher to grant. `generated` is the public key of the key `key --generate` made.
    pub fn matcher(&self, generated: Option<PublicKey>) -> anyhow::Result<IdentityMatcher> {
        Ok(match self {
            Workload::Azure(id) => azure(id, None),
            Workload::Aws(id) => aws(id),
            Workload::K8s(id) => IdentityMatcher::Kubernetes {
                issuer: id.issuer.clone(),
                namespace: id.service_account.0.clone(),
                service_account: id.service_account.1.clone(),
                service_account_uid: id.uid.clone(),
            },
            Workload::Gcp(id) => IdentityMatcher::Gcp { email: id.email.clone(), unique_id: id.unique_id.clone() },
            Workload::Github(id) => IdentityMatcher::GitHub {
                repository: id.repo.clone(),
                repository_id: id.repository_id,
                repository_owner_id: id.owner_id,
                scope: id.scope.scope(),
            },
            Workload::Key(k) => match (k.public, generated) {
                (Some(public_key), _) | (None, Some(public_key)) => app_key(public_key),
                (None, None) => bail!("key --generate makes the key first"),
            },
        })
    }

    /// `key --generate`: where the new key goes (`None`: stdout).
    pub fn generates(&self) -> Option<Option<&PathBuf>> {
        match self {
            Workload::Key(k) if k.generate => Some(k.out.as_ref()),
            _ => None,
        }
    }
}

impl WorkloadRef {
    /// Whether `m` is this identity.
    pub fn selects(&self, m: &IdentityMatcher) -> bool {
        match (self, m) {
            (WorkloadRef::Azure { object_id }, IdentityMatcher::Azure { object_id: o, .. }) => object_id == o,
            (WorkloadRef::Aws { role_arn }, IdentityMatcher::AwsRole { role_arn: r, .. }) => role_arn == r,
            (
                WorkloadRef::K8s { service_account },
                IdentityMatcher::Kubernetes { namespace, service_account: sa, .. },
            ) => &service_account.0 == namespace && &service_account.1 == sa,
            (WorkloadRef::Gcp { email }, IdentityMatcher::Gcp { email: e, .. }) => email == e,
            (WorkloadRef::Github { repo, scope }, IdentityMatcher::GitHub { repository, scope: s, .. }) => {
                repo == repository && &scope.scope() == s
            }
            (WorkloadRef::Key { public }, IdentityMatcher::AppKey { public_key, .. }) => public == public_key,
            _ => false,
        }
    }
}

impl Deployment {
    pub fn matcher(&self) -> anyhow::Result<IdentityMatcher> {
        Ok(match self {
            Deployment::Azure { id, hosted } => azure(id, hosted.mark()),
            Deployment::Aws(id) => aws(id),
            Deployment::ConfidentialSpace { id, hosted } => confidential_space(id, hosted.mark()),
            #[cfg(feature = "sim")]
            Deployment::Sim { identity, audience, hosted } => {
                let identity = serde_json::from_str(identity).map_err(|e| anyhow::anyhow!("the identity: {e}"))?;
                let m = matcher_for(identity, audience.clone())?;
                match (m, hosted.mark()) {
                    (IdentityMatcher::Azure { entra_tenant, object_id, audience, .. }, mode) => {
                        IdentityMatcher::Azure { entra_tenant, object_id, audience, hosted: mode }
                    }
                    (IdentityMatcher::ConfidentialSpace { project_number, service_account, .. }, mode) => {
                        IdentityMatcher::ConfidentialSpace { project_number, service_account, hosted: mode }
                    }
                    (_, Some(_)) => bail!("--hosted marks an Azure or Confidential Space identity"),
                    (m, None) => m,
                }
            }
        })
    }

    /// The same identity as revoking names it, to find an entry to replace.
    pub fn as_ref(&self) -> DeploymentRef {
        match self {
            Deployment::Azure { id, .. } => DeploymentRef::Azure { object_id: id.object_id.clone() },
            Deployment::Aws(id) => DeploymentRef::Aws { role_arn: id.role_arn.clone() },
            Deployment::ConfidentialSpace { id, .. } => DeploymentRef::ConfidentialSpace(id.clone()),
            #[cfg(feature = "sim")]
            Deployment::Sim { identity, .. } => DeploymentRef::Sim { identity: identity.clone() },
        }
    }
}

impl DeploymentRef {
    /// Whether `m` is this identity, hosted or not.
    pub fn selects(&self, m: &IdentityMatcher) -> anyhow::Result<bool> {
        Ok(match (self, m) {
            (DeploymentRef::Azure { object_id }, IdentityMatcher::Azure { object_id: o, .. }) => object_id == o,
            (DeploymentRef::Aws { role_arn }, IdentityMatcher::AwsRole { role_arn: r, .. }) => role_arn == r,
            (DeploymentRef::ConfidentialSpace(id), IdentityMatcher::ConfidentialSpace { .. }) => {
                confidential_space(id, None) == identity_of(m)
            }
            #[cfg(feature = "sim")]
            (DeploymentRef::Sim { identity }, m) => {
                let identity = serde_json::from_str(identity).map_err(|e| anyhow::anyhow!("the identity: {e}"))?;
                let audience = match m {
                    IdentityMatcher::Azure { audience, .. } => Some(audience.clone()),
                    _ => None,
                };
                matcher_for(identity, audience)? == identity_of(m)
            }
            _ => false,
        })
    }
}

/// A `WorkloadIdentity` as the matcher that matches exactly it. Azure needs `audience`;
/// app keys cannot be deployments.
#[cfg(feature = "sim")]
fn matcher_for(
    identity: seal_proto::identity::WorkloadIdentity,
    audience: Option<String>,
) -> anyhow::Result<IdentityMatcher> {
    use seal_proto::identity::WorkloadIdentity as W;
    Ok(match identity {
        W::Azure { entra_tenant, object_id } => IdentityMatcher::Azure {
            entra_tenant,
            object_id,
            audience: audience.ok_or_else(|| anyhow::anyhow!("an Azure identity needs --audience"))?,
            hosted: None,
        },
        W::AwsRole { role_arn, role_id, .. } => IdentityMatcher::AwsRole { role_arn, role_id },
        W::Kubernetes { .. } | W::Gcp { .. } | W::GitHub { .. } => bail!("not an enclave deployment identity"),
        W::ConfidentialSpace { project_number, service_account } => {
            IdentityMatcher::ConfidentialSpace { project_number, service_account, hosted: None }
        }
        W::AppKey { .. } => bail!("an app key cannot be a deployment identity"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Grant {
        #[command(subcommand)]
        identity: Workload,
    }

    #[derive(Parser, Debug)]
    struct Revoke {
        #[command(subcommand)]
        identity: WorkloadRef,
    }

    #[derive(Parser, Debug)]
    struct Enclave {
        #[command(subcommand)]
        identity: Deployment,
    }

    fn grant(args: &[&str]) -> Result<Workload, clap::Error> {
        Grant::try_parse_from(std::iter::once("grant").chain(args.iter().copied())).map(|g| g.identity)
    }

    #[test]
    fn each_kind_takes_its_ids() {
        let m = grant(&["aws", "--role-arn", "arn:aws:iam::1:role/x", "--role-id", "AROA1"]).unwrap();
        assert!(matches!(m.matcher(None).unwrap(), IdentityMatcher::AwsRole { .. }));
        assert!(grant(&["aws", "--role-arn", "arn:aws:iam::1:role/x"]).is_err(), "--role-id is required");
        assert!(grant(&["aws", "--role-arn", "x", "--role-id", "AROA1"]).is_err(), "not an ARN");
        let k8s = ["k8s", "--service-account", "prod/api", "--issuer", "https://k", "--uid", "u"];
        assert!(matches!(grant(&k8s).unwrap().matcher(None).unwrap(), IdentityMatcher::Kubernetes { .. }));
        assert!(grant(&["k8s", "--service-account", "api", "--issuer", "https://k", "--uid", "u"]).is_err());
        let gh = ["github", "--repo", "acme/api", "--environment", "prod", "--repository-id", "1", "--owner-id", "2"];
        let m = grant(&gh).unwrap().matcher(None).unwrap();
        assert!(matches!(m, IdentityMatcher::GitHub { scope: GitHubScope::Environment(ref e), .. } if e == "prod"));
        assert!(
            grant(&["github", "--repo", "acme/api", "--repository-id", "1", "--owner-id", "2"]).is_err(),
            "a scope"
        );
        assert!(grant(&[&gh[..], &["--ref", "refs/heads/main"]].concat()).is_err(), "one scope");
        assert!(grant(&["key"]).is_err(), "--generate or --public");
        assert!(grant(&["key", "--out", "k"]).is_err(), "--out goes with --generate");
        let generate = grant(&["key", "--generate", "--out", "k.key"]).unwrap();
        assert_eq!(generate.generates(), Some(Some(&PathBuf::from("k.key"))));
        assert!(matches!(generate.matcher(Some(PublicKey([1; 32]))).unwrap(), IdentityMatcher::AppKey { .. }));
        assert!(
            grant(&["confidential-space", "--project-number", "1", "--service-account", "a@b"]).is_err(),
            "enclaves only"
        );
    }

    #[test]
    fn revoking_names_the_primary_id() {
        let m = IdentityMatcher::AwsRole { role_arn: "arn:aws:iam::1:role/x".into(), role_id: "AROA1".into() };
        let parse =
            |args: &[&str]| Revoke::try_parse_from(std::iter::once("revoke").chain(args.iter().copied())).unwrap();
        assert!(parse(&["aws", "--role-arn", "arn:aws:iam::1:role/x"]).identity.selects(&m));
        assert!(!parse(&["aws", "--role-arn", "arn:aws:iam::1:role/y"]).identity.selects(&m));
        assert!(!parse(&["gcp", "--email", "a@b"]).identity.selects(&m));
    }

    #[test]
    fn hosted_marks_an_enclave_identity() {
        let parse = |args: &[&str]| Enclave::try_parse_from(std::iter::once("enclave").chain(args.iter().copied()));
        let cs = parse(&["confidential-space", "--project-number", "456", "--service-account", "t@h", "--hosted"])
            .unwrap()
            .identity;
        let m = cs.matcher().unwrap();
        assert_eq!(m.hosted(), Some(HostedMode::Sessions));
        assert!(cs.as_ref().selects(&m).unwrap(), "revoking ignores the hosted mark");
        let azure = ["azure", "--object-id", "oid", "--entra-tenant", "t", "--audience", "api://seal"];
        let m = parse(&[&azure[..], &["--hosted"]].concat()).unwrap().identity.matcher().unwrap();
        assert_eq!(m.hosted(), Some(HostedMode::Sessions));
        assert!(DeploymentRef::Azure { object_id: "oid".into() }.selects(&m).unwrap());
        assert_eq!(parse(&azure).unwrap().identity.matcher().unwrap().hosted(), None);
        assert!(parse(&["aws", "--role-arn", "arn:aws:iam::1:role/x", "--role-id", "A", "--hosted"]).is_err());
        assert!(parse(&[&azure[..], &["--hosted", "sessions"]].concat()).is_err());
    }
}

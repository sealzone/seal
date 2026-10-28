# Example release configurations

The shape of a deployment's release configurations, with placeholder hosts, project and
registry names (`example.com`, `example-project`, `123456789012`, `sealexample.azurecr.io`).
Tests parse these files, and the Dockerfiles' usage lines build from them.

| File | Compiled into | Build argument |
| --- | --- | --- |
| `enclave.json` | the enclave image | `RELEASE_CONFIG` of `enclave.Dockerfile` (`SEAL_RELEASE_ENCLAVE_CONFIG`) |
| `guardian-gcp.json`, `guardian-azure.json` | each guardian image | `RELEASE_CONFIG` of `guardian.Dockerfile` (`SEAL_RELEASE_GUARDIAN_CONFIG`) |
| `trust.json` | every config above, and SDK builds with `SEAL_RELEASE_TRUST` (production SDKs use `crates/sdk/seal-client/release-trust.json`) | |
| `aci.template.json`, `aci-policy.rego` | an Azure confidential container group for the enclave, and its policy as `seal-release aci-policy` writes it | |
| `guardian-aci.template.json` | an Azure confidential container group for the guardian (`seal-release aci-policy --component guardian`; set `image` to the build first) | |

The trust keys in `trust.json` are the development release, witness and registrar keys.
A real deployment replaces every value here with its own.

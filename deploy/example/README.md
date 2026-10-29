# Example release configurations

These files show the shape of a deployment's release configurations. Hosts, project and
registry names are placeholders (`example.com`, `example-project`, `123456789012`,
`sealexample.azurecr.io`). Tests parse these files, and the usage lines in the Dockerfiles
build from them.

| File | Compiled into | Build argument |
| --- | --- | --- |
| `enclave.json` | the enclave image | `RELEASE_CONFIG` of `enclave.Dockerfile` (`SEAL_RELEASE_ENCLAVE_CONFIG`) |
| `guardian-gcp.json`, `guardian-azure.json` | each guardian image | `RELEASE_CONFIG` of `guardian.Dockerfile` (`SEAL_RELEASE_GUARDIAN_CONFIG`) |
| `trust.json` | every config above, and SDK builds with `SEAL_RELEASE_TRUST`. Production SDKs use `crates/sdk/seal-client/release-trust.json` instead. | |
| `aci.template.json`, `aci-policy.rego` | an Azure confidential container group for the enclave, and its policy as `seal-release aci-policy` writes it | |
| `guardian-aci.template.json` | an Azure confidential container group for the guardian (`seal-release aci-policy --component guardian`). Set `image` to the build first. | |

The keys in `trust.json` are the development release, witness and registrar keys. A real
deployment replaces every value here with its own.

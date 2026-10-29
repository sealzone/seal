# sealzone-cli: the `seal` command

Seal lets apps use secrets they never hold, because an attested enclave injects each secret
into the app's upstream traffic. The `seal` command seals secrets and administers a Seal
tenant.

## Install

```sh
pip install sealzone              # installs `seal` (with the Python SDK)
cargo install sealzone-cli        # or from source
```

## Example

```sh
seal login
seal use acme
seal secret --endpoint https://10.0.1.4:8443 --to https://api.openai.com/v1 --app checkout --header x-api-key > api.blob
```

`seal login` signs in to the console, and `seal use` picks the tenant. The CLI verifies the
tenant's root chain and state on your machine. `seal secret` then seals a secret for app
`checkout` and prints the blob. It reads the secret from the terminal or stdin, and it
verifies the enclave before it asks for the secret.

## Commands

```sh
# Anyone may seal without signing in. Name the tenant as its admins' `seal status` prints it.
seal secret --tenant acme@<root id> --endpoint https://10.0.1.4:8443 --to https://api.openai.com/v1 --app checkout

# Who may do what.
seal grant app checkout azure --object-id <oid> --entra-tenant <id> --audience api://seal
seal grant app checkout github --repo acme/api --environment production --repository-id <n> --owner-id <n>
seal settings integrity on critical suspend=3600
seal changes --watch              # proposals waiting for signatures, logged changes not yet in force

# Verify telemetry.
seal telemetry --receipts receipts.jsonl

# Deploy enclave replicas into your Azure subscription.
seal deploy azure --vnet app-vnet
```

The CLI builds every change on the verified state and shows it as classified differences.
The admins then sign it, in the console or here with `--key-file`, and the change is logged.

`seal --help` lists every command, and `seal COMMAND --help` explains each one. The
configuration (the selected tenant and URLs) lives in `$SEAL_HOME`, which defaults to
`~/.config/seal`. The console login is kept in the OS keychain. The CLI stores no admin key.

Source and documentation: <https://github.com/sealzone/seal>. Licensed under Apache-2.0.

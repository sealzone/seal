# sealzone-cli: the `seal` command

Seal secrets and administer a Seal tenant from the command line.

```sh
cargo install sealzone-cli        # installs `seal`
```

```sh
# Sign in to the console and pick the tenant; its root chain and state are verified here.
seal login
seal use acme

# Seal a secret for app `checkout` (read from the terminal or stdin); prints the blob.
seal secret --to https://api.openai.com/v1 --app checkout --header x-api-key > api.blob

# Who may do what: every change is built on the verified state, shown as classified
# differences, then signed by the admins (in the console, or here with --key-file) and logged.
seal grant app checkout azure --object-id <oid> --entra-tenant <id> --audience api://seal
seal grant app checkout github --repo acme/api --environment production --repository-id <n> --owner-id <n>
seal settings integrity on critical suspend=3600
seal changes --watch              # proposals waiting for signatures, logged changes not yet in force

# Verify telemetry, and deploy enclave replicas into your Azure subscription.
seal telemetry --receipts receipts.jsonl
seal deploy azure --vnet app-vnet
```

`seal --help` lists every command, `seal COMMAND --help` explains each. The configuration
(the selected tenant and URLs) lives in `$SEAL_HOME` (default `~/.config/seal`); the console
login is kept in the OS keychain, and the CLI stores no admin key.

Source and documentation: <https://github.com/sealzone/seal>. Licensed under Apache-2.0.

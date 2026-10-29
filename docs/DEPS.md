# Dependencies

Which crates Seal uses, which it writes itself, and which it refuses. The enclave and the
guardian are the trusted computing base: every crate compiled into them is code an attacker
may target, and the guardian's code can never change. So the rule is to use well-maintained
crates for anything hard, write small well-specified pieces ourselves, and keep the TEE images
small.

## Rules

1. **Use crates maintained by an organization**: RustCrypto, dalek-cryptography, rustls,
   tokio-rs, hyperium, rust-postgres, PyO3, AWS, Google. A single-maintainer crate needs a
   reason written here.
2. **Write it ourselves only when it is small and specified** (an RFC or a wire format), and
   ship it with the spec's test vectors and a `proptest` or fuzz target. Never hand-roll
   cryptographic primitives.
3. **One crypto generation.** RustCrypto, dalek and rand move together; every crate here uses
   the same generation (`rand_core` 0.10, `sha2` 0.11, `der` 0.8). A crate stuck on an older
   one is listed under "Known exceptions" with what ends it.
4. **No native crypto or TLS** (OpenSSL, native-tls) anywhere, and no C build (`aws-lc-rs`) in
   a TEE image: it makes reproducible builds harder, and the measurement is the binary.
5. **Versions live in one place**: the root `[workspace.dependencies]`. Crates opt in with
   `.workspace = true`, so a version is decided once.
6. **crates.io only**: no git or path dependencies outside the workspace.

## Use

| Need | Crate | Used by | Why this one |
| --- | --- | --- | --- |
| AEAD, KDF, MAC, hashes | `aes-gcm` 0.11, `hkdf` 0.13, `hmac` 0.13, `sha2` 0.11 | seal-crypto, seal-proto | RustCrypto; `aes-gcm` is NCC-audited |
| Signatures, key exchange | `ed25519-dalek` 3, `x25519-dalek` 3, `p256` 0.14, `p384` 0.14 | seal-crypto, seal-attest, seal-tee, seal-control (console control tokens: raw Ed25519 over the payload bytes received, not a Seal signature) | dalek and RustCrypto |
| HPKE | `hpke` 0.15 (`x25519`, `aes`) | seal-crypto | RFC 9180 on RustCrypto, tested against the RFC vectors |
| RSA | `rsa` `=0.10.0-rc.19` | seal-crypto, seal-attest, seal-guardian | RS256 JWTs and AMD's RSA-PSS ARK/ASK; in the guardian's Key Vault source also RSA-OAEP (the ephemeral key of Secure Key Release, the wrapped root). A pinned release candidate (see exceptions) |
| AES key wrap with padding (RFC 5649) | `aes-kw` 0.3 | seal-guardian | RustCrypto, on the same `aes`. Key Vault wraps a released key with it |
| Randomness | `rand` 0.10 | seal-crypto, seal-tee, seal-adapter-pg (its own cancel keys) | Functions take `&mut impl CryptoRng`; the IO edge passes `UnwrapErr(SysRng)` |
| Constant time, wiping | `subtle`, `zeroize` | seal-crypto, seal-proto, seal-control, seal-registrar | |
| CBOR | `ciborium` 0.2 | seal-proto, seal-attest | Serde-based; `coset` needs it too (see watch list) |
| X.509 | `x509-cert` 0.3, `der`, `spki` | seal-crypto, seal-attest | Same ecosystem as the crypto. Its builder signs with deterministic `p256` for `TlsKey`'s byte-identical certificate |
| COSE | `coset` | seal-attest | Google; parses Nitro attestation documents |
| SNP device | `sev` 8 (`snp` only, default features off) | seal-tee | VirTEE. The `/dev/sev-guest` ioctl only. Its crypto features pull OpenSSL or the old generation, and it re-encodes reports before hashing, so `seal-attest` parses and verifies reports itself and the SDK never pulls it in |
| TLS | `rustls` 0.23 (`ring`), `tokio-rustls`, `webpki-roots` | seal-net, seal-client, seal-control (inbound) | `ring` over `aws-lc-rs` for reproducible builds |
| HTTP | `hyper` 1, `hyper-util`, `http-body-util` | seal-net, adapters, enclave, guardian, SDK | The HTTP stack everything else builds on |
| HTTP routing | `axum` 0.8 | seal-control, seal-enclave, seal-tlog (`dev` feature only, never in a TEE image) | tokio-rs. The guardian uses bare hyper: four routes, smallest code |
| Postgres wire protocol | `postgres-protocol` 0.6 | seal-adapter-pg | rust-postgres; includes SCRAM-SHA-256 for upstream authentication |
| AWS workload identity | `aws-sigv4`, `aws-config` | seal-client, `aws` feature only | Official. Large, so opt-in and never in a TEE |
| CLI | `clap` (`wrap_help`), `clap_complete`, `anstyle`, `rpassword`, `anyhow`, `jiff`, `tracing-subscriber` | seal-cli | clap-rs's own; `clap_complete` writes `seal completion`, `anstyle` styles output the way clap's help is styled; `jiff` parses times and durations. Spinner, tables and prompts are a few lines in `seal-cli/src/ui.rs` rather than `indicatif` or `dialoguer` |
| OS keychain | `keyring` 4 (default `v1`: Keychain Services, Windows Credential Manager, the Secret Service over `zbus`) | seal-cli | open-source-cooperative's; holds the console login (`sealcli_…`); hosts without a keychain fall back to a private file. Pure Rust on Linux (`zbus`, not libdbus), on the current RustCrypto generation. Never an admin key: the CLI stores none |
| Security keys (CTAP2 over USB HID) | `ctap-hid-fido2` 3.6 (on `ring`, `hidapi`) | seal-cli, `passkey` feature (default) | Single maintainer: the only CTAP2 client with neither OpenSSL nor NSS. `seal changes sign --passkey` gets an assertion from it, giving it the `clientDataJSON` as the challenge (it hashes that into the clientDataHash), and checks it with seal-crypto's own WebAuthn verifier. It pulls `x509-parser` for attestation certificates assertions never use (a scoped exception in `deny.toml`) and builds C `hidapi`, which needs libudev on Linux; never in a TEE |
| Python | `pyo3` 0.30 (abi3), built with `maturin` | seal-py | |
| Browser | `wasm-bindgen` (pinned exactly), `getrandom` 0.4 (`wasm_js`) | seal-verify-wasm, `wasm32` builds only | The wasm-bindgen organization's; the JS glue `wasm-bindgen-cli` writes must come from the same version, so the pin and `build.sh` keep them equal. `getrandom` is already in every tree through `rand`; `wasm_js` lets it build for the browser. Neither reaches a TEE image |
| Async, data, errors | `tokio`, `async-trait`, `serde`, `serde_json`, `bytes`, `base64`, `hex`, `url`, `thiserror`, `tracing` | everywhere | `tokio` without its `parking_lot` feature: `parking_lot` keeps every waiter in one process-wide table, which `fork()` copies mid-update, so a forked child (a Python prefork worker) could deadlock on its own new locks. Tokio's std locks are per object |
| Tests | `proptest` | seal-tlog, seal-tee, seal-crypto, seal-adapter, Postgres, Redis and ClickHouse adapters | Fuzzes the hand-written parsers |

Approved but not yet added: `testcontainers`, as a dev-dependency for sim integration tests
against Postgres, Redis and ClickHouse in Docker.

## Write ourselves

| Piece | Lives in | Size | Why not a crate | Must ship with |
| --- | --- | --- | --- | --- |
| JWS verification (RS256, ES256) | seal-crypto | ~100 lines on `rsa`/`p256` | `jsonwebtoken` pulls the previous crypto generation into the TEE. The algorithm is fixed per issuer, which rules out algorithm confusion by construction | RFC 7515 examples; tokens with a wrong `alg`, `kid` or `typ` are rejected |
| RFC 9162 Merkle proofs, C2SP checkpoints | seal-tlog | ~200 lines | No well-maintained crate | RFC 9162 vectors; proptest on proof generation and verification |
| SEV-SNP report parsing and verification (fixed AMD ABI offsets, VCEK binding, UVM endorsement) | seal-attest | ~400 lines on `p384`, `rsa`, `x509-cert`, `coset` | `sev` checks only chain and signature (no VCEK-to-report binding, validity or debug checks) and needs a third crypto stack to do that | Real ACI, Milan, Genoa and Turin reports (Microsoft sidecar and CCF test data); tampered reports and endorsements rejected |
| Redis RESP framing (AUTH/HELLO, relay) | seal-adapter-redis | ~400 lines | `redis-protocol` has a single maintainer and drags in `nom` and a pinned `cookie-factory`; `redis` is a whole client | proptest round trips; malformed frames never panic |
| ClickHouse native protocol: handshake, query decoding and refusal rules, a per-type insert-block decoder (specified in the crate docs; the adapter is a stub) | seal-adapter-clickhouse | ~1,500 lines, estimated | `clickhouse` speaks HTTP, not the native protocol; `klickhouse` is barely used | Captured sessions from real servers; proptest on the block decoder; CI against ClickHouse LTS servers × clickhouse-client, clickhouse-go and clickhouse-driver at `REVISION_CAP` |
| Roughtime client (RFC 10049, plus the draft profiles live servers still speak) | seal-tee | ~700 lines on `ed25519-dalek` | `roughenough` has almost no users | Captured live responses for each pinned profile; RFC 10049 Appendix B only with a note that it is signed with draft labels |
| WebAuthn ES256 assertion check | seal-crypto | ~60 lines on `p256` | `webauthn-rs` is heavy and uses OpenSSL | WebAuthn spec examples; flag and RP ID checks |
| Azure, GCP, GitHub, Kubernetes token fetches | seal-client, seal-cloud, seal-tee (the Confidential Space launcher socket, a small HTTP/1.1 client with a proptest) | ~20 lines each on hyper | One GET each does not need a cloud SDK | Recorded responses |
| Key Vault Secure Key Release (MAA request, release, `key_hsm` unwrap, release JWS check, release policy check) | seal-guardian | ~400 lines on `rsa`, `aes-kw` and rustls' webpki | `azure_security_keyvault` is a large SDK, and nothing verifies the JWS or the policy | A fake vault wrapping keys as Key Vault does; refused policies, JWSs and copies |

## Avoid

| Crate | Reason | Use instead |
| --- | --- | --- |
| `openssl`, `openssl-sys`, `native-tls` | Native code, separate patch cycle | rustls, RustCrypto |
| `aws-lc-rs` in a TEE | C/cmake build; reproducibility | `ring` (the SDK's `aws` feature may pull it) |
| `reqwest` | More than we need, and its own TLS defaults | `hyper-util` with Seal's pinned rustls config |
| `jsonwebtoken` | Previous crypto generation in the TEE | Hand-written JWS above |
| `x509-parser` | nom-based, different ecosystem | `x509-cert` |
| `rcgen` | Adds `yasna` and `time`; a second X.509 stack | `x509-cert` builder |
| `webauthn-rs` | Heavy, OpenSSL | `p256` |
| `azure_identity` and other cloud SDKs | Large trees for one HTTP call | Hand-written fetches |
| `aws-nitro-enclaves-cose` | OpenSSL | `coset` |
| `serde_cbor` | Unmaintained (RUSTSEC-2021-0127) | `ciborium` |
| `redis-protocol`, `klickhouse`, `roughenough` | Single maintainer or barely used | Hand-written pieces above |

`deny.toml` bans the crates in this table, so adding one fails `cargo deny check`.

## Known exceptions

| Exception | Cost | Ends when |
| --- | --- | --- |
| `rsa` is a release candidate, pinned exactly (`=0.10.0-rc.19`), and pulls `pkcs1` `0.8.0-rc.5` | No compatibility promise between RCs: every bump is manual and may break the API. Chosen over stable 0.9, which pulled the previous crypto generation (about a dozen duplicate crates) into every TEE | `rsa` 0.10 is stable: switch to `"0.10"`. Before the guardian's first release, ship the newest RC only if its verify and OAEP paths are reviewed; otherwise go back to 0.9 for that release |
| `rsa` advisory RUSTSEC-2023-0071 (Marvin) | A timing side channel on private-key operations. Seal's only ones are the guardian's Key Vault source: blinded RSA-OAEP decryptions, one with a fresh ephemeral key per boot and one per wrapped root with the released key. The attack needs many timed decryptions of chosen ciphertexts; a wrapped root is a boot input, but each try costs a container start and an attested key release, and every failure gives the same error. Still open in 0.9 and the 0.10 RCs | Fixed upstream or `rsa` replaced |
| `option-ext` (MPL-2.0) through `sev` → `dirs` | File-level copyleft on an unmodified crate, in `seal-tee` only (never the SDK) | `sev` drops `dirs` |
| `zvariant`, `zvariant_derive`, `zbus_names` unmaintained (RUSTSEC-2026-0370..0372) through `keyring` → `secret-service` → `zbus` 5 | Standalone crates zbus 6 merged; still fixed upstream through zbus 5. In the CLI only, for its keychain login on Linux | `secret-service` (and its keyring store) moves to zbus 6 |

## Watch list

- **`ciborium`**: no release since January 2024, but widely used and needed by `coset`. If
  it is marked unmaintained, move Seal's own encoding to `minicbor` and keep `ciborium`
  only behind `coset`.
- **`rsa` 0.10**: 19 release candidates since mid-2025 and no announced date. Check each RC's
  changelog before bumping the pin.
- **`ring`**: last release March 2025. It also pulls `getrandom` 0.2 next to 0.4. If it stops receiving fixes, switch rustls to a
  pure-Rust provider rather than `aws-lc-rs`.
- **TEE size**: the enclave pulls about 205 external crates and the guardian about 180,
  mostly tokio and hyper. The guardian can never change, so shrinking
  its set (fewer tokio features, no axum, no seal-net) is worth doing before its first
  release.

## Checks

`scripts/check-deps.sh` runs both checks, locally and in CI:

1. **`cargo deny check`** (`deny.toml`): RustSec advisories (this covers `cargo audit`),
   licenses, the banned crates above, and crates.io as the only source. Each accepted
   advisory or license exception names its reason.
2. **TEE budget**: the external crates in `seal-enclave` and `seal-guardian`, built as the
   image builds them, must equal `tee-deps/<crate>.txt`. A new crate in a TEE fails the check
   until someone reviews it and commits the updated list (`scripts/check-deps.sh --update`).
   No crate from the "Avoid" list may ever appear there.

## Builds

- The toolchain is pinned in `rust-toolchain.toml`; bump it deliberately, with a release.
- `Cargo.lock` is committed; every build uses `--locked`.
- TEE images are built one package at a time (`cargo build --locked --release -p
  seal-enclave`), never workspace-wide. Cargo unifies features across every package in one
  build, so a workspace build would let the SDK's `aws` feature switch rustls' `aws-lc-rs`
  backend on inside the enclave.
- Image builds download nothing. `scripts/vendor.sh` writes `cargo vendor --locked` output to
  `vendor/` (not committed; cargo checks every vendored crate against `Cargo.lock`'s
  checksums), and `deploy/{enclave,guardian}.Dockerfile` build from it with `--frozen` in a
  `RUN --network=none` step, on a base image that already holds the pinned toolchain. So an
  image rebuilds from the repository, its `Cargo.lock` and the digest-pinned base images, to
  the same digest.

## Adding or upgrading a crate

1. Check it against the rules above, and prefer a crate already listed.
2. Add the version to the root `[workspace.dependencies]` and `.workspace = true` in the crate.
3. Add a row to "Use" (or "Write ourselves"), with why.
4. Run `scripts/check-deps.sh`. If a TEE set changed, review the new crates and commit the
   updated `tee-deps/` list in the same change.

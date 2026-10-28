# Test vectors

Real evidence from real chips and Microsoft's real signing chain, used by `tests/azure.rs`
and `src/azure/tests.rs`. Unless noted, files are byte-identical to their source.

| Files | Source | License | What |
| --- | --- | --- | --- |
| `aci/snp_report.bin`, `aci/uvm_host_amd_certificate.json`, `aci/body.uvm_reference_info.bin`, `aci/uvm_security_policy.base64` | [microsoft/confidential-sidecar-containers](https://github.com/microsoft/confidential-sidecar-containers) `pkg/attest/test_data/` at `722a981ae2e9b961501d5890b67e231750536e99` | MIT, notice below | One confidential container group on production Azure (Milan): the SNP report, `host-amd-cert-base64` (VCEK, ASK, ARK), `reference-info-base64` (legacy UVM endorsement, svn 22) and the security policy whose SHA-256 is the report's `host_data` |
| `aci-genoa/snp_report.bin`, `aci-genoa/host-amd-cert-base64`, `aci-genoa/reference-info-base64`, `aci-genoa/transparent-reference-info-base64`, `aci-genoa/security-policy-base64`, `aci-genoa/kds_vcek.der` | Captured by Seal on 2026-10-27T05:43:04Z (`1793079784`) from a confidential container group in eastus (Genoa) by `seal_tee::azure`'s `live_capture` test | This repository's (the certificates and Microsoft's endorsements are public) | The report for report data SHA-256(`seal-dev-azure capture`), the security context files byte for byte, and the VCEK AMD's KDS served for the same chip and TCB. The policy lists the capture container and ACI's three infra containers (`atlas-mount-resolv-conf`, `msi-atlas-adapter`, `atlas-netstats`) without fragments; its SHA-256 is the report's `host_data` |
| `ccf/{milan,genoa,turin}_attestation.bin`, `ccf/{milan,genoa,turin}_endorsements.pem`, `ccf/v2_format_milan_attestation.bin` | [microsoft/CCF](https://github.com/microsoft/CCF) `src/pal/test/snp_attestation_validation_data.h` at `23380cd0b763c42450c16798271c5dffb36d35ee`, extracted: `ds::from_hex(...)` arrays hex-decoded, `R"(...)"` PEM strings verbatim | Apache-2.0 | SNP reports from Milan, Genoa and Turin (versions 3, 3, 5) with their `[VCEK, ASK, ARK]` bundles, and a version-2 Milan report |
| `ccf/uvm_0.2.9.cose`, `ccf/uvm_0.2.10.cose`, `ccf/int_svn.cose`, `ccf/rsa_test1.cose`, `ccf/ecdsa_test1.cose` | microsoft/CCF `tests/uvm_endorsements/` at the same commit | Apache-2.0 | UVM endorsements: legacy (0.2.9: svn 103; `int_svn`: 102; `rsa_test1`: 100, matching the version-2 Milan report), CWT (0.2.10: svn 104), and a ConfAKS one (`ecdsa_test1`: EKU `…59.1.5`, feed `ConfAKS-AMD-UVM`) |
| `kds/v2_milan_vcek.der` | AMD KDS, `https://kdsintf.amd.com/vcek/v1/Milan/dc7e37cc9b95b4d072ec4c6ebcabeaf98a6655b2e692768f9eb79e0fe1fa9d6c70b1d0a251757dcd48b360d660f89bbf228ef9f99003014c6d534a681473ea07?blSPL=3&teeSPL=0&snpSPL=8&ucodeSPL=115`, fetched 2026-10-26 | Public certificate, served by AMD to anyone without terms | The VCEK for the chip and REPORTED_TCB of `ccf/v2_format_milan_attestation.bin`, valid 2026-10-26 to 2033-10-26 |
| `virtee/report_milan.hex`, `virtee/vcek_milan.der` | [virtee/sev](https://github.com/virtee/sev) `tests/certs_data/` in the `sev` 8.0.0 crate | Apache-2.0 | A Milan report whose `report_data` uses all 64 bytes (refused by Seal), and its VCEK |
| `gcp/tdx.jwt`, `gcp/tdx-two-nonces.jwt`, `gcp/tdx-no-nonce.jwt`, `gcp/sev.jwt` | Recorded 2026-10-27 on Confidential Space VMs in project `seal-512903` (`us-central1-a`, production image `confidential-space-261000`), service account `seal-dev-gcp@…`: `c3-standard-4` TDX and `n2d-standard-2` SEV | Google-issued tokens; no secrets | PKI tokens for audience `https://seal.zone/attestation`. `tdx.jwt` and `sev.jwt` came from `seal_tee`'s attestor (`seal-cloud/examples/confidential_space_probe.rs`, report data 0..32); the others from `curl` on the launcher socket with two nonces and none. The image is `capture:probe` (`sha256:58c94f8c…`) |
| `gcp/tdx-debug.jwt`, `gcp/sev-debug.jwt` | The same, on the debug image `confidential-space-debug-261000`, image `capture:curl` (`sha256:c0b7df5a…`) | Google-issued tokens; no secrets | One nonce each, `dbgstat: enabled` |
| `gcp/test-ca/` | Generated with `openssl` 3.5 for these tests | This repository's | Synthetic chains shaped like Google's (RSA-2048, SHA-256): `root`, `intermediate`, `leaf` and the leaf's private key (`leaf-key.pkcs1.der`, test only), plus `other-root` with `other-intermediate`, a `not-ca-intermediate`, an `expired-leaf` and an `other-key-leaf` |
| `nitro/tpm.cbor` | Recorded 2026-10-28T05:39:46Z on a `c7i.large` EC2 instance in us-east-1, booted from Amazon Linux 2023 (`al2023-ami-2023.12.20261026.1-kernel-6.1-x86_64`) registered with `--tpm-support v2.0 --boot-mode uefi`, by `nitro-tpm-attest` from `aws-nitro-tpm-tools` 1.1.2 | AWS-issued document; no secrets (the instance is terminated) | A NitroTPM document with nonce `sealnonce-0123456789abcdef0123456789abcdef` and user data `sealuserdata`, kept exactly as the tool wrote it. The same AMI on a `t3.micro` has NitroTPM but cannot make a document (`NV_DefineSpace` refuses the tool's 8 KiB buffer) |
| `nitro/test-ca/` | Generated with `openssl` 3.5 for these tests | This repository's | Synthetic chains shaped like AWS's (P-384, ECDSA SHA-384): `root`, `intermediate`, `leaf` (common name `i-0123456789abcdef0-tpm0123456789abcdef.us-east-1.aws`) and its private scalar (`leaf-key.raw`, test only), plus `other-root`, a `not-ca-intermediate` with `under-not-ca-leaf`, an `expired-leaf`, an `other-key-leaf` and an `other-cn-leaf` |
| `sim/evidence.cbor` | Generated: `seal_attest::sim::sign` of the document in `tests/sim.rs` | This repository's | Frozen simulator evidence |

Every Azure test checks at 2026-10-26T07:33:20Z (`1793000000`), when all the VCEKs above are
valid, except the `aci-genoa` capture, checked at its capture time. Microsoft's endorsement
chains are checked at each endorsement's signing time. Confidential Space tokens last one
hour: the GCP tests check at 2026-10-27T05:53:20Z (`1793080400`), when every recorded token
and test certificate is valid. The NitroTPM document's leaf lasts three hours: the Nitro tests
check at its `timestamp`, 2026-10-28T05:39:46Z (`1793165986`).

Tokens are kept exactly as the launcher returned them (header, claims and signature). To
record new ones, run an image holding the probe on a Confidential Space VM with
`tee-container-log-redirect=true` (the image needs the label
`tee.launch_policy.log_redirect=always` on the production image) and reassemble the
`SEAL_PROBE token` lines from the serial console.

## MIT notice (microsoft/confidential-sidecar-containers)

```
Project name: Confidential Sidecar Containers

Copyright (c) Microsoft Corporation.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The Apache-2.0 files (microsoft/CCF: Copyright (c) Microsoft Corporation; virtee/sev: The
VirTEE Project Developers) are redistributed unmodified apart from the hex decoding noted
above, under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), the
license of this repository.

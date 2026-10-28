# Baked vendor roots

## AMD SEV-SNP

AMD's root (ARK) and signing key (ASK) for each chip family, compiled into
`seal_attest::azure`. Evidence carries only the VCEK, so the family is whichever of these
ASKs verifies it. Every file here is part of the guardian, enclave and SDK builds, so a
change produces new measurements and needs an M-of-N release. Files are kept byte-identical
to their source: two PEM certificates each, ASK first, then the self-signed ARK.

| File | Source | SHA-256 | Contents |
| --- | --- | --- | --- |
| `milan_cert_chain.pem` | https://kdsintf.amd.com/vcek/v1/Milan/cert_chain (fetched 2026-10-26) | `22e62f8d2c21a156470145fc75f7b5a377cb053ced3e97f0bd3f8d8ca5941ce6` | `CN=SEV-Milan` (2020-10-22 to 2045-10-22), `CN=ARK-Milan` (2020-10-22 to 2045-10-22) |
| `genoa_cert_chain.pem` | https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain (fetched 2026-10-26) | `e6ecc853fa56d3170a624d40851f98a1036f974b50204ea69e6aec91d777aca3` | `CN=SEV-Genoa` (2022-10-31 to 2047-10-31), `CN=ARK-Genoa` (2022-01-26 to 2047-01-26) |
| `turin_cert_chain.pem` | https://kdsintf.amd.com/vcek/v1/Turin/cert_chain (fetched 2026-10-26) | `cc9a52fbed3fbc6e4a0a50149a541a75938f975658909c2a6084767829b36e85` | `CN=SEV-Turin` (2023-05-15 to 2048-05-15), `CN=ARK-Turin` (2023-05-15 to 2048-05-15) |

All six are RSA-4096 and sign with RSASSA-PSS (SHA-384, MGF1-SHA-384, salt 48). Bergamo and
Siena chips use the Genoa keys.

To update or add a family: fetch `cert_chain` from the KDS URL above, check that it holds
exactly the `SEV-<family>` ASK followed by the self-signed `ARK-<family>` and that a real
VCEK of that family verifies against it, add the file unchanged, and update the hashes here
and in `azure::report::tests::baked_roots`.

## Google Confidential Space

`confidential_space_root.pem` is Google's Confidential Space Root CA, the root of every
attestation token of type PKI, compiled into `seal_attest::gcp`. A token's `x5c` ends with
this exact certificate. Kept byte-identical to its source (one PEM certificate, no trailing
newline). Google rotates it every 10 years; a new root is a new verifier release.

| File | Source | SHA-256 of the file | SHA-256 of the DER (fingerprint) | Contents |
| --- | --- | --- | --- | --- |
| `confidential_space_root.pem` | https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt (fetched 2026-10-27, `last-modified` 2024-06-13) | `1e9f82db6b86371f80913f246049516a9dc333e28fb1bf3e343d3459347e0d11` | `148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39` | `CN=Confidential Space Root CA, OU=Google Cloud, O=Google LLC` (2024-01-19 to 2034-01-16), RSA-4096, self-signed with SHA-256 |

To update: fetch the URL above, check that the certificate is self-signed and is the last
`x5c` entry of a real token, add it unchanged, and update the hashes here and in
`gcp::tests::baked_root_matches_google`.

## AWS Nitro

`aws_nitro_root_g1.pem` is AWS's Nitro attestation root (G1), the root of every Nitro
Enclaves and NitroTPM attestation document, compiled into `seal_attest::nitro`. A document's
`cabundle` starts with this exact certificate. Kept byte-identical to `root.pem` in the zip.
Its lifetime is 30 years.

| File | Source | SHA-256 of the file | SHA-256 of the DER (fingerprint) | Contents |
| --- | --- | --- | --- | --- |
| `aws_nitro_root_g1.pem` | `root.pem` in https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip (fetched 2026-10-28) | `6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0` | `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`, as AWS publishes it | `CN=aws.nitro-enclaves, OU=AWS, O=Amazon, C=US` (2019-10-28 to 2049-10-28), P-384, self-signed with ECDSA SHA-384 |

To update: fetch the zip, check the fingerprint against AWS's documentation and that the
certificate is `cabundle[0]` of a real document, add it unchanged, and update the hashes here
and in `nitro::tests::baked_root_matches_aws`.

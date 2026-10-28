# Baked upstream CAs

Trust anchors compiled into `seal_net::baked_roots()` on top of the Mozilla set
(`webpki-roots`). Every file here is part of the enclave image, so any change produces a
new measurement and needs an M-of-N release. Files are kept byte-identical to their source.

| File | Source | SHA-256 | Contents |
| --- | --- | --- | --- |
| `aws-rds-global-bundle.pem` | https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem (fetched 2026-10-26) | `90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b` | 114 self-signed Amazon RDS regional root CAs (RSA2048, RSA4096, ECC384 G1), valid to 2061–2126 |

Not needed here, because the Mozilla set already includes them: DigiCert Global Root G2
and Microsoft RSA/ECC Root Certificate Authority 2017 (Azure Database for PostgreSQL,
Azure Cache for Redis), and Amazon Root CA 1–4 (ElastiCache).
DigiCert Global Root CA (G1) is deliberately absent: it is not in the Mozilla set
(`webpki-roots` 1.0.11), and current Azure server certificates chain to G2.

To update: fetch from the source above, check that every certificate is a self-signed
`OU=Amazon RDS` CA, replace the file unchanged, update the hash and count here and in
`tests::baked_roots_load`.

# A guardian image: one per (served platform, platform it runs on), frozen once that platform
# ships. On ACI its layers are in the container policy whose hash (host_data) the Key Vault
# release policy pins; on Confidential Space its digest is its measurement and what the Cloud
# KMS workload identity provider pins. So the build is reproducible: base images pinned by
# digest, the toolchain pinned by rust-toolchain.toml, crates from vendor/ with no network, the
# release configuration compiled in, paths remapped, timestamps rewritten to
# SOURCE_DATE_EPOCH, no provenance or SBOM attestations. Build from the repo root on an x86_64 builder:
#
#   scripts/vendor.sh
#   docker buildx build -f deploy/guardian.Dockerfile \
#     --build-arg RELEASE_CONFIG=deploy/example/guardian-azure.json \
#     --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
#     --provenance=false --sbom=false --platform linux/amd64 \
#     --output type=registry,name=<registry>/guardian-azure:<tag>,rewrite-timestamp=true .
#
# On ACI, `seal-release aci-policy --component guardian` writes the container policy for
# deploy/example/guardian-aci.template.json; its env rules let the operator set the same four
# variables. The launch policy (Confidential Space reads these labels; they are part of the
# digest): the operator may set the wrapped roots, ask for the root ceremony, or run a
# succession (the predecessor's URL and the control plane's), nothing else; logs may be
# redirected, since the ceremony and succession print their result there and the guardian logs
# no secret.

# rust:1.99.0-slim-trixie: the toolchain rust-toolchain.toml pins, so rustup downloads nothing.
FROM rust@sha256:2752b332db73fdbb7dc576f06c82ed1f312005784ef913d7e04a28f5f55dc581 AS build
ARG RELEASE_CONFIG
ARG SOURCE_DATE_EPOCH
WORKDIR /src
COPY . .
# The toolchain comes from the image (rust-toolchain.toml would also ask for clippy and rustfmt).
ENV RUSTUP_TOOLCHAIN=1.99.0 \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/src=/seal -C link-arg=-Wl,--build-id=none"
RUN test -n "$RELEASE_CONFIG" && test -f "$RELEASE_CONFIG" \
 && { test -d vendor || { echo "run scripts/vendor.sh first" >&2; exit 1; }; } \
 && { grep -qx "channel = \"$(rustc --version | cut -d' ' -f2)\"" rust-toolchain.toml \
      || { echo "the base image's toolchain is not the one rust-toolchain.toml pins" >&2; exit 1; }; }
RUN --network=none --mount=type=cache,target=/src/target \
    SEAL_RELEASE_GUARDIAN_CONFIG="$RELEASE_CONFIG" cargo build --release --frozen \
        --config 'source.crates-io.replace-with="vendor"' --config 'source.vendor.directory="vendor"' -p seal-guardian --bin seal-guardian \
 && install -m 0755 target/release/seal-guardian /seal-guardian

FROM gcr.io/distroless/cc-debian13@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e
LABEL "tee.launch_policy.allow_env_override"="SEAL_GUARDIAN_WRAPPED_ROOTS,SEAL_GUARDIAN_CEREMONY,SEAL_GUARDIAN_SUCCEED_FROM,SEAL_GUARDIAN_RELEASES"
LABEL "tee.launch_policy.log_redirect"="always"
# Confidential Space opens only the ports the image exposes.
EXPOSE 7400
COPY --from=build --chmod=0755 /seal-guardian /seal-guardian
CMD ["/seal-guardian"]

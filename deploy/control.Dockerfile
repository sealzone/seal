# The control plane, the registrar and the dev transparency log, as images from one build.
# Base images are pinned by digest; bump them deliberately. Build from the repo root:
#
#   docker build -f deploy/control.Dockerfile --target control  -t seal-control .
#   docker build -f deploy/control.Dockerfile --target tlog-dev -t seal-tlog-dev .
#   docker build -f deploy/control.Dockerfile --target registrar -t seal-registrar .
#
# CONTROL_FEATURES=sim lets the control plane and registrar reach loopback http:// upstreams (staging next
# to the dev log); production builds leave it empty.

FROM rust@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src
COPY . .
ARG CONTROL_FEATURES=""
RUN cargo build --release --locked -p sealzone-control --bin seal-control ${CONTROL_FEATURES:+--features $CONTROL_FEATURES} \
 && cargo build --release --locked -p sealzone-tlog --features dev --bin seal-tlog-dev \
 && cargo build --release --locked -p seal-registrar --bin seal-registrar ${CONTROL_FEATURES:+--features $CONTROL_FEATURES}

FROM gcr.io/distroless/cc-debian13@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e AS control
COPY --from=build /src/target/release/seal-control /usr/local/bin/seal-control
ENTRYPOINT ["/usr/local/bin/seal-control"]

# Development and staging only: one operator key and in-process witnesses.
FROM gcr.io/distroless/cc-debian13@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e AS tlog-dev
COPY --from=build /src/target/release/seal-tlog-dev /usr/local/bin/seal-tlog-dev
ENTRYPOINT ["/usr/local/bin/seal-tlog-dev"]

FROM gcr.io/distroless/cc-debian13@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e AS registrar
COPY --from=build /src/target/release/seal-registrar /usr/local/bin/seal-registrar
ENTRYPOINT ["/usr/local/bin/seal-registrar"]

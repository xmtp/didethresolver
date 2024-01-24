FROM ghcr.io/xmtp/rust:latest as builder

USER xmtp

RUN sudo apt update && sudo apt install -y pkg-config openssl libssl-dev

RUN sudo mkdir -p /xmtp
RUN sudo chown -R xmtp:xmtp /xmtp

WORKDIR /build
COPY --chown=xmtp:xmtp . .

ENV PATH=~xmtp/.cargo/bin:$PATH
ENV USER=xmtp

ENV CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-1}
RUN cargo check --all-features
RUN cargo fmt --check --all
RUN cargo clippy --all-features --no-deps -- -D warnings
RUN cargo test --package=resolver --bin=resolver
RUN CARGO_TARGET_DIR=/build/target cargo install --root /xmtp --path resolver --bin=resolver
RUN strip /xmtp/bin/resolver
RUN cp CHANGELOG.md /xmtp/
RUN cp LICENSE /xmtp/

FROM debian:stable-slim
ARG TARGETARCH

RUN export DEBIAN_FRONTEND=noninteractive && \
  apt update && \
  apt install -y -q --no-install-recommends \
    ca-certificates apt-transport-https \
    && \
  apt clean && \
  rm -rf /var/lib/apt/lists/*

COPY --from=builder /xmtp/ /xmtp/

RUN useradd -s /dev/null none

EXPOSE 8080

ENV USER=none
USER none

ENV RUST_LOG=info
CMD ["/xmtp/bin/resolver", "--host", "0.0.0.0", "--port", "8080"]

LABEL org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.name="didethresolver" \
    org.label-schema.description="Ethereum DID resolver" \
    org.label-schema.url="https://github.com/xmtp/didethresolver" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="git@github.com:xmtp/didethresolver.git" \
    org.label-schema.vendor="xmtp" \
    org.label-schema.version=$VERSION \
    org.label-schema.schema-version="1.0" \
    org.opencontainers.image.description="Ethereum DID Resolver Container"

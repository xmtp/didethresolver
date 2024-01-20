FROM ghcr.io/xmtp/rust:latest
ARG CARGO_INCREMENTAL
ARG PROJECT=didethresolver
WORKDIR /workspaces/${PROJECT}

RUN sudo apt update && sudo apt install -y pkg-config openssl libssl-dev

USER xmtp
ENV USER=xmtp
ENV PATH=/home/${USER}/.cargo/bin:$PATH
# source $HOME/.cargo/env

COPY --from=ghcr.io/xmtp/foundry:latest /usr/local/bin/anvil /usr/local/bin/anvil

COPY --chown=xmtp:xmtp . .

ENV CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-1}
RUN cargo fmt --check --all
RUN cargo clippy --all-features --no-deps -- -D warnings
RUN cargo test --workspace --all-features

CMD cargo run

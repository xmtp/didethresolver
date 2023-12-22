FROM ghcr.io/xmtp/rust:latest

ARG PROJECT=didethresolver
WORKDIR /workspaces/${PROJECT}

RUN sudo apt update && sudo apt install -y pkg-config openssl libssl-dev

USER xmtp
ENV USER=xmtp
ENV PATH=/home/${USER}/.cargo/bin:$PATH

# source $HOME/.cargo/env

COPY --chown=xmtp:xmtp . .

RUN cargo fmt --check
RUN cargo clippy --all-features --no-deps
# Skip integration tests
RUN cargo test --lib
RUN cargo test --doc
RUN cargo test --examples

CMD cargo run

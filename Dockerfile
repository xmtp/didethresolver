FROM ghcr.io/xmtp/rust:latest

ARG PROJECT=didethresolver
WORKDIR /workspaces/${PROJECT}

USER xmtp
ENV USER=xmtp
ENV PATH=/home/${USER}/.cargo/bin:$PATH
# source $HOME/.cargo/env

COPY --chown=xmtp:xmtp . .

RUN cargo fmt --check
RUN cargo clippy --all-features --no-deps
RUN cargo test
CMD cargo run

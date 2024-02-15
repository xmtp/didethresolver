FROM ghcr.io/xmtp/rust:latest
ARG PROJECT=didethresolver
ARG CARGO_INCREMENTAL

WORKDIR /workspaces/${PROJECT}

RUN sudo apt update && sudo apt install -y pkg-config openssl libssl-dev

USER xmtp
ENV USER=xmtp
ENV PATH=~${USER}/.cargo/bin:$PATH
# source $HOME/.cargo/env

COPY --from=ghcr.io/xmtp/foundry:latest /usr/local/bin/anvil /usr/local/bin/anvil

COPY --chown=xmtp:xmtp . .

RUN yamlfmt -lint .github/workflows/*.yml

ENV CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-1}
RUN cargo check --all-features
RUN cargo fmt --check --all
RUN cargo clippy --all-features --no-deps -- -D warnings
RUN cargo test --workspace --all-features
RUN CARGO_TARGET_DIR=/workspaces/${PROJECT}/target cargo install --path resolver --bin=resolver --root ~${USER}/.cargo/
RUN valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose ~${USER}/.cargo/bin/resolver --help

ENV RUST_LOG=info
CMD cargo run --package=resolver -- --host 0.0.0.0 --port 8080

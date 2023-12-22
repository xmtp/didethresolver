FROM ghcr.io/xmtp/rust:latest

ARG PROJECT=didethresolver

RUN sudo apt update && sudo apt install -y pkg-config openssl libssl-dev


WORKDIR /build
RUN git clone https://github.com/foundry-rs/foundry

ARG MAXIMUM_THREADS=2
WORKDIR /build/foundry
RUN git pull && LATEST_TAG=$(git describe --tags --abbrev=0) || LATEST_TAG=master && \
    echo "building tag ${LATEST_TAG}" && \
    git -c advice.detachedHead=false checkout nightly && \
    . $HOME/.cargo/env && \
    THREAD_NUMBER=$(cat /proc/cpuinfo | grep -c ^processor) && \
    MAX_THREADS=$(( THREAD_NUMBER > ${MAXIMUM_THREADS} ?  ${MAXIMUM_THREADS} : THREAD_NUMBER )) && \
    echo "building with ${MAX_THREADS} threads" && \
    cargo install --path crates/anvil --jobs ${MAX_THREADS}

WORKDIR /workspaces/${PROJECT}
USER xmtp
ENV USER=xmtp
ENV PATH=/home/${USER}/.cargo/bin:$PATH

# source $HOME/.cargo/env

COPY --chown=xmtp:xmtp . .

RUN cargo fmt --check
RUN cargo clippy --all-features --no-deps
# Skip integration tests for now
RUN cargo test --lib
RUN cargo test --doc

CMD cargo run

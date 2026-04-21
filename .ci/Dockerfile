FROM rust:1-slim-trixie AS builder

RUN apt-get update && \
    apt-get install -y git curl wget iproute2 iputils-ping jq strace build-essential python3 libusb-1.0-0 file aha asciidoctor pkg-config libssl-dev && \
    apt-get clean

RUN cargo install --git https://github.com/embassy-rs/cargo-batch cargo --bin cargo-batch --locked
RUN cargo install probe-rs-tools --git https://github.com/probe-rs/probe-rs --locked --features remote

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y git curl wget iproute2 iputils-ping jq strace build-essential python3 libusb-1.0-0 file aha asciidoctor pkg-config libssl-dev libclang-dev && \
    apt-get clean

RUN \
    gem install asciidoctor-multipage

RUN \
    curl -o /usr/bin/rustup https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init && \
    chmod +x /usr/bin/rustup && \
    ln -s /usr/bin/rustup /usr/bin/cargo && \
    ln -s /usr/bin/rustup /usr/bin/cargo-clippy && \
    ln -s /usr/bin/rustup /usr/bin/cargo-fmt && \
    ln -s /usr/bin/rustup /usr/bin/cargo-miri && \
    ln -s /usr/bin/rustup /usr/bin/clippy-driver && \
    ln -s /usr/bin/rustup /usr/bin/rust-gdb && \
    ln -s /usr/bin/rustup /usr/bin/rust-lldb && \
    ln -s /usr/bin/rustup /usr/bin/rustc && \
    ln -s /usr/bin/rustup /usr/bin/rustdoc && \
    ln -s /usr/bin/rustup /usr/bin/rustfmt

RUN \
    curl -L -o /usr/bin/kubectl https://dl.k8s.io/release/v1.27.2/bin/linux/amd64/kubectl && \
    chmod +x /usr/bin/kubectl

RUN \
    curl -L -o gh.tar.gz https://github.com/cli/cli/releases/download/v2.34.0/gh_2.34.0_linux_amd64.tar.gz && \
    tar xzvf gh.tar.gz && \
    cp gh_2.34.0_linux_amd64/bin/gh /usr/bin && \
    rm -rf gh_2.34.0_linux_amd64 gh.tar.gz


COPY --from=builder /usr/local/cargo/bin/* /usr/bin

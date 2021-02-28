FROM debian:stable-slim
WORKDIR /src
RUN apt-get update && apt-get install curl openssl libssl-dev make gcc pkg-config -y
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --default-host x86_64-unknown-linux-gnu
RUN $HOME/.cargo/bin/rustup update
COPY . /src
RUN $HOME/.cargo/bin/cargo clean
RUN $HOME/.cargo/bin/cargo build --release

FROM docker.io/debian:stable-slim AS builder

RUN apt-get update && apt-get install curl openssl libssl-dev make gcc pkg-config -y
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --default-host x86_64-unknown-linux-gnu
ENV PATH="/root/.cargo/bin:${PATH}"

COPY . /build

WORKDIR /build
RUN cargo build --release

FROM docker.io/debian:stable-slim
RUN apt-get -y update && apt-get -y install ca-certificates openssl
RUN mkdir /app

WORKDIR /app/
COPY --from=builder /build/target/release/mass-acme /app/

VOLUME /app/config

ENTRYPOINT ["/app/mass-acme", "/app/config/config.json"]

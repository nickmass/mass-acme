FROM alpine:edge
WORKDIR /src
RUN apk --no-cache --upgrade add rust cargo openssl openssl-dev make
COPY . /src
RUN cargo clean
RUN cargo build --release

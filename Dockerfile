FROM rust:1-buster as builder

WORKDIR /app
RUN USER=root cargo new dodyndns
WORKDIR /app/dodyndns
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release && rm target/release/deps/dodyndns*

COPY src ./src
RUN cargo install --locked --path .

FROM debian:buster-slim

EXPOSE 8080

RUN apt-get update && apt-get -y install openssl ca-certificates
COPY --from=builder /usr/local/cargo/bin/dodyndns .

ENTRYPOINT ["./dodyndns"]

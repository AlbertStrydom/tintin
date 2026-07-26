# syntax=docker/dockerfile:1
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev

WORKDIR /app
COPY . .

RUN cargo build --release -p tintin-server

# ── Runtime ──────────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache ca-certificates libgcc

COPY --from=builder /app/target/release/tintin-server /usr/local/bin/

EXPOSE 9666

VOLUME ["/data"]
ENV TINTIN_DB_PATH=/data/tintin-server.db

ENTRYPOINT ["tintin-server"]

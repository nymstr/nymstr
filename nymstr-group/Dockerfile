# syntax=docker/dockerfile:1

FROM rust:1.86 as builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       pkg-config \
       libssl-dev \
       libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       libssl3 \
       libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/app/target/release/nymstr-groupd /usr/local/bin/nymstr-groupd

ENV DATABASE_PATH=storage/groupd.db \
    KEYS_DIR=storage/keys \
    LOG_FILE_PATH=logs/groupd.log \
    SECRET_PATH=secrets/encryption_password \
    NYM_SDK_STORAGE=storage/groupd \
    NYM_CLIENT_ID=groupd

RUN mkdir -p storage keys logs secrets

CMD ["nymstr-groupd"]

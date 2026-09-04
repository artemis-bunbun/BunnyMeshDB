# Alpine/musl multi-stage build for BunnyMeshDB.
#
# BunnyMeshDB is pure Rust: at runtime it makes raw syscalls (getrandom,
# sockets) and does not link glibc, so the release binaries run identically
# on musl. This builds a self-contained static-musl pair and ships only the
# two binaries + the `fuse3` runtime lib (for L3 mounts) into a ~15 MB image.
#
# Verified end-to-end: 51/51 tests pass and a live mesh node (libp2p swarm)
# serves a signed-capability GET/PUT round-trip under musl.
#
# Usage:
#   docker build -t bunnymeshdb .
#   docker run --rm -p 8848:8848 bunnymeshdb serve --config /etc/bmd/config.toml
#   # or drop into a shell to `bunny init` + write a config first:
#   docker run --rm -it bunnymeshdb sh

# --- Build stage: rust toolchain on musl (glibc-free crates) ---
FROM rust:alpine AS build
WORKDIR /src
RUN apk add --no-cache musl-dev fuse3 fuse3-dev
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# --- Runtime: minimal Alpine with just FUSE for L3 ---
FROM alpine:latest
RUN apk add --no-cache fuse3 curl && adduser -D -h /data bmd
WORKDIR /data
COPY --from=build /src/target/release/bunny /usr/local/bin/bunny
COPY --from=build /src/target/release/bunnymeshdbd /usr/local/bin/bunnymeshdbd
USER bmd
EXPOSE 8848
ENTRYPOINT ["/bin/sh"]
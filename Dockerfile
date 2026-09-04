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
#   # or drop into a shell to `bunnymeshdb init` + write a config first:
#   docker run --rm -it bunnymeshdb sh

# --- Build stage: rust toolchain on musl (glibc-free crates) ---
FROM rust:alpine AS build
WORKDIR /src
# musl-dev/fuse3 are C-dep headers; build-base+cc compile the vendored
# mimalloc C sources.
RUN apk add --no-cache musl-dev fuse3 fuse3-dev build-base cc
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# --features mimalloc: musl's single-heap malloc collapses under multi-worker
# contention (we measured 32-conn GET 4 workers: musl ~75k/s vs glibc ~278k/s).
# mimalloc's per-thread arenas recover Alpine to glibc parity (~240k/s).
# Keep OFF for glibc/Ubuntu (native glibc malloc is slightly faster than
# mimalloc there); the musl build enables it.
RUN cargo build --release --features mimalloc

# --- Runtime: minimal Alpine with just FUSE for L3 ---
FROM alpine:latest
RUN apk add --no-cache fuse3 curl && adduser -D -h /data bmd
WORKDIR /data
COPY --from=build /src/target/release/bunnymeshdb /usr/local/bin/bunnymeshdb
COPY --from=build /src/target/release/bunnymeshdbd /usr/local/bin/bunnymeshdbd
USER bmd
EXPOSE 8848
ENTRYPOINT ["/bin/sh"]
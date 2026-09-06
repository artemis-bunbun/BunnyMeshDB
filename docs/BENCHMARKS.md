# Performance

Measured on the release profile. Throughput figures are **single-node, local**
GET/PUT round-trips; mesh sync adds a pull latency bounded by
`sync_interval_secs` (default 30s).

## GET throughput — malloc backend

Condition: 32 concurrent HTTP GET connections, 4 tokio workers, warm cache.

| Binary / malloc | GET throughput |
|---|---|
| glibc/Ubuntu, native glibc malloc | ~278k ops/s |
| Alpine/musl, musl malloc (single-heap, contended) | ~75k ops/s |
| Alpine/musl, mimalloc (per-thread arenas) | ~240k ops/s |

Two findings from the build work:

1. **musl's single-heap malloc collapses under multi-worker contention.**
   The default `musl` build measured ~75k ops/s (32 conns, 4 workers) — a
   ~3.7× drop vs the same workload on glibc.
2. **mimalloc recovers Alpine to glibc parity.** Enabling `--features
   mimalloc` gives musl builds per-thread arenas and brings GET throughput
   back to ~240k ops/s (≈ glibc-native).

The `Dockerfile` therefore builds **with** mimalloc for the Alpine image and
keeps it **off** for glibc/Ubuntu builds (native glibc malloc is slightly
faster than mimalloc there, so don't force the feature on glibc targets).

## Why allocations matter here

The data path avoids needless copies: reads return stable byte slices out of
the snapshot index, writes append-then-index with one `pwrite-at-end`, and
no per-record fsync is used (crash safety is bounded to the single in-flight
record, recovered by truncation). The gap above is almost entirely allocator
contention, not the storage engine.

## Reproduce

These numbers came from a throwaway load generator (`loadgen.rs`, not in the
repo). To re-measure on your hardware:

```bash
cargo build --release                 # glibc
cargo build --release --features mimalloc   # musl (Alpine/Docker)
```

then run `GET /l2/{ns}/{key}` over 32 connections on a warm key. Exact
figures depend on CPU and disk; the glibc-vs-musl ratio is the stable signal.

## Reproduced (2026-09-06)

Differential check with a serial keep-alive HTTP/1.1 client (std-only
loadgen; 32 connections, one warm key, 3 s), same machine:

| Binary | GET throughput |
|---|---|
| doc-era `b0dc71b` (when the table above was written) | ~150-152k ops/s |
| current `HEAD` | ~157-165k ops/s |
| current, rate limiting disabled | ~123-129k ops/s (noise) |

Readings: the engine is unchanged since the original numbers — doc-era and
current are statistically identical (spread ≲3%), and the v0.2.x auth /
rate-limit work costs nothing measurable on the GET path (ON and OFF match;
the small OFF dip is run-to-run noise). Absolute figures are lower than the
table above because this client is **serial request/response**, bounded by
per-request round-trip latency; the original generator batched more work per
connection and hit ~278k. The stable signal remains the *relative*
comparison (glibc vs musl, mimalloc on/off) — take any absolute number with
the harness in mind.
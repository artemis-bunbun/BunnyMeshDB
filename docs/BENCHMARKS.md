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

## Reproduced (2026-09-06, corrected 2026-09-07)

Differential check with a serial keep-alive HTTP/1.1 client (std-only
loadgen; one warm key, 3 s), same machine, **authenticated with a real L2
capability and verified `200` responses** (an earlier draft of this section
measured the 403-forbidden path by mistake — a fixture bug where the seed
PUT used the L1 admin cap, which cannot write L2; auth-path cost dominates
both, so the numbers landed the same, but the corrected protocol below is
the honest one):

| Scenario | Throughput |
|---|---|
| doc-era `b0dc71b` (original numbers), 32 conns | ~150-152k GET/s |
| current `HEAD`, 32 / 64 / 128 conns | 155-157k GET/s (flat) |
| batch `POST /l2/{ns}/batch`, 100 ops × 8-16 conns | ~12.5-13.1M ops/s |
| batch, 300 ops × 4 conns | **~17.4M ops/s** |

Readings and caveats:
1. The engine is unchanged since the original numbers — doc-era and current
   are statistically identical. The serial client saturates a server-side
   per-request cost (auth verification + JSON + allocation) around ~155k
   GET/s regardless of connection count — the transport wall, not the
   storage engine.
2. **Batching is the throughput lever**: the pipelined batch endpoint moves
   the same per-request cost out of the per-op path (~100× on this
   harness). This is a GET on one warm key; write batches show the same
   shape.
3. The relative signal (glibc vs musl, mimalloc on/off) remains the stable
   comparison; absolute numbers depend on harness, CPU, and disk. Verify
   with your own client against a minted L2 cap, not the L1 admin cap.
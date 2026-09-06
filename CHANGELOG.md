# Changelog

## Unreleased

### Performance pipeline
- **HTTP/2**: axum now builds with the `http2` feature; the TLS listener
  advertises `h2` via ALPN (with `http/1.1` fallback). Verified live:
  `curl --http2` over TLS negotiates `http_version=2` and serves
  authenticated requests.
- **`POST /l2/{ns}/batch` + `/l3/u/{pk}/batch`**: pipelined batch ops —
  one capability verification, one rate-limit charge, one storage lock for
  up to 1000 ops. Reads observe a consistent batch prefix, per-op failures
  don't abort, read-only caps are refused (write-gated like `/ql`). Native
  client: **~17M ops/s batched (batch=300) vs ~155k serial GET/s — ~100×**
  on the same machine; per-op quota/schema/TTL still enforced. SDK:
  `DataClient.batch(ops)` → typed per-op results (`sdk/src/data.ts`).
- **Rate limiter striped** across 64 shards (global bound preserved) so
  distinct-token traffic no longer contends on one lock.

## v0.2.0

Ops polish + security hardening since `v0.1.0`, with expanded query power.

### Security
- **L3 authorization fix** (was unauthorized write/read to any `u/<pk>`):
  previously `auth_l3` derived the subject pk **from the URL**, so
  `is_l3_owner` was a tautology and the L3 "user sandbox" was completely
  open — any anonymous client could PUT/GET/scan any principal's namespace
  without holding its key. Now L3 requires a host-signed capability scoped
  to `u/<pk>` **bound to that principal** (subject == pk), verified through
  the same path as L2. The `u/<pk>` path alone is not a credential. The SDK
  `l3(pk)` mints the owner-bound cap. Verified live: anonymous write → 401,
  owner (minted cap) works, a cap for principal A → 403 on B's namespace.
- **HTTP `/ql` scope/privilege gate**: the ql DSL's `create_ns` (an L1/admin
  op) ran under any L2 write capability — any write-cap holder could create
  arbitrary namespaces (build `owned` namespaces / disk-fill); and a latent
  `use` scope-escape would let a narrow cap read outside its grant. The
  remote ql path now refuses `use`/`create_ns` (a `remote` flag on
  `QueryCtx`); the REPL keeps them (local trusted). Verified live: create_ns
  and use now return `query_error`, legit data fns still work, no rogue ns.
- **CI hardening**: in-crate `#![deny(warnings)]` replaces a brittle log-scan;
  fixed a hardcoded absolute path in the RN-compat test and a musl step that
  couldn't compile on stock runners; made mesh assertions deterministic.
- Found + fixed a latent mesh bug: `verify_batch` refused `TAG_SCHEMA`/`TAG_INDEX`
  records, silently blocking schema/index replication across peers.

### New
- **Secondary indexes + indexed queries**: define indexed fields (`/l1/.../index`
  or `index_create`), query with `by_index("field","value")`. Definition
  replicates; the index is derived from values on every peer, so `by_index`
  converges across the mesh without racing.
- **Root key rotation** (`bunnymeshdb rotate-key`): graceful roll keeping
  predecessors valid, or `--drop-predecessor` for compromise recovery;
  `--reissue-admin` keeps admin access. Offline op.
- **Rate limiting** (on by default, `node.ratelimit`), **live peer
  management** (`GET|POST|DELETE /l1/peers`), **metrics**, **auto-compact/
  TTL GC** (`node.gc_interval_secs`), resumable SSE, `durable_writes`.

Per-commit detail: `d9129b8` (indexes), `6e86a55`/`2a4b0c3`/`7946460`/`c977c8c`
(CI + ops), `51ac3c2` (mesh flakes).

## v0.1.0

First tagged release: the self-hosted, multi-master Rust engine + zero-dep
TypeScript SDK, with CI (cargo test + SDK typecheck) and static-musl release
binaries for x86_64 and aarch64.

### Storage engine
- Per-namespace merkle append-log (CRC32 + SHA-256 chain), no per-record
  fsync (crash-safe to the single in-flight record).
- Snapshot checkpointing (`index.snap`), hybrid logical clocks, LWW and
  `register` conflict policies, per-key TTL, `?versions=true`/`/conflicts`.
- **Log compaction / TTL GC** (`bunnymeshdb compact`): offline rewrite of each
  namespace log to the minimal records that reproduce current state — drops
  superseded versions and expired TTL rows, reclaiming disk that a
  TTL/churn-heavy workload would otherwise grow forever. Refuses a
  mesh-synced node (the log is the replication dedupe key; compaction is only
  safe standalone). Sequence numbers restart at 1.
- Multi-master sync over libp2p (pull-based), configurable
  `sync_interval_secs`.
- Alpine/musl Docker image with mimalloc (restores musl to glibc GET
  throughput parity).

### HTTP API
- L1 admin: namespaces, Ed25519 capability issue/revoke, per-namespace
  JSON-Schema set/get/clear.
- L2/L3 data routes (cap-authenticated): get/put/delete/scan, head, changes
  feed, conflicts, query DSL, Server-Sent-Events push (`/events`).
- Read-only capabilities can read; writes/DSL need `write`.

### SDK (`sdk/`)
- Zero-dependency TypeScript client; runs on Node ≥18, browsers, and React
  Native (pure-JS base64/UTF-8 fallbacks).
- get/put/delete/scan, TTL, head, changes, conflicts, subscribe (SSE), query
  DSL, schema admin, capability issuance.

### Operations
- `bunnymeshdb` CLI: init, backup, restore, repl, peers, compact.
- `bunnymeshdbd serve` self-initializes an uninitialized data dir (refuses to
  touch a corrupt one).
- **SSE change push with resume**: `GET /l2/{ns}/events?since=<seq>` replays
  the backlog then pushes live events, each tagged `id: <seq>`; the SDK
  auto-reconnects with backoff from the last seen seq, so no write is missed
  across a dropped connection.
- **Durable writes**: `node.durable_writes` (default false) fsyncs every
  append before acknowledging — the durability toggle for the no-per-record-
  fsync fast path.
- **Metrics**: `GET /metrics` — requests, writes, namespaces (lock-free).
- **Rate limiting**: on by default — `node.ratelimit = { enabled, max_requests,
  window_secs }` (600 req/token/60s default), 429 on breach, disable with
  `enabled = false`. Protected routes only (`/healthz`,`/metrics` open).
- **Live peer management**: `GET|POST /l1/peers`, `DELETE /l1/peers/{name}`
  — persists to the config file (shared `Arc<Mutex<Config>>` with the mesh
  engine, so edits reach the engine's next kick without a restart).
- **Auto-compact/TTL GC**: `node.gc_interval_secs` runs log compaction +
  expiry GC on a live daemon for standalone nodes (same safety guard as the
  CLI). Online mesh-node compaction deliberately deferred — it needs protocol
  fencing so a peer can't re-send a compacted record.
- TLS termination via tokio-rustls.

### Not yet (tracked)
- **Per-record durability toggle**: writes are not fsynced per record by
  default (a crash can lose the single in-flight write); a `durable_writes`
  option is a potential follow-up.
- OSI license stays AGPL-3.0; pricing/commercial tier not yet offered.

### Compatibility
Commit that added `TAG_SCHEMA` changed the on-disk log record set (the
`TAG_SCHEMA` append-only record). Pre-0.1.0 dev logs without schema records
are unchanged and still replay.

Full history: see git log. Repo: `github.com/artemis-bunbun/BunnyMeshDB`.
# Changelog

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

## unreleased

- **Secondary indexes + indexed queries**: define indexed fields per namespace
  (`/l1/namespaces/{ns}/index`, or `index_create` in `/ql`); the engine
  derives an in-memory secondary index from JSON-stored values and answers
  `by_index("field", "value")` in sorted order. The definition replicates
  through the mesh (an `index@`-style `TAG_INDEX` log record, mirroring
  JSON-Schema), and the index itself is derived from values on every peer —
  so `by_index` converges across nodes without racing (values converge →
  derived indexes converge). Index maintenance rides the put/delete/synced
  apply paths and rebuilds on open. 1 new unit test (65 total) + 4 integration
  assertions (18/18).
- **Root key rotation** (`bunnymeshdb rotate-key <data-dir>`): swap the active
  ed25519 keypair without bricking the deployment. Graceful mode keeps the
  previous key valid (a `RootKeyring` on the verification path accepts current
  + retired predecessors, so already-issued capabilities and records keep
  verifying; new caps mint with the fresh key). `--drop-predecessor` severs
  the old key — the compromise-recovery path where its caps are all invalid
  and must be re-issued; `--reissue-admin` re-signs the persisted admin cap so
  the operator isn't locked out. Persists retired keys in `sys/root_chain`;
  chain is written before meta.bin so a crash is re-runnable. Offline op
  (daemon stopped).
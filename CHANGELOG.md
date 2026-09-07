# Changelog

## v0.4.1

### Release engineering
- `softprops/action-gh-release` was 403ing ("Resource not accessible by
  integration") because the job's `GITHUB_TOKEN` was read-only. No GitHub
  Release was ever created — v0.1.0 through v0.4.1 tags shipped without
  attached binaries. The `build` job now grants `contents: write`
  explicitly; the v0.4.1 tag was re-cut to backfill its release. Node on
  both workflows is pinned to 24 (20 is deprecated on runners).
- Version consts bumped to 0.4.1: binaries built from this tag report
  `bunnymeshdb 0.4.1` / `bunnymeshdbd 0.4.1` (they previously said 0.4.0
  despite the tag).

### Residual audit closes + threat-model doc

- **ql no longer stalls the daemon (LOCK-ACROSS-BATCH-007 closed)**: the
  Query DSL now classifies each statement before taking a store lock —
  reads (`get`/`scan`/`by_index`/`index_fields`/…, including nested call
  args) run under a **read lock**; only statements containing a mutator
  (`put`/`del`/`index_create`/`index_drop`, even nested as an argument)
  take the write lock. A heavy authenticated read query can no longer
  block every other request. `QueryCtx.store` is now a read/write enum;
  a mutation reaching a read context fails closed by construction.
- **Per-peer namespace allow-list (MESH-002/record injection residual
  closed)**: a peer can now be scoped to contribute records to a
  **subset of shared namespaces** (`namespaces` on `POST /l1/peers`, or
  `add_peer`/config). Default remains "all shared namespaces" (today's
  behavior), but least-privilege mesh contribution is now possible —
  a pinned peer is no longer implicitly trusted across the whole store.
- **p2p_listen accepts a full multiaddr**: `/ip4/127.0.0.1/tcp/9002` binds
  loopback; a bare port keeps the legacy `0.0.0.0` wildcard bind
  (documented — prefer the explicit form in production).
- **SECURITY.md**: threat model, trust boundaries, attack classes,
  deployment notes, known residual boundaries, and the full audit-status
  table. The artifact that turns the v0.4.0 audit into a
  buy/procurement-ready security story.
- Tests: 88/88 cargo (+`classify` mutator detection incl. nested,
  read-context fails-closed, `add_peer` allow-list round-trip,
  duplicate-pin refusal).

## v0.4.0

### Security audit — capability, HTTP, mesh, FUSE (3 parallel audits, 26 findings)

First full security review of every attack surface (auth/HTTP, libp2p mesh
+ TOFU, FUSE). Fixed:

- **Capability forgery via nonce reuse (CRITICAL)** — the per-request
  capability cache was keyed by the attacker-visible `nonce`, so ANY cap
  holder could replay their nonce into a forged admin (or any-scope) cap
  with a garbage signature and be authorized; the signature check was
  skipped on the cached path. The cache is now keyed by a content digest
  (sha256 of the exact signed bytes); forged caps always re-verify the
  signature. Regression-tested.
- **Unauthenticated mesh Pull (CRITICAL)** — the libp2p listener served
  `Hello`/`Pull` to ANY reachable TCP peer, letting a remote node drain the
  entire store (all namespaces, bypassing capability auth) and forcing an
  unbounded log materialization (OOM). Inbound requests now require a
  configured + pinned peer (authenticated connection peer id cross-checked
  against the pin); pulls read a bounded record window per request.
- **GET `?prefix=` scan bypass (HIGH)** — auth was checked against the URL
  key's directory, not the query prefix, so a cap scoped to prefix `a`
  could scan sibling prefixes. The scan now authorizes the requested prefix
  itself.
- **FUSE read-back writes (HIGH)** — every file close committed the
  open-time preload, so a read-only open could resurrect deleted data,
  clobber concurrent writers, and grew the log on every read. Read-only
  opens no longer buffer or write; clean closes are no-ops; expired
  entries read as absent; truncate/append honor the handle buffer.
- **TOFU first-contact binding (MEDIUM)** — the pin was bound from the
  plaintext Hello `host_id`, so a MITM winning the first connection could
  permanently displace a peer's identity. The pin must now match the
  noise-authenticated connection peer id; peers can also be pre-seeded
  with a pin out-of-band; persistence failures escalate.
- **HLC same-ms collisions (MEDIUM)** — two writes in the same millisecond
  produced identical HLCs and the second was silently dropped by sync
  dedupe. `Hlc::now()` is a strictly-increasing process-wide issuer now.
- **Prefix-boundary scope escape (MEDIUM)** — `Scope::covers` used raw
  `starts_with`; cap prefix `a` covered sibling `ab`. Now segment-bounded.
- Rate limiter: junk `Authorization` headers now share the anon bucket
  (no unique-bucket evasion) and the bucket map has an absolute bound.
- Batch/feed hardening: batch GET responses are byte-capped, the changes
  feed is bounded per response, SSE catch-up is incremental (was O(n²)),
  batch/QL validation moved outside the global store lock, quota is
  charged only after schema validation, SSE streams are capped, `add_peer`
  rejects duplicate identities, and a single oversized record no longer
  wedges namespace sync.
- CLI/daemon: `--version` (`bunnymeshdb 0.4.0` / `bunnymeshdbd 0.4.0`).

### Batched log records (ingest-side batching)
- The batch endpoint (`/l2/{ns}/batch`, `/l3/u/{pk}/batch`) now writes
  **ONE merkle-log record per request** (`TAG_BATCH`, carrying up to 1000
  sub-ops) instead of N records. Log growth, replication payloads, snapshot
  replay, and mesh transfer all drop up to 1000× for bulk writes. Verified
  live: 1000-put batch → namespace head advances by exactly 1, all accepted
  writes share one seq, 1000/1000 ops committed.
- **Atomic batches**: one record = one dedupe identity, one change-feed/SSE
  event, one visibility boundary. Reads inside a batch observe the
  fully-applied batch (a get of a key a later op writes sees the final
  state) — documented in API.md; the changes feed flags batch records with
  `"batch": true` + `"ops"`.
- Batches whose serialized record would exceed ~6 MiB are refused up front
  (`413 batch_too_large`, nothing charged): a record that could not pass the
  mesh replication frame budget would wedge that namespace's sync.
- **Mesh replication fix**: a single log record larger than the 960 KiB
  sync-chunk budget previously stalled that namespace's replication forever
  (the chunk builder dropped it → empty chunk → infinite re-pull). The
  builder now sends oversized records alone; verified live with a 1.2 MiB
  value replicating node-to-node.
- **Base64 decode fix**: `b64_decode` now tolerates standard `=` padding;
  previously any padded base64 value (i.e. anything produced by a normal
  ecosystem encoder) was rejected as an invalid char. Unpadded inputs still
  decode.

## v0.3.0

Performance pipeline: batching, HTTP/2, limiter striping.

### Performance pipeline
- **HTTP/2**: axum now builds with the `http2` feature; the TLS listener
  advertises `h2` via ALPN (with `http/1.1` fallback), and plaintext
  listeners accept h2 by prior knowledge (h2c) as well — both verified
  live (`curl --http2` / `--http2-prior-knowledge` negotiate version 2 and
  serve authenticated requests).
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
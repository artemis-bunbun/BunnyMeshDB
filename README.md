# BunnyMeshDB

A decentralized, multi-master database with libp2p mesh sync, capability-based
auth, and a zero-dependency TypeScript client. It stores its own data — no
rocksdb/redb/sled — and replicates via a signed append-only log.

Intended for self-hosted, offline-first, multi-node workloads: two or more
nodes that must keep converging without a central server.

## What it does

- **Multi-master sync.** Each node accepts writes independently (no leader).
  Nodes pull missing entries from peers over libp2p on a configurable interval.
- **Durable, verifiable storage.** A per-namespace merkle append-log with
  CRC32 + SHA-256 chain; snapshots checkpoint the index. Crash-safe within one
  in-flight record.
- **Timestamped replication.** Hybrid logical clocks order concurrent writes;
  default LWW converges deterministically; `register` policy keeps every
  divergent version so you can reconcile.
- **Capability auth.** Ed25519-signed bearer capabilities scoped to a tier and
  namespace with `read`/`write`/`admin` perms. Revocable. Read-only caps can
  read.
- **Change feed + push.** Poll `changes?since=` for a gapless stream, or
  subscribe to real-time SSE push (`GET /l2/{ns}/events`) — including writes
  that arrive via mesh sync.
- **TTL, JSON-Schema, conflicts.** Per-key expiry (replicated), per-namespace
  JSON-Schema validation (replicated, enforced on every write), and a
  `/conflicts` surface for register-policy namespaces.
- **L3 filesystem (optional).** A FUSE mount backed by a namespace.

## Layout

```
src/         Rust engine (storage, HLC, merkle log, mesh, HTTP)
sdk/         TypeScript client (no runtime deps; also runs on React Native)
examples/    two-node mesh + docker-compose
docs/        architecture + performance
```

## Install

### From source

Requires a Rust toolchain.

```bash
cargo build --release
# -> target/release/bunnymeshdb (CLI), target/release/bunnymeshdbd (daemon)
```

### Docker

```bash
docker build -t bunnymeshdb .
docker compose up -d --build   # two mesh nodes in containers
```

~15 MB Alpine image (static-musl, mimalloc).

## Run a node

```bash
bunnymeshdb init ./data-dir              # creates ./data-dir/data (root keypair)

cat > config.toml <<'EOF'
[node]
name = "dev.bunnymeshdb.test"            # doubles as the scope authority
data_dir = "./data-dir/data"
listen = "127.0.0.1:8848"                # HTTP API
p2p_listen = "9100"                      # libp2p mesh
worker_threads = 4
mesh_sync = true
sync_interval_secs = 30                  # how often nodes pull from peers
[node.l3]
default_quota = 1048576
EOF

bunnymeshdbd serve --config config.toml
```

The daemon prints your admin capability on startup:

```
INFO bunnymeshdbd: admin cap: bmdb-cap:eyJzY29wZSI6…
```

`serve` will also initialize an empty data dir if the config points at one
that hasn't been initialized yet.

## Two-node mesh

See `examples/two-node/` for complete configs (localhost and compose). The
short version — node A and node B each list the other as a peer:

```toml
# config-a.toml
[node]
name = "node-a.bunnymeshdb.test"
data_dir = "./node-a/data"
listen = "127.0.0.1:8850"
p2p_listen = "9100"

[[peers]]
name = "node-b.bunnymeshdb.test"
addr = "/ip4/127.0.0.1/tcp/9101"

# config-b.toml mirrors this, with node-a as its peer
```

Writes on either node converge to the other within one sync interval.
Sync is pull-based: a node asks a peer for namespaces they share and pulls
what it is missing. No corruption is ever introduced by a tick; a bad
record is refused.

## Backup / restore

`bunnymeshdb backup <data-dir> --out <backup>` checkpoints then copies the
data dir. `bunnymeshdb restore <backup> --data-dir <target>` restores it into
a fresh dir.

**Capability caveat:** capabilities are scoped to the node authority in the
config `name`. Restoring to a node with the **same** `name` keeps existing
caps valid. Restoring to a node with a **different** `name` invalidates them
(reads return 403) — re-issue caps for the new host.

## SDK

```bash
cd sdk && npm run build    # -> dist/
```

```ts
import { BunnyMeshClient } from "./dist/index.js";

const client = new BunnyMeshClient("http://127.0.0.1:8848", "bmdb-cap:eyJ…");

await client.createNamespace("notes", "register");
const db = await client.openL2("notes");

await db.put("welcome", "hello");
const value = await db.getText("welcome");          // "hello"
await db.subscribe((ev) => console.log("write:", ev.seq)); // real-time push
```

Zero runtime dependencies; runs in Node ≥18, browsers, and React Native.
See `sdk/README.md` for the full surface.

## HTTP API

- `GET /healthz`
- Admin (L1, `admin` perm): namespaces, capability issue/revoke, JSON-Schema,
  secondary indexes (`GET|POST|DELETE /l1/namespaces/{ns}/index`).
- Data (L2 cap-authenticated): `GET/PUT/DELETE /l2/{ns}/{key}?ttl=&versions=`,
  `GET /l2/{ns}?prefix=`, `/head`, `/changes?since=`, `/conflicts`,
  `/events?since=` (SSE push, auto-resumes from the last seen seq),
  `/ql`.
- L3 (owner-identity-gated): `u/{pk}` variants of the data routes.
- `GET /metrics` (open): runtime counters — requests, writes, namespaces.

**Secondary indexes / query.** Values are JSON. Define indexed fields per
namespace (`POST /l1/namespaces/{ns}/index` with `["field", ...]`), then in
`/ql` query them: `by_index("city", "london")` returns keys whose value's
`city` field equals `"london"`, in sorted order. The index definition
replicates through the mesh; the index itself is derived from values on every
peer, so `by_index` answers identically everywhere. `/ql` also has
`get/put/del/scan/get_all`, `index_create/index_fields/index_drop`,
`use/create_ns`, `now/hlc/before/clock_skew`.

## Operations

- `bunnymeshdb backup|restore` — checkpoint + copy (see caveat above).
- `bunnymeshdb rotate-key <data-dir> [--drop-predecessor] [--reissue-admin]` —
  rotate the root ed25519 keypair (daemon stopped). By default the previous
  key stays valid so existing capabilities keep working (graceful roll);
  `--drop-predecessor` severs it — the compromise-recovery path where every
  cap it signed is invalidated and must be re-issued. `--reissue-admin`
  re-signs the persisted admin cap with the new key so you keep admin access.
- `bunnymeshdb compact <data-dir>` or config `node.gc_interval_secs` — reclaim
  disk on a TTL/churn-heavy **standalone** node: drop superseded versions and
  expired TTL rows. The CLI runs with the daemon stopped; `gc_interval_secs`
  runs it automatically on a live daemon. Both refuse a mesh-synced node
  (compaction is only safe single-node; online mesh GC needs protocol
  fencing). Sequence numbers restart at 1.
- Config: `node.durable_writes` (fsync every write), `node.sync_interval_secs`
  (mesh pull cadence), `node.gc_interval_secs` (auto-compact cadence, 0 off),
  `node.ratelimit` (on by default; disable with `{ enabled = false }`).

## Docs

- `docs/ARCHITECTURE.md` — storage, log, auth, mesh, sessions, L3.
- `docs/API.md` — full HTTP API reference (all routes, verbs, payloads).
- `docs/COMPARISON.md` — bunnymeshdb vs. SQLite/sync, CouchDB, Redis, hosted.
- `sdk/README.md` — full SDK surface.

## Documented performance

See `docs/BENCHMARKS.md` for measured throughput and memory under
single-node GET/PUT and multi-worker concurrency, including the musl-vs-glibc
difference and the mimalloc fix.

## License

AGPL-3.0
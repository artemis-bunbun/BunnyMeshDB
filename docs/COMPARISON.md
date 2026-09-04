# bunnymeshdb vs. the alternatives

Honest positioning. bunnymeshdb is a **self-hosted, offline-first,
multi-master key-value store** with a small, auditable engine. It is not, and
does not try to be, a general-purpose SQL/analytics database. Compare it
against the tool a developer would otherwise reach for.

## Where it wins

- **Offline-first multi-master.** Writes succeed on any node while peers are
  down; convergence is eventual via libp2p pull. SQLite + sync tooling (Litestream,
  turso, Dolt) and most hosted DBs require a central server or leader for
  writes — bunnymeshdb's leaderless model is the differentiator.
- **Capability-based auth.** Ed25519-signed, revocable, host-scoped bearer
  tokens. No user/password database; you share a capability string. Read-only
  caps genuinely read-only. This is closer to actor/object-capability models
  (like SDN or Matrix's authn) than SQLite's file perms or a hosted DB's
  IAM.
- **Small, auditable, self-contained.** Storage engine (merkle log, HLC,
  snapshotting), HTTP API, mesh sync, and FUSE all in ~thousands of lines of
  Rust with a curated dependency set (no rocksdb/redb/sled). A technical
  buyer can read the whole thing.
- **Ships as binaries.** Static-musl x86_64 + aarch64 release artifacts, ~15 MB
  Alpine image, no runtime dependencies. `bunnymeshdbd serve` self-initializes.
- **Real-time feed built in.** Gapless `changes?since=` poll + resumable SSE
  push, replicated TTL, JSON-Schema validation, conflict observation. These
  come out of the box rather than as add-ons.

## Honest tradeoffs

| Concern | bunnymeshdb | Crafted-for comparison (SQLite) |
|---|---|---|
| Throughput | ~240-278k GET/s single-node (mimalloc/musl) | SQLite similar order for reads, different workload |
| Concurrency model | Single-writer log append, snapshot index | Fine-grained queries, mature MVCC |
| Query language | Indexed DSL (`by_index`/`scan` + `ql`), no JOIN | Full SQL |
| Durability default | No per-record fsync (loss of last write on crash) unless `durable_writes` | Rollback journal / WAL, ACID |
| Conflict handling | LWW or multi-version register (optional) | N/A (single-writer) |
| Ecosystem | None yet (SDK + docs only) | Massive |
| Maturity | Pre-1.0, one maintainer | Decades |

## Specific comparisons

### vs. hosted (Firebase, Supabase, DynamoDB/MongoDB Atlas)
- **Pro:** self-hostable, no vendor lock-in, offline-capable, privacy (data
  never leaves your machines), sync-aware from day one (not a bolt-on).
- **Con:** you operate it; no managed uptime/SLA; far less querying/
  indexing/aggregation; no billing/metering/teams UI; tiny ecosystem.

### vs. SQLite + sync (Litestream, turso/libSQL, Dolt)
- **Pro:** true multi-master (not just replication to read replicas), conflict
  support (`register`/`versions`), capability auth, offline-first writes
  (not just resilient reads), and replicated **secondary indexes** with
  `by_index` — so a syncable app gets indexed point/equality reads without
  bolting on a relational engine.
- **Con:** no SQL, no MVCC, no rich transactions, no Azure/RDS-style managed
  offering. For an app that *needs* relational queries, SQLite + a sync layer
  is still the better fit.

### vs. CouchDB / Couchbase / CouchDB-style
- **Pro:** simpler model (plain KV, no map/reduce or views), capability
  bearer auth, HLC-based deterministic LWW, resumable SSE feed, zero external
  runtime deps.
- **Con:** CouchDB has mature MVCC/replication/`_changes` and decades of
  hardening; it's the reference for multi-master docs. bunnymeshdb is
  deliberately laser-narrow (KV) by comparison.

### vs. Redis / key-value stores
- **Pro:** persistence (snapshot + log), multi-master sync, capability auth,
  TTL with replication — things a bare in-memory KV lacks or does insecurely.
- **Con:** nowhere near Redis's in-memory speed/ops ecosystem/data types
  (lists, hashes, streams, pub/sub).

### vs. IPFS / DHT / libp2p stores
- **Pro:** content-addressing at app layer but with mutability: you get
  signed, revocable **mutable** records, not immutable CIDs. Authoritative
  host-scoped writes (not everyone-write CAS).
- **Con:** not content-addressed for dedup; relies on pull (no DHT discovery);
  no swarm-wide global namespace (scoped per host).

## When to choose bunnymeshdb

Best fits: an app that must **work offline and converge across a handful of
nodes you control** — local-first apps, edge/field deployments, self-hosted
*tools that want a syncable KV with real auth* and no external service. It
stands up in minutes with a config file and a capability string.

Avoid it for: relational workloads, multi-tenant SaaS that needs managed
uptime and rich queries, single-node apps that need ACID transactions, or
anything where you want a large ecosystem of drivers/orms. Use SQLite/Redis
(or a hosted DB) there.

## Verdict

bunnymeshdb trades SQL, MVCC, and ecosystem for three things most tools
treat as hard problems: **offline-first multi-master writes, capability-based
auth out of the box, and a source you can read end to end.** It is deliberately
narrow. Pick it when that narrowness matches the job; reach for a general-
purpose database everywhere else.
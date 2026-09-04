# BunnyMeshDB

**bunnymeshdb** is a decentralized, distributed, speed-first database with
multi-node mesh sync, capability-based auth, change feeds (poll + real-time
SSE push), per-namespace JSON-Schema validation, TTL, conflict observation,
and optional FUSE L3 filesystem mounts. It stores its own data (no
redb/sled/rocksdb) and syncs peers over libp2p.

```
src/         Rust engine (storage engine, HLC, merkle append-log, libp2p mesh)
sdk/         Zero-dependency TypeScript client (dist/ via `npm run build`)
examples/    two-node mesh + docker-compose
docs/        architecture
```

## Quickstart — run a node

```bash
cargo build --release

bunnymeshdb init ./data-dir          # generates ./data-dir/data (root keypair)
cat > config.toml <<'EOF'
[node]
name = "dev.bunnymeshdb.test"
data_dir = "./data-dir/data"
listen = "127.0.0.1:8848"
p2p_listen = "9100"
worker_threads = 2
mesh_sync = true
[node.l3]
default_quota = 1048576
EOF

bunnymeshdbd serve --config config.toml
# INFO bunnymeshdbd: admin cap: bmdb-cap:eyJzY29wZSI6…   <- your admin token
```

## Quickstart — two-node mesh

A mesh node pulls namespaces it has in common with each peer. Bring up two
nodes (see `examples/two-node/` for the full configs), then:

```bash
# node A (listen :8850) — create the namespace, issue a write cap
curl -X POST localhost:8850/l1/namespaces -H "Authorization: Bearer $ADM_A" \
  -H 'Content-Type: application/json' -d '{"name":"shared","policy":"register"}'
# …issue caps for scope bmdb://node-a…/l2/shared and bmdb://node-b…/l2/shared

curl -X PUT  localhost:8850/l2/shared/hello -H "Authorization: Bearer $CAP_A" -d 'hi'
curl localhost:8851/l2/shared/hello -H "Authorization: Bearer $CAP_B"
# → "hi"   (after the next 30s sync round)
```

Or `docker compose up -d --build` for the same two nodes in containers.

## Quickstart — SDK

```bash
cd sdk && npm run build   # produces dist/
```

```ts
import { BunnyMeshClient } from "./dist/index.js";
const client = new BunnyMeshClient("http://127.0.0.1:8848", "bmdb-cap:eyJz…");
client.createNamespace("notes", "register");
const db = await client.openL2("notes");
await db.put("welcome", "hello from the SDK");
await db.subscribe((ev) => console.log("write:", ev.seq)); // real-time push
console.log(await db.getText("welcome")); // "hello from the SDK"

// Optional per-namespace JSON-Schema (enforced on every put, replicated):
await client.setSchema("notes", { type: "object", required: ["title"] });
await db.put("post", JSON.stringify({ title: "A" })); // ok
await db.put("bad", "{}"); // → BunnyMeshError 400 schema_violation
```

## Container / Docker

`docker build -t bunnymeshdb .` → static-musl pair in a ~15 MB Alpine image
(with mimalloc). `docker-compose.yml` runs two mesh nodes.

## Docs

- `docs/ARCHITECTURE.md` — storage, log, auth, mesh, sessions, L3.
- `sdk/README.md` — full SDK surface.

## License
AGPL-3.0
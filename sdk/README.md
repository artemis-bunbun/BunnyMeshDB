# bunnymeshdb — TypeScript client for BunnyMeshDB

Zero-dependency TypeScript client for the BunnyMeshDB HTTP API — the
offline-first, multi-master sync engine. Covers the whole surface: admin
(namespaces, capability issuance), L2/L3 data (get/put/delete/scan), TTL,
change feed, conflict observation, and query DSL.

Works in Node ≥18 and modern browsers (uses `fetch` and `TextEncoder`).

## Install

```bash
npm install bunnymeshdb
```

(SDK lives in this repo under `sdk/`; `npm run build` produces `dist/`.)

## Quickstart

```ts
import { BunnyMeshClient } from "bunnymeshdb";

// The admin capability is printed at daemon startup:
//   INFO bunnymeshdbd: admin cap: bmdb-cap:eyJzY29wZSI6…
const client = new BunnyMeshClient("http://127.0.0.1:8853", "bmdb-cap:eyJzY29wZSI6…");

await client.createNamespace("notes", "register");

// Issue an L2 data capability and open the namespace:
const db = await client.openL2("notes"); // scope derived from admin cap

await db.put("welcome", "hello from the SDK");       // string
await db.put("blob", new Uint8Array([0, 1, 2, 250])); // or bytes
await db.put("temp", "expires in 10s", { ttl: 10 }); // replicated TTL

const v = await db.getText("welcome"); // "hello from the SDK"
const b = await db.get("blob");        // Uint8Array(4)
await db.delete("blob");

// Change feed — poll with since = previous head.seq for a gapless stream:
const { head, changes } = await db.changes();
for (const c of changes) console.log(c.seq, c.key, c.del ? "del" : "put");

// Binary payloads are returned as Uint8Array; decode strings with
// new TextDecoder().decode(bytes) or use getText().
```

## API

### `BunnyMeshClient(baseUrl, adminToken?)`
| method | description |
|---|---|
| `health()` | `GET /healthz` |
| `namespaces()` | list namespaces + policy |
| `createNamespace(name, policy?)` | policy: `"lww"` (default) or `"register"` |
| `issueCap({scope, perms?, expiryMs?, to?})` | returns `{cap, token}` — use `token` as the `Authorization` bearer value |
| `listCaps()` | capability ledger |
| `revoke(scope, to)` | revoke a subject's capability |
| `setSchema(ns, schema)` | set per-namespace JSON-Schema (replicated) |
| `getSchema(ns)` | active schema, or `null` when none is set |
| `clearSchema(ns)` | clear the schema (validation off) |
| `openL2(ns, opts?)` | issue an L2 cap (default `["read","write"]`) + return `DataClient`; `{ perms: ["read"] }` for a read-only client |
| `data(ns, capOrToken)` | `DataClient` from an existing capability |
| `l3(pk)` | `DataClient` for owner namespace `u/<pk>` (identity-gated) |

### `DataClient` (namespace operations)
| method | description |
|---|---|
| `get(key)` / `getText(key)` | fetch; `null` when missing/deleted/expired |
| `put(key, value, {ttl?})` | write; returns `{seq, expires_at}` |
| `delete(key)` | tombstone (appears in the change feed) |
| `scan(prefix?)` | keys + values + `expires_at` |
| `versions(key)` | every retained version (`?versions=true`) |
| `head()` | `{seq, hash}` — cheap poll point |
| `changes(since?)` | gapless `{since, head, changes[]}` stream |
| `subscribe(onEvent, signal?)` | live SSE push — one event per write, carrying the log head |
| `conflicts()` | register-policy keys with >1 divergent version |
| `ql(expr)` | query-DSL expression |

Errors: failed HTTP → `BunnyMeshError` (`status` + machine-readable `error`).
`get`/`head` return `null` on 404; everything else throws.

## Notes & quirks

- **Capability tokens are verbatim server JSON.** `issueCap` and `data(ns, token)`
  pass the server's token through unmodified — re-encoding a parsed capability
  object would corrupt the u64 `nonce` through JS number precision and break
  the signature. Prefer wire-token strings over object round-trips.
- **Reads need only `read`; writes need `write`.** GET routes (get/scan/head/
  changes/conflicts/subscribe) authorize on `read` alone, so a read-only cap
  can read; PUT/DELETE and the query DSL require `write`. `openL2` defaults to
  `["read","write"]`. (Previously every data route demanded both, so read-only
  caps got 403 — fixed.)
- **React Native.** The SDK runs on RN with no dependencies: its base64 and
  UTF-8 codecs fall back to pure-JS implementations (`sdk/src/compat.ts`) when
  `Buffer`/`atob`/`TextEncoder`/`TextDecoder` are absent, so the full non-
  streaming surface (get/put/scan/ql/head/changes/conflicts/schema) works
  unchanged. Live push `subscribe()` needs a `ReadableStream`-capable fetch,
  which RN's runtime does not provide — use `changes(since)` polling for
  real-time on RN (the method throws a clear, actionable error if you try).
- **JSON-Schema** (`setSchema`/`getSchema`/`clearSchema`) is a replicated,
  per-namespace server-side enforcement: the schema is a plain JS object, and
  `put()` payloads must conform or the write is rejected with 400
  `schema_violation`. The validated subset intentionally excludes `pattern`,
  `format` and `$ref` (no audited regex engine on the server); unsupported
  keywords are rejected at set time with 400 `unsupported_schema`, never
  silently skipped.
- **u64 precision.** HLC/nonce values beyond 2^53 arrive as strings (parsed
  through a safe reviver); `seq` is small and stays a number.
- Values are raw bytes: the server does **not** JSON-encode on the wire; use
  `Uint8Array`/strings and encode application JSON yourself.

## License
AGPL-3.0 (matches the server repository).
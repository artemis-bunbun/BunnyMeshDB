# HTTP API reference

All endpoints are relative to a node's HTTP `listen` address. Capabilities
are bearer tokens: `Authorization: Bearer bmdb-cap:…`. Admin (L1) routes need
`admin` on the L1 scope; data (L2) routes need `read` (GET) or `write`
(PUT/DELETE/QL); L3 routes are capability-gated too — the `u/{pk}` path alone
is not a credential, access needs a cap scoped to `u/{pk}` bound to that
principal.

`GET /healthz` and `GET /metrics` are open (no auth).

Request bodies are JSON unless noted; responses are JSON. Errors are
`{ "error": "<machine-code>: <detail>" }` with a 4xx/5xx status.
`get`/`head` on a missing key/namespace return null/404.

## Open

### `GET /healthz`
`{ "ok": true }`

### `GET /metrics`
Runtime counters (lock-free).
```json
{ "requests": 1234, "writes": 56, "namespaces": 3 }
```

## Admin (L1) — `admin` perm on the L1 scope

### `GET /l1/namespaces`
List namespaces: `[ { "name", "policy" } ]` (`lww` | `register`).

### `POST /l1/namespaces`
Body `{ "name", "policy"? }` (`register` for conflict-retaining).
409 `namespace_exists`, 400 `bad_request`.

### `GET|POST|DELETE /l1/namespaces/{ns}/schema`
JSON-Schema per namespace. GET → the schema (404 `no_schema`). POST → set
(body is the JSON-Schema; 400 `unsupported_schema` for pattern/format/$ref).
DELETE → clear.

### `GET|POST|DELETE /l1/namespaces/{ns}/index`
Secondary-index field list per namespace. GET → the active `["field",...]`
(404 `no_index`). POST → set (body is the JSON array of field names; `[]`
clears; 400 `bad_index_def`). DELETE → clear. The definition is replicated
through the log, so every mesh peer derives the same index from the same
values (the index itself is derived, never stored).

### `GET /l1/caps`
The capability ledger.

### `POST /l1/caps`
Issue a capability: `{ "scope", "perms"?, "expiry_ms"?, "to"? }`.
Returns the signed capability JSON. The wire token is
`bmdb-cap:` + unpadded base64url(cap JSON) — keep it verbatim.

### `POST /l1/revoke`
Body `{ "scope", "to" }` — revoke a subject's capability for a scope.

### `GET|POST /l1/peers`
Live peer management (persisted to the config file; the mesh engine dials them
on its next kick). GET lists `{ "peers": [ { "name", "addr", "pin" } ] }`;
POST adds `{ "name", "addr", "pin"? }` — `pin` optionally pre-seeds the TOFU
pin (the peer's 64-hex-digit host public key); when absent the pin is bound
on the first successful Hello (400 on invalid multiaddr or duplicate).

### `DELETE /l1/peers/{name}`
Remove a peer. 404 `peer_not_found`.

## Data (L2/L3)

L2: `Authorization: Bearer bmdb-cap:…` scoped `l2/{ns}`.
L3: `u/{pk}` namespace, `Authorization: Bearer bmdb-cap:…` scoped
`l3/u/{pk}` and bound to the owning principal (subject == `pk`).

### `GET|PUT|DELETE /{tier}/{ns}/{*key}`
- `GET` → raw value bytes (the value is **not** JSON-encoded by the server);
  404 `not_found` when missing/deleted/expired.
  - `?versions=true` → every retained version (`register` policy).
- `PUT` — body is raw bytes. `?ttl=<secs>` sets a replicated wall-clock
  expiry. Returns `{ "ok", "seq", "expires_at" }`. 400 `schema_violation`
  when a namespace schema rejects the payload.
- `DELETE` → tombstone (appears in the change feed).

### `GET /{tier}/{ns}?prefix=<bytes>`
Scan keys under a byte prefix → `{ "entries": [ { "key", "value_b64",
"expires_at" } ] }`.

### `GET /{tier}/{ns}/head`
`{ "seq", "hash" }` — cheap poll point. For scanning, see `GET /{tier}/{ns}`.

### `GET /{tier}/{ns}/changes?since=<seq>`
Gapless, lowest-seq-first stream of durable records:
```json
{ "since", "head": { "seq", "hash" }, "changes": [ { "seq", "key_b64",
"value_b64", "del", "ttl", "expires_at", "hlc", "batch", "ops" } ] }
```
A batch write appears as **one** change (it is one record): `"batch": true`
and `"ops"` = its sub-op count; `key_b64`/`value_b64` are empty for it. The
SSE events API (`/events?since=<seq>`) likewise emits one `change` event
per batch record.

The response is capped at **10,000 records** per poll: a client that falls
far behind simply pages by setting `since` to the last seq it saw. There is
no `more` flag — the array is silently truncated, so keep polling while the
response is full.

> **Retention** (FEED-RETENTION-010): the change feed replays *raw log
> records*, so it exposes historical values — including values of keys that
> were later overwritten or deleted — to anyone holding READ on the
> namespace, until the log is compacted offline (`compact`). Treat the feed
> as a full write-audit trail; a redaction option is planned.

### `GET /{tier}/{ns}/events?since=<seq>` (SSE)
Server-Sent Events change push with resume. Replays every record after
`since` (one `change` event per record, `id: <seq>`), then pushes live
events for local HTTP *and* mesh-applied writes. `retry:` hints reconnect.
Auto-resumes across dropped connections when the client passes the last seen
seq back as `since`.

Concurrent subscriptions are capped globally at **256** live streams; the
next connect is refused with `503 too_many_streams`. A slot is released when
the stream ends or the client disconnects.

### `GET /{tier}/{ns}/conflicts`
`register`-policy keys holding >1 divergent version, for reconciliation:
`{ "conflicts": [ { "key", "count", "versions" } ] }`.

### `POST /{tier}/{ns}/ql`
Query-DSL expression. `{ "expr" }`. Functions:
- `use(ns)`, `create_ns(ns)`, `now()`, `hlc()`, `before(a,b)`, `clock_skew(host)`
- `get(key)`, `put(key, value)` (`value` must be a JSON-encoded string; the
  DSL is string-typed), `del(key)`, `scan(prefix)`, `get_all(key)`
- Secondary indexes: `index_create("field", ...)`, `index_fields()`,
  `index_drop()`, and the indexed read `by_index("field", "value")` → keys
  whose value's `field` equals `value`, sorted. Define the index with the
  admin `/index` route (or `index_create`); values are JSON and the scalar
  field is extracted per value. Fields are only answerable once indexed.

### `POST /{tier}/{ns}/batch`
Pipelined batch (the throughput lever): one capability verification, one
rate-limit charge, one storage lock, and **one log record** for the whole
batch instead of per op. Body: `{ "ops": [ { op, key, ... } ] }`,
`1..=1000` ops, all in this namespace only (never cross-namespace).
Requires a **WRITE** capability on the namespace (like `/ql`) — read-only
caps get `403`; the same part is charged once.

The batch is **atomic**: it is appended as a single merkle-log record, so it
has one dedupe identity, one change-feed/SSE event, and one visibility
boundary — reads inside the batch observe the **fully-applied batch** (a
`get` of a key that a later op in the same batch writes sees the final
state, not a position-dependent prefix). A failing op is reported in place
and does not abort the batch (no rollback of earlier ops).
- `{ "op":"get", "key" }` → `{ ok:true, value_b64 }` (standard base64; a
  missing/expired key reads as `{ ok:true, value_b64:null }`). The
  cumulative decoded size of `get` results is capped at **8 MiB** per batch:
  the first `get` that would exceed it (and every `get` after it) fails with
  `{ ok:false, error:"batch_get_response_too_large" }` instead of
  materializing a multi-GB response
- `{ "op":"put", "key", "value_b64", "ttl"? }` → `{ ok:true, seq }`; quota
  and JSON-Schema are enforced per op
- `{ "op":"del", "key" }` → `{ ok:true }`
- anything else → `{ ok:false, error }` aligned by index

All accepted writes share the batch record's `seq` (all sub-ops are one
record). If the serialized batch record would exceed ~6 MiB the request is
refused with `413 batch_too_large` before anything is charged (a record
beyond the replication frame budget could not reach mesh peers).
Response: `{ "results": [ ... ] }` aligned with `ops`.

## Rate limiting

On by default: `node.ratelimit = { enabled, max_requests, window_secs }`
(default `{}`, 600 req/token/60s). Breaches return `429 rate_limited` on
protected routes (`/healthz`/`/metrics` are open). Disable with
`node.ratelimit = { enabled = false }`.
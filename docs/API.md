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
POST adds `{ "name", "addr" }` (400 on invalid multiaddr or duplicate).

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
"value_b64", "del", "ttl", "expires_at", "hlc" } ] }
```

### `GET /{tier}/{ns}/events?since=<seq>` (SSE)
Server-Sent Events change push with resume. Replays every record after
`since` (one `change` event per record, `id: <seq>`), then pushes live
events for local HTTP *and* mesh-applied writes. `retry:` hints reconnect.
Auto-resumes across dropped connections when the client passes the last seen
seq back as `since`.

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

## Rate limiting

On by default: `node.ratelimit = { enabled, max_requests, window_secs }`
(default `{}`, 600 req/token/60s). Breaches return `429 rate_limited` on
protected routes (`/healthz`/`/metrics` are open). Disable with
`node.ratelimit = { enabled = false }`.
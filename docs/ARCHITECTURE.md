# BunnyMeshDB — Architecture (draft v0.1)

## 1. Model: federated sovereign hosts

- A **host** is one deployment of BunnyMeshDB: a node with its own
  ed25519 **root keypair** and a name (`api.bunnymeshdb.test.com`, a mesh
  peer id, or any resolvable name).
- Every host is **sovereign root over its own namespaces**. There is no
  global L1: the trust root is always the host named in the URL.
  `api.bunnymeshdb.test.com/l1/...` is *that host's* L1; someone else's
  `api.other.net/l1/...` is theirs — same ladder, different root.
- A **network** is emergent: the set of hosts that peer with each other.
  Peering is per-host policy (allowlist by key/name, or open). Anyone can
  spin up their own host and their own network.
- Federation is protocol-level interop: any node can serve or request
  another host's namespaces when reachable and when capabilities verify.
  The identity/authorization layer is transport-agnostic.

## 2. Naming: the URL is the name

    bmdb://<host>/<tier>/<namespace>/<key>
    https://<host>/l1|/l2|/l3/<namespace>/<key>

- `<host>` = the authority whose root key must vouch.
- `<tier>` = access level (see §3).
- `<namespace>` = data scope, owned by the host.
- `<key>` = record key inside the namespace.

Host-to-key binding:

- Internet: DNS TXT record `bmdb-key=<base64url(ed25519 pub)>` for
  authenticated bootstrap (DANE-style).
- Mesh / offline: **TOFU** on first connect; pin the key together with the
  name. Key changes surface as visible events in the merkle log.

A name is identity-bearing: whoever resolutes the name claims the
namespace. Capabilities keep *data* safe even under name squatting;
squatting itself is a federation problem — mitigations are key pinning,
user-visible pin diffs, and cap chains that reference original-issuer keys.

## 3. Tiers: per-host authorization ladder

| Tier | Scope | Prerogatives |
|------|-------|--------------|
| L1 | host root | create namespaces, provision principals, issue capabilities, host config |
| L2 | delegated | read/write on namespaces where a signed capability grants it |
| L3 | user sandbox | auto-provisioned personal namespace; quota-bound; cannot mint capabilities |

- Tiers are **checks on capability chains rooted at the host key**,
  evaluated locally and offline. No global user database, no central admin.
- "L3 = people's own filesystems" falls out of the model: each principal
  gets a personal namespace scoped by their key. Access requires a
  host-signed capability whose **subject is that principal** and whose scope
  is the `u/<pk>` namespace — the `u/<pk>` path alone is not a credential.
- Absolute-privilege APIs live behind L1 and are host-local; they never
  replicate.

## 4. Records and time

Every write is a record:

    { key, value, hlc, replica, cap_chain }

- `hlc`: 64-bit **hybrid logical clock** (physical ms + per-node counter).
  Monotonic across hosts without trusting NTP; ordering + causality in
  8 bytes. SQLite HRT / CockroachDB HLC are the precedent.
- `replica`: originating host id — deterministic tiebreak.
- Per-namespace **merkle log**: each record hashes its predecessor; a
  namespace's head hash is the sync and verification boundary, so a forged
  or reordered timestamp is detectable even if a node's clock lies.
- Query functions: `now()`, `hlc()`, `before(a, b)`, `clock_skew(host)`.

## 5. Capabilities

    { scope: bmdb://<host>/l2|<l3>/<ns>[/<prefix>],
      perms: [read | write | admin],
      expiry, issued_by, chain[] }  signed ed25519

- Verification = walk the chain to the host root key. Local, offline, cheap.
- Capabilities are data: they live in a `sys/caps` namespace and sync via
  the merkle log like anything else — grants and revocations propagate
  with the mesh itself.

## 6. Sync and conflicts

- Peer config = per-host policy: which namespaces to replicate from whom.
- Sync unit = namespace. Exchange merkle head hashes, pull missing records.
- Conflict policy = per-namespace, chosen at creation:
  - last-writer-wins (HLC + replica) — default, simple
  - per-key CRDT (register/map/counter) — offline-friendly
  - merge-on-write — dev tooling
- Reachability: HTTPS for internet hosts; libp2p (transport, hole-punch,
  relay) for mesh hosts. Transport-agnostic above the wire protocol.

## 7. Open questions (not papered over)

- POSIX filesystem semantics (locks, renames, mmap) over L3 are brutal to
  distribute. v1 exposes key-value plus directory-like ops, not full POSIX.
- Quota enforcement without trusting a peer: host-local quotas are
  enforceable; cross-host quotas are advisory.
- Capability revocation in an offline mesh: expiry + merkle tombstones are
  the v1 answers; true revocation needs a revocation log.

## 8. Milestones

1. redb core + records + HLC — single node, no network
2. Capability verification + L3 sandbox API (https scheme) — multi-user
3. Merkle log + peer sync (libp2p) — the mesh is real at this point
4. L3-as-filesystem (FUSE) on top of the synced KV

## 9. Production features (HTTP API)

Additive surface on the existing L1/L2/L3 routes; none change the wire
record format or the sync protocol.

- **TLS termination** (`[node.tls]` in `config.toml`: `cert_path` +
  `key_path`, PEM). axum serves over a `tokio-rustls` listener; capability
  tokens and payloads are then encrypted on the wire. Capability auth stays
  the application boundary — TLS is transport defense-in-depth. Fails fast on
  missing/mismatched keys.
- **Value TTL** — `PUT /l2/{ns}/{key}?ttl=<secs>` records a wall-clock
  expiry as a new log tag (`TAG_PUT_TTL`), replicated alongside the value.
  GET/scan treat an expired value as absent; expiry survives offline nodes
  (each replica enforces it locally), unlike single-node Redis TTL. Record
  layout for ordinary PUT/DEL is unchanged; snapshots bump `BMDBIDX1` →
  `BMDBIDX2` with a trailing `expires_at` (v1 snapshots load transparently).
- **Change feed** — `GET /l2/{ns}/changes?since=<seq>` returns a gapless,
  lowest-seq-first stream of durable log records (PUT/DEL/TTL), plus the
  namespace `head`; `GET /l2/{ns}/head` returns `{seq, hash}` for cheap
  long-poll. Poll with `since` = previous `head.seq`.
- **Real-time push (SSE)** — `GET /l2/{ns}/events` streams a Server-Sent
  event per committed write (local HTTP *or* mesh-applied), each carrying
  the log head at delivery; the client replays the delta via the change
  feed. Turns the poll feed into a subscription.
- **Conflict observability** — register-policy namespaces keep every
  concurrent version. `GET /l2/{ns}/{key}?versions=true` exposes them raw;
  `GET /l2/{ns}/conflicts` lists every key holding >1 version. This turns
  divergent-history CRDT data into something a client can see and reconcile.
- **Backup / restore** — `bunnymeshdb backup <data> --out <dir>` checkpoints the
  store then copies the data dir (root private key written 0600);
  `bunnymeshdb restore <backup> --data-dir <dir>` copies it back into a fresh
  node dir. Byte-identical `meta.bin` ⇒ restored node keeps its identity.
- Known quirk: data routes require a cap carrying `read|write` regardless of
  method (pre-existing; a read-only cap cannot GET). Not part of this
  change — flagged for a follow-up.
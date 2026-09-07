# Security

BunnyMeshDB's security posture, threat model, and audit status. This file is
the canonical answer to "how do I know this is safe to run?" — it documents
what the product guarantees, what it deliberately does not, and how the
guarantees are enforced and verified.

## Threat model

**Assets.** Per-node data: capability-signed namespaces (L2/L3), the
namespace/merkle logs on disk, and the node's root keypair (`meta.bin`).
The mesh replicates log records between nodes that share namespaces.

**Trust boundaries.**

| Boundary | Trusted parties | Untrusted |
|---|---|---|
| HTTP API | holders of host-signed capabilities | everyone else on the network |
| Mesh protocol | configured + TOFU-pinned peer identities | strangers on the wire, first-contact MITMs, pinned peers outside their namespace allow-list |
| FUSE mount | the OS-level mounting uid (default: owner-only mount) | other uids, root, since the mount represents the host identity |
| On-disk data | a node operator with the data dir | tampering, bit-flips (detected, not prevented) |

**Attacker classes** are deliberately bounded: an unauthenticated network
attacker (exfiltration/falsification) cannot read or write any namespace
through any surface; a malicious *pinned* peer can only contribute records
to namespaces its allow-list grants (default: all shared ones — scope the
list for least privilege); a cap holder is scoped to exactly the
`scope`/`perms`/`expiry` their capability carries (and cannot forge
another's); OS users are separated by the FUSE owner-only mount.

## Authentication & authorization

- **Capabilities** (L1 admin / L2 namespace / L3 `u/<pk>` sandbox) are
  Ed25519-signed by the node's root key. `scope`, `perms`, `expiry_ms`,
  `nonce`, `issuer`, `subject`, and `sig` are verified per request.
- **L1** requires host admin scope + `admin` perms. **L3** additionally
  requires the cap's `subject` to equal the `u/<pk>` owner — the URL is
  never a credential.
- **Prefix scoping is segment-bounded**: a cap scoped to `a` covers `a` and
  `a/b` but never sibling `ab`; a `?prefix=` scan must be inside the cap's
  own prefix.
- **The verification cache is content-addressed**: a cap's cached "fully
  verified" verdict is keyed by sha256 of the exact signed bytes + sig, so
  reusing a cached `nonce` in a forged cap re-triggers signature
  verification (the v0.4.0 critical fix — see Audit status).
- **Revocation** bumps a per-node epoch; any revocation invalidates cached
  verdicts for the current epoch.
- **Rate limiting + quota** protect the node: fixed-window limiter (per
  valid token; junk headers share one anon bucket; maps are absolutely
  bounded), per-namespace write quota charged only after schema validation.

## Transport

- **HTTP**: TLS 1.2/1.3 (rustls) when `[node.tls]` is configured — the
  plaintext listener is not started alongside. ALPN negotiates h2 or
  http/1.1; auth is capability-based so neither is a security downgrade.
  Default bind is `127.0.0.1`; put the node behind a firewall or TLS in
  production.
- **Mesh (libp2p / noise)**: the peer id bound by the noise handshake is
  the identity anchor. **TOFU** pins a peer's key on first contact *only*
  when its claimed `host_id` matches the authenticated connection — a MITM
  can never pin its own key. Pins can be seeded out-of-band (`pin` on
  `add_peer`). Inbound `Hello`/`Pull` are served **only** to configured
  peers whose stored pin matches the connection; everyone else is denied
  and nothing is read. Set `p2p_listen` to a full multiaddr
  (`/ip4/127.0.0.1/tcp/9002`) to avoid exposing the mesh on all
  interfaces.

## Storage integrity

- Every namespace is a **merkle log**: each record hashes its predecessor
  and carries a CRC; `verify_batch` checks parse, chain, and tags on every
  sync pull. Any corruption is detected and that namespace is skipped (it
  is never applied).
- **Tamper detection**: logs/snapshots carry CRCs; the audit CLI/integration
  tests flip bits and confirm detection. This detects — it does not
  prevent — a node operator rewriting the data dir.
- **Deleted/overwritten history** remains in the log (and thus readable via
  the changes feed to READ holders, and recoverable from disk) until
  offline compaction. Deleted data is tombstoned for `get`, not shredded.

## Operating notes

- `meta.bin` (root key) is written 0600. Keep the data dir
  operator-owned; consider protecting `config.toml` (0600) — its `pin`
  entries are the mesh trust anchor.
- Online (mesh-synced) compaction is intentionally not available; run
  `bunnymeshdb compact` offline.
- `bunnymeshdb untrust <peer>` clears a pin (key rollover, or a peer
  restored from backup with a new key — it re-pins on the next Hello).

## Residual boundaries (known + documented)

- **FUSE mount** is capability-free by design: it is OS owner-only and
  represents the host identity (its writes replicate as host-authored), and
  it bypasses HTTP quota/rate limits. It must be treated as the host's own
  write surface.
- **Query DSL size** is bounded by statement/arg count and the body limit;
  a heavy read query now runs under a read lock (v0.4.1) so it cannot stall
  the node's writes.
- **Single-writer confidence**: the project is pre-1.0 with an external
  audit trail but no public bug bounty; report findings (below).

## Reporting vulnerabilities

Do not open public issues with exploit details. Contact the maintainer
privately (GitHub private security advisory on this repository) with:
affected version(s), steps to reproduce, impact, and a suggested fix. You
will receive an acknowledgment within 7 days. Credit is given in the
CHANGELOG unless anonymity is requested.

## Audit status

Three parallel security audits (auth/HTTP, libp2p mesh + TOFU, FUSE) were
run against the surfaces, producing **26 findings**. All were fixed and are
regression-tested (v0.4.0, v0.4.1). Headline items, all closed:

| Finding | Severity | Fix |
|---|---|---|
| Capability-forgery via nonce-reuse cache | CRITICAL | content-addressed verify cache |
| Unauthenticated mesh Pull (drain + OOM) | CRITICAL | pinned-peer gate + bounded pulls |
| GET `?prefix=` scope escape | HIGH | scan prefix re-authorized |
| FUSE read-back writes (resurrect/clobber) | HIGH | read-only opens never write |
| Pinned-peer record injection (MESH-002) | HIGH | per-peer namespace allow-list |
| TOFU first-contact displacement | MEDIUM | pin binds authenticated peer id |
| HLC same-ms dedupe drop | MEDIUM | strictly-increasing HLC issuer |
| Prefix-boundary scope escape | MEDIUM | segment-bounded covers() |
| Batch/feed/rate-limit DoS surfaces | MEDIUM/LOW | bounds, caps, lock-scope, validation order |
| ql under global write lock | MEDIUM | read/write lock split by statement kind |

Contact: private GitHub security advisory to this repository's maintainer.
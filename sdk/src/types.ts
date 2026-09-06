/** Wire types — field-for-field with the BunnyMeshDB HTTP API.
 *
 * Big integer caveat: the server serializes `u64` values (HLC, nonce) as
 * raw JSON numbers. JavaScript `Number` loses precision past 2^53, so the
 * client parses unsafe integers as strings (`number | string`) — compare
 * ordering semantics on the `seq` field instead, which is small and exact.
 */

/** Namespace conflict policy (chosen at creation). */
export type ConflictPolicy = "lww" | "register";

export interface NamespaceInfo {
  name: string;
  policy: ConflictPolicy;
}

/** A capability as issued by `POST /l1/caps`. */
export interface Capability {
  scope: string;
  perms: string[];
  expiry_ms: number | null;
  nonce: number | string;
  issuer: string;
  subject: string;
  sig: string;
}

/** Namespace log head: seq + chain hash. `hash` is the merkle chain
 * fingerprint; poll `head` (or `changes`) to detect new writes. */
export interface Head {
  seq: number;
  hash: string;
}

/** One durable log record delivered by the change feed. A PUT with TTL
 * reports `ttl: true` and a wall-clock `expires_at` (ms epoch, 0 = never);
 * a DELETE reports `del: true` (value empty). */
export interface Change {
  seq: number;
  key: string;
  value: Uint8Array;
  del: boolean;
  ttl: boolean;
  expires_at: number;
  hlc: number | string;
}

export interface ChangesResponse {
  since: number;
  head: Head | null;
  changes: Change[];
}

/** One retained version of a key (register policy keeps every concurrent
 * version; `?versions=true` and `/conflicts` expose them). */
export interface VersionInfo {
  hlc: number | string;
  replica: string;
  seq: number;
  expires_at: number;
  value: Uint8Array;
}

export interface KeyVersions {
  key: string;
  versions: VersionInfo[];
}

/** A key holding >1 divergent version (register policy). */
export interface ConflictEntry {
  key: string;
  count: number;
  versions: VersionInfo[];
}

export interface ScanEntry {
  key: string;
  value: Uint8Array;
  expires_at: number;
}

export interface PutResult {
  ok: true;
  seq: number;
  expires_at: number;
}

/** One op of a pipelined `DataClient.batch` call. Ops apply in order within
 * the batch's namespace; `put` values are string-or-bytes, `ttl` in seconds. */
export type BatchOp =
  | { op: "put"; key: string; value: Uint8Array | string; ttl?: number }
  | { op: "get"; key: string }
  | { op: "del"; key: string };

/** Result for one batch op, aligned with the input array. `get` decodes the
 * value (`null` = missing/expired); a failed op reports `ok: false` and does
 * not abort the batch. */
export type BatchResult =
  | { op: "put"; ok: true; seq: number }
  | { op: "put"; ok: false; error: string }
  | { op: "get"; ok: true; value: Uint8Array | null }
  | { op: "get"; ok: false; error: string }
  | { op: "del"; ok: true }
  | { op: "del"; ok: false; error: string };
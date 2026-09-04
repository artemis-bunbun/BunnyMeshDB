import { BunnyMeshError, parseJson, request } from "./client.js";
import { StreamUtf8 } from "./compat.js";
import { b64Decode, decodeUtf8, utf8 } from "./encoding.js";
import type { Change, ChangesResponse, ConflictEntry, Head, PutResult, ScanEntry, VersionInfo } from "./types.js";

/** Typed namespace client (L2 cap-authenticated, or L3 owner identity).
 *
 * `get` returns `null` for a missing/expired key; every other failure
 * (auth, namespace-not-found, server error) throws `BunnyError`.
 */
export class DataClient {
  private readonly tier: "l2" | "l3";
  private readonly base: string;

  constructor(
    public readonly baseUrl: string,
    public readonly ns: string,
    private readonly token: string | null,
  ) {
    this.tier = ns.startsWith("u/") ? "l3" : "l2";
    this.base = `/${this.tier}/${ns}`;
  }

  private req<T>(method: string, path: string, opts: { query?: Record<string, string | number | undefined>; body?: Uint8Array | string; json?: unknown } = {}, parse: (res: Response) => Promise<T>): Promise<T> {
    return request<T>(this.baseUrl, { method, path: this.base + path, query: opts.query, body: opts.body, json: opts.json, auth: this.token }, parse);
  }

  private static json(res: Response): Promise<unknown> {
    return res.text().then(parseJson);
  }

  private static parsed<T>(parse: (v: unknown) => T): (res: Response) => Promise<T> {
    return async (res) => parse(await DataClient.json(res));
  }

  private static rawBytes(res: Response): Promise<Uint8Array> {
    return res.arrayBuffer().then((b) => new Uint8Array(b));
  }

  private static readVersion(v: Record<string, unknown>): VersionInfo {
    if (typeof v.value_b64 !== "string") throw new Error("malformed version payload");
    return {
      hlc: v.hlc as VersionInfo["hlc"],
      replica: String(v.replica),
      seq: Number(v.seq),
      expires_at: Number(v.expires_at),
      value: b64Decode(v.value_b64),
    };
  }

  private static parseHead(v: unknown): Head {
    if (typeof v !== "object" || v === null) throw new Error("malformed head payload");
    const r = v as Record<string, unknown>;
    return { seq: Number(r.seq), hash: String(r.hash) };
  }

  /** Fetch a key. `null` = missing, deleted, or expired. */
  async get(key: string): Promise<Uint8Array | null> {
    try {
      return await this.req("GET", `/${encodeURIComponent(key)}`, {}, DataClient.rawBytes);
    } catch (e) {
      if (e instanceof BunnyMeshError && e.status === 404) return null;
      throw e;
    }
  }

  /** Shortcut for UTF-8 string reads. */
  async getText(key: string): Promise<string | null> {
    const v = await this.get(key);
    return v === null ? null : decodeUtf8(v);
  }

  /** Every retained version of a key (`?versions=true`). */
  async versions(key: string): Promise<VersionInfo[]> {
    return this.req("GET", `/${encodeURIComponent(key)}`, { query: { versions: "true" } }, DataClient.parsed((j) => {
      const k = j as { key?: unknown; versions?: unknown };
      return Array.isArray(k.versions) ? (k.versions as Record<string, unknown>[]).map(DataClient.readVersion) : [];
    }));
  }

  /** Write a value (string or bytes). `ttl` seconds → value expires
   * (replicated log record; other mesh nodes enforce it too). */
  async put(key: string, value: Uint8Array | string, opts: { ttl?: number } = {}): Promise<PutResult> {
    return this.req("PUT", `/${encodeURIComponent(key)}`, { body: utf8(value), query: opts.ttl ? { ttl: opts.ttl } : undefined }, DataClient.parsed((j) => {
      const k = j as Record<string, unknown>;
      return { ok: true as const, seq: Number(k.seq), expires_at: Number(k.expires_at) };
    }));
  }

  async delete(key: string): Promise<void> {
    await this.req("DELETE", `/${encodeURIComponent(key)}`, {}, DataClient.parsed(() => undefined));
  }

  /** Prefix scan over the whole namespace (`prefix` optional, default all). */
  async scan(prefix = ""): Promise<ScanEntry[]> {
    return this.req("GET", "", { query: { prefix } }, DataClient.parsed((j) => {
      const k = j as { entries?: unknown };
      return Array.isArray(k.entries) ? (k.entries as Record<string, unknown>[]).map((e) => ({
        key: String(e.key),
        value: b64Decode(String(e.value_b64)),
        expires_at: Number(e.expires_at),
      })) : [];
    }));
  }

  /** Namespace log head — poll for new writes cheaply. `null` = namespace
   * missing. */
  async head(): Promise<Head | null> {
    try {
      return await this.req("GET", "/head", {}, DataClient.parsed(DataClient.parseHead));
    } catch (e) {
      if (e instanceof BunnyMeshError && e.status === 404) return null;
      throw e;
    }
  }

  /** Gapless change stream after `since` (oldest first). Poll with
   * `since = lastResponse.head.seq`. */
  async changes(since = 0): Promise<ChangesResponse> {
    return this.req("GET", "/changes", { query: { since } }, DataClient.parsed((j) => {
      const r = j as Record<string, unknown>;
      const changes = Array.isArray(r.changes) ? (r.changes as Record<string, unknown>[]).map<Change>((c) => ({
        seq: Number(c.seq),
        key: decodeUtf8(b64Decode(String(c.key_b64))),
        value: b64Decode(String(c.value_b64)),
        del: Boolean(c.del),
        ttl: Boolean(c.ttl),
        expires_at: Number(c.expires_at),
        hlc: c.hlc as Change["hlc"],
      })) : [];
      return {
        since: Number(r.since),
        head: r.head ? DataClient.parseHead(r.head as Record<string, unknown>) : null,
        changes,
      };
    }));
  }

  /** Keys holding >1 divergent version (register policy). */
  async conflicts(): Promise<ConflictEntry[]> {
    return this.req("GET", "/conflicts", {}, DataClient.parsed((j) => {
      const r = j as { conflicts?: unknown };
      return Array.isArray(r.conflicts) ? (r.conflicts as Record<string, unknown>[]).map((c) => ({
        key: String(c.key),
        count: Number(c.count),
        versions: Array.isArray(c.versions) ? (c.versions as Record<string, unknown>[]).map(DataClient.readVersion) : [],
      })) : [];
    }));
  }

  /** Subscribe to live change events (SSE push, `GET /events`).
   *
   * `onEvent` fires once per committed write to this namespace (local HTTP
   * or mesh-applied); each event carries the log head at delivery — replay
   * the delta with `changes(since)` seeded from `head.seq`. Resolves when
   * the stream ends (daemon shutdown or `signal` abort).
   */
  async subscribe(
    onEvent: (ev: { ns: string; seq: number; hash: string }) => void,
    signal?: AbortSignal,
  ): Promise<void> {
    const url = `${this.baseUrl}${this.base}/events`;
    const headers: Record<string, string> = {};
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    let res: Response;
    try {
      res = await fetch(url, { headers, signal });
    } catch (e) {
      throw new Error(`BunnyMeshDB: cannot reach ${this.baseUrl} (${(e as Error).message})`);
    }
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new BunnyMeshError(res.status, text, "GET", `${this.base}/events`);
    }
    const body = res.body;
    if (typeof body?.getReader !== "function") {
      throw new Error(
        "BunnyMeshDB: live push needs a ReadableStream-capable fetch (unavailable on this React Native runtime). " +
          "Fall back to changes(since) polling for real-time on RN.",
      );
    }
    const reader = body.getReader();
    const decoder = new StreamUtf8();
    let buf = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.feed(value);
      let idx: number;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const dataLine = frame.split("\n").find((l) => l.startsWith("data: "));
        if (dataLine) {
          try {
            onEvent(JSON.parse(dataLine.slice(6)) as { ns: string; seq: number; hash: string });
          } catch {
            // malformed frame — skip
          }
        }
      }
    }
  }

  /** Run a query-DSL expression in this namespace. */
  async ql(expr: string): Promise<unknown> {
    return this.req("POST", "/ql", { json: { expr } }, DataClient.json);
  }
}
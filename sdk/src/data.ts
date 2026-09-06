import { BunnyMeshError, parseJson, request } from "./client.js";
import { StreamUtf8 } from "./compat.js";
import { b64Decode, b64Encode, decodeUtf8, utf8 } from "./encoding.js";
import type { BatchOp, BatchResult, Change, ChangesResponse, ConflictEntry, Head, PutResult, ScanEntry, VersionInfo } from "./types.js";

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

  /** Subscribe to live change events (SSE push, `GET /events?since=`).
   *
   * `onEvent` fires once per committed write to this namespace (local HTTP
   * or mesh-applied), in log order, each carrying `{ns, seq, hash}` (the
   * per-record log head — `seq` is a gapless cursor). Auto-resumes: on a
   * dropped connection it reconnects with `since = last seen seq` and
   * exponential backoff, so no committed write is missed. Resolves only when
   * `signal` aborts (or the daemon stays down and `signal` is never set).
   */
  async subscribe(
    onEvent: (ev: { ns: string; seq: number; hash: string }) => void,
    signal?: AbortSignal,
  ): Promise<void> {
    let since = 0;
    let attempt = 0;
    for (;;) {
      if (signal?.aborted) return;
      const url = `${this.baseUrl}${this.base}/events?since=${since}`;
      const headers: Record<string, string> = {};
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      let res: Response;
      try {
        res = await fetch(url, { headers, signal });
      } catch (e) {
        if (signal?.aborted) return;
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
          let dataLine: string | null = null;
          let id: string | null = null;
          for (const l of frame.split("\n")) {
            if (l.startsWith("data: ")) dataLine = l.slice(6);
            else if (l.startsWith("id:")) id = l.slice(3).trim();
          }
          if (dataLine) {
            let ev: { ns?: string; seq?: unknown; hash?: unknown };
            try {
              ev = JSON.parse(dataLine);
            } catch {
              continue;
            }
            if (typeof ev.seq === "number" && Number.isSafeInteger(ev.seq)) since = ev.seq;
            else if (id !== null && /^\d+$/.test(id)) since = Number(id);
            onEvent(ev as { ns: string; seq: number; hash: string });
          }
        }
        if (signal?.aborted) return;
      }
      // Stream ended (daemon restart / network drop). Backoff + reconnect,
      // resuming from the last seen seq so nothing is missed.
      if (signal?.aborted) return;
      attempt++;
      const delay = Math.min(1000 * Math.pow(2, Math.min(attempt, 5)), 30000);
      await new Promise((r) => setTimeout(r, delay));
    }
  }

  /** Run a query-DSL expression in this namespace. */
  async ql(expr: string): Promise<unknown> {
    return this.req("POST", "/ql", { json: { expr } }, DataClient.json);
  }

  /** Pipelined batch of data ops — the read/write throughput lever. One
   * capability verification, one rate-limit charge, and one storage lock
   * for the whole batch instead of per op. Ops apply in order to THIS
   * namespace only (never cross-namespace), reads observe the consistent
   * prefix of the batch, and a failing op is reported in place without
   * aborting the batch. Requires a WRITE capability (like `ql`). Results
   * align with `ops`. */
  async batch(ops: BatchOp[]): Promise<BatchResult[]> {
    const payload = ops.map((o) => {
      if (o.op === "put") {
        return { op: "put", key: o.key, value_b64: b64Encode(utf8(o.value)), ...(o.ttl ? { ttl: o.ttl } : {}) };
      }
      return { op: o.op, key: o.key };
    });
    const res = (await this.req("POST", "/batch", { json: { ops: payload } }, DataClient.json)) as {
      results: Array<Record<string, unknown>>;
    };
    return res.results.map((r, i): BatchResult => {
      const op = ops[i]!;
      if (r.ok === true) {
        if (op.op === "get") {
          return { op: "get", ok: true, value: r.value_b64 != null ? b64Decode(String(r.value_b64)) : null };
        }
        return op.op === "put" ? { op: "put", ok: true, seq: r.seq as number } : { op: "del", ok: true };
      }
      return { op: op.op, ok: false, error: String(r.error ?? "error") };
    });
  }
}
import type { Capability, ConflictPolicy, NamespaceInfo } from "./types.js";
import { DataClient } from "./data.js";
import { b64urlEncode, decodeCapToken, encodeCapToken } from "./encoding.js";
import { utf8Encode } from "./compat.js";

/** HTTP error carrying the server's machine-readable `error` string. */
export class BunnyMeshError extends Error {
  constructor(
    public readonly status: number,
    public readonly error: string,
    public readonly method: string,
    public readonly url: string,
  ) {
    super(`BunnyMeshDB ${method} ${url} -> ${status} ${error}`);
  }
}

/** Reviver: unsafe JSON integers (u64 HLC/nonce fields) become strings so
 * consumers never silently lose precision. */
function safeJsonReviver(_key: string, value: unknown): unknown {
  return typeof value === "number" && !Number.isSafeInteger(value) ? String(value) : value;
}

/** Parse server JSON with the u64-safe reviver (HLCs become strings when
 * they exceed 2^53). */
export function parseJson(text: string): unknown {
  return JSON.parse(text, safeJsonReviver);
}

async function errorBody(res: Response): Promise<string> {
  try {
    const j = (await res.json()) as { error?: unknown };
    return typeof j.error === "string" ? j.error : JSON.stringify(j);
  } catch {
    return res.text().catch(() => res.statusText);
  }
}

export interface RequestInit2 {
  method: string;
  path: string;
  body?: Uint8Array | string;
  query?: Record<string, string | number | undefined>;
  auth?: string | null;
  json?: unknown;
}

export async function request<T>(baseUrl: string, init: RequestInit2, parse: (res: Response) => Promise<T>): Promise<T> {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(init.query ?? {})) {
    if (v !== undefined) qs.set(k, String(v));
  }
  const q = qs.toString();
  const url = baseUrl + init.path + (q ? `?${q}` : "");
  const headers: Record<string, string> = {};
  if (init.auth) headers.Authorization = `Bearer ${init.auth}`;
  let body: BodyInit | undefined;
  if (init.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(init.json);
  } else if (init.body !== undefined) {
    body = init.body as BodyInit;
  }
  let res: Response;
  try {
    res = await fetch(url, { method: init.method, headers, body });
  } catch (e) {
    throw new Error(`BunnyMeshDB: cannot reach ${baseUrl} (${(e as Error).message})`);
  }
  if (!res.ok) throw new BunnyMeshError(res.status, await errorBody(res), init.method, init.path);
  return parse(res);
}

/** The host authority from a scope URL, e.g. `bmdb://api.host.test/l1` →
 * `api.host.test`. Scopes must reference the serving host, so the SDK
 * derives it from the admin capability rather than asking the operator. */
function scopeHost(cap: Capability): string {
  const m = /^bmdb:\/\/([^/]+)\//.exec(cap.scope);
  return m ? m[1] : "localhost";
}

/** Admin client: L1 control plane (namespaces, capability issuance). The
 * admin token is the `bmdb-cap:…` value printed at daemon startup. */
export class BunnyMeshClient {
  constructor(
    public readonly baseUrl: string,
    public adminToken: string | null = null,
  ) {}

  setAdminToken(token: string): void {
    this.adminToken = token;
  }

  private get admin(): string {
    if (!this.adminToken) throw new Error("no admin capability: pass it to the BunnyMeshClient constructor or setAdminToken()");
    return this.adminToken;
  }

  async health(): Promise<{ ok: boolean }> {
    return request(this.baseUrl, { method: "GET", path: "/healthz" }, (res) => res.json() as Promise<{ ok: boolean }>);
  }

  async namespaces(): Promise<NamespaceInfo[]> {
    return request(this.baseUrl, { method: "GET", path: "/l1/namespaces", auth: this.admin }, (res) => res.text().then(parseJson) as Promise<NamespaceInfo[]>);
  }

  async createNamespace(name: string, policy: ConflictPolicy = "lww"): Promise<void> {
    await request(
      this.baseUrl,
      { method: "POST", path: "/l1/namespaces", auth: this.admin, json: { name, policy } },
      async () => undefined,
    );
  }

  /** Set a per-namespace JSON-Schema (replicated to every mesh peer, which
   * then enforce it). `schema` is a plain JS object/array/boolean — the
   * validated subset excludes `pattern`/`format`/`$ref` (no audited regex
   * engine on the server); unsupported keywords are rejected with 400. */
  async setSchema(ns: string, schema: unknown): Promise<void> {
    await request(
      this.baseUrl,
      { method: "POST", path: `/l1/namespaces/${encodeURIComponent(ns)}/schema`, auth: this.admin, json: schema },
      async () => undefined,
    );
  }

  /** Clear the namespace schema (validation off). */
  async clearSchema(ns: string): Promise<void> {
    await request(
      this.baseUrl,
      { method: "DELETE", path: `/l1/namespaces/${encodeURIComponent(ns)}/schema`, auth: this.admin },
      async () => undefined,
    );
  }

  /** Set a per-namespace index field list (replicated to every mesh peer,
   * which derive the same secondary index from the same values). `fields` is
   * the array of scalar JSON field names to index. */
  async setIndex(ns: string, fields: string[]): Promise<void> {
    await request(
      this.baseUrl,
      { method: "POST", path: `/l1/namespaces/${encodeURIComponent(ns)}/index`, auth: this.admin, json: fields },
      async () => undefined,
    );
  }

  /** Clear the namespace's secondary index definition. */
  async clearIndex(ns: string): Promise<void> {
    await request(
      this.baseUrl,
      { method: "DELETE", path: `/l1/namespaces/${encodeURIComponent(ns)}/index`, auth: this.admin },
      async () => undefined,
    );
  }

  /** The active index-field list, or `null` if none is set. */
  async getIndex(ns: string): Promise<string[] | null> {
    try {
      return await request(
        this.baseUrl,
        { method: "GET", path: `/l1/namespaces/${encodeURIComponent(ns)}/index`, auth: this.admin },
        (res) => res.text().then(parseJson) as Promise<string[] | null>,
      );
    } catch (e) {
      if (e instanceof BunnyMeshError && e.status === 404) return null;
      throw e;
    }
  }

  /** The active namespace schema, or `null` if none is set. */
  async getSchema(ns: string): Promise<unknown> {
    try {
      return await request(
        this.baseUrl,
        { method: "GET", path: `/l1/namespaces/${encodeURIComponent(ns)}/schema`, auth: this.admin },
        (res) => res.text().then(parseJson),
      );
    } catch (e) {
      if (e instanceof BunnyMeshError && e.status === 404) return null;
      throw e;
    }
  }

  /** Issue a capability and return it with its ready-to-send wire token.
   * The token encodes the server's raw JSON verbatim — re-encoding the
   * parsed object would corrupt the u64 nonce through JS number precision,
   * breaking the signature. */
  async issueCap(opts: {
    scope: string;
    perms?: string[];
    expiryMs?: number;
    to?: string;
  }): Promise<{ cap: Capability; token: string }> {
    const raw = await request<string>(
      this.baseUrl,
      {
        method: "POST",
        path: "/l1/caps",
        auth: this.admin,
        json: {
          scope: opts.scope,
          perms: opts.perms ?? ["read", "write"],
          expiry_ms: opts.expiryMs,
          to: opts.to,
        },
      },
      (res) => res.text(),
    );
    const cap = parseJson(raw) as Capability;
    return { cap, token: `bmdb-cap:${b64urlEncode(utf8Encode(raw))}` };
  }

  async listCaps(): Promise<Capability[]> {
    return request(this.baseUrl, { method: "GET", path: "/l1/caps", auth: this.admin }, (res) => res.text().then(parseJson) as Promise<Capability[]>);
  }

  async revoke(scope: string, to: string): Promise<void> {
    await request(this.baseUrl, { method: "POST", path: "/l1/revoke", auth: this.admin, json: { scope, to } }, async () => undefined);
  }

  /** Issue an L2 data capability and return a ready DataClient. Defaults to
   * `["read","write"]`: data routes require both perms regardless of method
   * (documented server quirk). */
  async openL2(
    ns: string,
    opts: { perms?: string[]; expiryMs?: number; to?: string } = {},
  ): Promise<DataClient> {
    const adminCap = decodeCapToken(this.admin);
    const host = scopeHost(adminCap);
    const scope = `bmdb://${host}/l2/${ns}`;
    const { token } = await this.issueCap({ scope, perms: opts.perms ?? ["read", "write"], expiryMs: opts.expiryMs, to: opts.to });
    return new DataClient(this.baseUrl, ns, token);
  }

  /** Data client for an existing capability (object or wire token). */
  data(ns: string, cap: Capability | string): DataClient {
    const token = typeof cap === "string" ? cap : encodeCapToken(cap);
    return new DataClient(this.baseUrl, ns, token);
  }

  /** L3 owner namespace `u/<pk>`. L3 is capability-gated like L2: this
   * mints a cap scoped to the namespace with `subject` = the owning `pk`, so
   * only a holder of that capability (issued by the admin/root) can access
   * the namespace — the `u/<pk>` path alone is not a credential. */
  async l3(pk: string, opts: { perms?: string[]; expiryMs?: number } = {}): Promise<DataClient> {
    const host = scopeHost(decodeCapToken(this.admin));
    const scope = `bmdb://${host}/l3/u/${pk}`;
    const { token } = await this.issueCap({ scope, perms: opts.perms ?? ["read", "write"], expiryMs: opts.expiryMs, to: pk });
    return new DataClient(this.baseUrl, `u/${pk}`, token);
  }
}
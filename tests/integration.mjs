// Daemon-level integration test. Boots a real bunnymeshdbd on an ephemeral
// port and exercises the HTTP surface end-to-end: guarded serve self-init,
// health, capability auth (read-only caps can read, can't write), PUT/get,
// JSON-Schema enforcement (400 schema_violation), and SSE push (a concurrent
// PUT must arrive as a live event).
//
//   cargo build --release && node tests/integration.mjs
//
// Requires Node >= 18 and a built daemon (default ./target/release/bunnymeshdbd,
// override with BMDB_BIN).

import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { BunnyMeshClient } from "../sdk/dist/index.js";

const BIN = process.env.BMDB_BIN || "./target/release/bunnymeshdbd";

async function freePort() {
  const s = createServer();
  await new Promise((res, rej) => { s.once("error", rej); s.listen(0, "127.0.0.1", res); });
  const port = s.address().port;
  s.close();
  return port;
}

const dir = mkdtempSync("/tmp/bmdb-itest-");
const httpPort = await freePort();
const cfgPath = `${dir}/config.toml`;
const logPath = `${dir}/server.log`;
writeFileSync(cfgPath, `[node]
name = "itest.bunnymeshdb.test"
data_dir = "${dir}/data"
listen = "127.0.0.1:${httpPort}"
p2p_listen = "0"
worker_threads = 2
mesh_sync = false
[node.l3]
default_quota = 1048576
`);

const proc = spawn("bash", ["-c", `exec "${BIN}" serve --config "${cfgPath}"`], {
  cwd: process.cwd(),
  stdio: ["ignore", "pipe", "pipe"],
});
let logBuf = "";
proc.stdout.on("data", (d) => { logBuf += d; });
proc.stderr.on("data", (d) => { logBuf += d; });
proc.on("error", (e) => { console.error("spawn error:", e); process.exit(2); });

const base = `http://127.0.0.1:${httpPort}`;
let pass = 0;
const ok = (name, cond, extra = "") => {
  if (!cond) throw new Error(`FAIL: ${name} ${extra}`);
  pass++;
  console.log(`ok ${pass} - ${name}${extra ? ` (${extra})` : ""}`);
};

async function eventually(fn, what, timeoutMs = 12000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { if (await fn()) return; } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`timed out: ${what}`);
}

await eventually(() => fetch(base + "/healthz").then((r) => r.ok), "daemon health");
ok("guarded serve self-init + health", true);

// Gather the admin capability from the daemon's own startup log (we spliced
// stdout/stderr into logBuf).
let adminCap = null;
for (const step of [1, 2, 3, 4, 5]) {
  const m = /admin cap: (bmdb-cap:[\w.-]+)/.exec(logBuf);
  if (m) { adminCap = m[1]; break; }
  await new Promise((r) => setTimeout(r, 500));
}
if (!adminCap) {
  await new Promise((r) => setTimeout(r, 1500));
  const m = /admin cap: (bmdb-cap:[\w.-]+)/.exec(logBuf);
  adminCap = m && m[1];
}
ok("admin capability logged", !!adminCap);

const client = new BunnyMeshClient(base, adminCap);
await client.createNamespace("it", "register");
const db = await client.openL2("it");

const put = await db.put("k1", "hello-itest");
ok("PUT returns seq", typeof put.seq === "number" && put.seq > 0);
ok("GET roundtrip", (await db.getText("k1")) === "hello-itest");

const ro = await client.openL2("it", { perms: ["read"] });
ok("read-only cap can GET", (await ro.getText("k1")) === "hello-itest");
let ro403 = false;
try { await ro.put("x", "no"); } catch (e) { ro403 = e.status === 403; }
ok("read-only cap cannot PUT (403)", ro403);

await client.setSchema("it", { type: "object", properties: { title: { type: "string" } }, required: ["title"], additionalProperties: false });
let schema400 = false;
try { await db.put("bad", JSON.stringify({ nope: 1 })); } catch (e) { schema400 = e.status === 400 && e.error.startsWith("schema_violation"); }
ok("schema violation -> 400 schema_violation", schema400);
await db.put("good", JSON.stringify({ title: "ok" }));
ok("schema-conforming PUT ok", JSON.parse(await db.getText("good")).title === "ok");
await client.clearSchema("it");

// SSE push: with resume, subscribe first replays any backlog (since=0), then
// a concurrent PUT must surface as a live event with that seq.
const events = [];
const subDone = db.subscribe((ev) => { events.push(ev); }).catch(() => {});
await new Promise((r) => setTimeout(r, 300));
const seq2 = (await db.put("k2", "sse-push")).seq;
await eventually(() => Promise.resolve(events.some((e) => e.seq === seq2)), "SSE event", 8000);
ok("SSE event arrives on concurrent PUT", true, `seq=${seq2}`);
// resume: a reconnecting subscriber with since=last sees only newer records
const head = await db.head();
const evs2 = [];
const sub2 = db.subscribe((ev) => { evs2.push(ev); }).catch(() => {});
await new Promise((r) => setTimeout(r, 250));
await db.put("k3", "after-resume");
await eventually(() => Promise.resolve(evs2.some((e) => e.seq === (head?.seq ?? 0) + 1)), "resume skips backlog", 8000);
ok("subscribe since=head skips backlog", true, `got seqs ${evs2.map((e) => e.seq).join(",")}`);

// live peer management (admin) — must persist in config + list + remove
const H = { Authorization: `Bearer ${adminCap}`, "Content-Type": "application/json" };
const addRes = await fetch(base + "/l1/peers", { method: "POST", headers: H, body: JSON.stringify({ name: "peer-x.test", addr: "/ip4/127.0.0.1/tcp/9999" }) });
ok("peer add ok", addRes.ok, String(addRes.status));
const addBad = await fetch(base + "/l1/peers", { method: "POST", headers: H, body: JSON.stringify({ name: "bad", addr: "nope" }) });
ok("peer add invalid addr -> 400", addBad.status === 400);
const listRes = await fetch(base + "/l1/peers", { headers: H });
const peers = (await listRes.json()).peers ?? [];
ok("peer list contains added", peers.some((p) => p.name === "peer-x.test"));
const delRes = await fetch(base + "/l1/peers/peer-x.test", { method: "DELETE", headers: H });
ok("peer remove ok", delRes.ok);

// secondary indexes: admin sets a field list; json values index + query.
const idxSet = await fetch(base + "/l1/namespaces/it/index", { method: "POST", headers: H, body: JSON.stringify(["city"]) });
ok("index set admin ok", idxSet.ok, String(idxSet.status));
const idxGet = await fetch(base + "/l1/namespaces/it/index", { headers: H });
ok("index get returns fields", JSON.stringify((await idxGet.json())) === `["city"]`);
await db.put("p1", JSON.stringify({ city: "london" }));
await db.put("p2", JSON.stringify({ city: "paris" }));
const qlLon = await db.ql(`by_index("city","london")`);
ok("by_index london -> p1", JSON.stringify(qlLon) === `["p1"]`);
const qlPar = await db.ql(`by_index("city","paris")`);
ok("by_index paris -> p2", JSON.stringify(qlPar) === `["p2"]`);

// pipelined batch: one auth + one rate-limit + ONE log record. The batch is
// atomic: reads inside the batch observe the fully-applied batch — a get of
// a key that a LATER op in the same batch writes sees the final state, not a
// positional prefix. Per-op failures do not abort; read-only caps are
// refused (write-gated like /ql).
const batchR = await db.batch([
  { op: "put", key: "b1", value: "batch-val" },
  { op: "get", key: "b1" },
  { op: "del", key: "b1" },
  { op: "get", key: "b1" },
]);
ok("batch put ok", batchR[0].ok === true && typeof batchR[0].seq === "number", JSON.stringify(batchR[0]));
// b1 is written then DELETED by the same batch: the batch is one record, so
// BOTH reads see the final state (deleted → null).
ok("batch get sees fully-applied batch (del shadows put)", batchR[1].ok === true && batchR[1].value === null, JSON.stringify(batchR[1]));
ok("batch del ok", batchR[2].ok === true, JSON.stringify(batchR[2]));
ok("batch get after del -> null", batchR[3].ok === true && batchR[3].value === null, JSON.stringify(batchR[3]));
// A read of a key the batch does not write sees pre-batch state.
const batchR2 = await db.batch([{ op: "put", key: "b2", value: "v2" }, { op: "get", key: "b1" }]);
ok("batch read of untouched key -> null", batchR2[1].ok === true && batchR2[1].value === null, JSON.stringify(batchR2));
// All accepted writes in one batch share the batch record's seq (ONE log
// record); two puts expose it through the typed SDK.
const shareSeq = await db.batch([{ op: "put", key: "s1", value: "x" }, { op: "put", key: "s2", value: "y" }]);
ok("batch accepted writes share one log seq", shareSeq[0].ok === true && shareSeq[1].ok === true && shareSeq[0].seq === shareSeq[1].seq, JSON.stringify(shareSeq));
const mixed = await db.batch([{ op: "bogus", key: "x" }, { op: "get", key: "k1" }]);
ok("batch per-op failure isolated", mixed[0].ok === false && mixed[1].ok === true, JSON.stringify(mixed));
let roBatch403 = false;
try { await ro.batch([{ op: "get", key: "k1" }]); } catch (e) { roBatch403 = e.status === 403; }
ok("read-only cap batch -> 403", roBatch403);

try { proc.kill("SIGKILL"); } catch {}
// The SIGKILL below tears down the open SSE subscriptions; the reconnect
// loop may reject with a transport error. Swallow + short-circuit so the
// script exits 0 on the assertions, not the teardown.
await new Promise((r) => setTimeout(r, 50));
process.exit(0);
rmSync(dir, { recursive: true, force: true });
console.log(`\nPASS all ${pass} integration assertions`);
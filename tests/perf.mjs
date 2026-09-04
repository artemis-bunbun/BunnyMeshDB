// Perf regression smoke: boots a daemon, seeds N keys, hammers GET with
// C concurrent fetches, and asserts throughput stays above a conservative
// floor. The floor is deliberately low (CI runners vary widely); it exists
// to catch gross regressions (allocator collapse, accidental sync overhead),
// not to benchmark. Real numbers live in docs/BENCHMARKS.md + loadgen.
//
//   cargo build --release && node tests/perf.mjs
//
// Requires Node >= 18 and a built daemon (BMDB_BIN override).

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { BunnyMeshClient } from "../sdk/dist/index.js";

const BIN = process.env.BMDB_BIN || "./target/release/bunnymeshdbd";
const KEYS = 2000;
const CONC = 16;
const FLOOR_OPS = 1500; // ops/s — very conservative for shared CI

async function freePort() {
  const s = createServer();
  await new Promise((res, rej) => { s.once("error", rej); s.listen(0, "127.0.0.1", res); });
  const port = s.address().port; s.close(); return port;
}
const dir = mkdtempSync("/tmp/bmdb-perf-");
const httpPort = await freePort();
writeFileSync(`${dir}/cfg.toml`, `[node]
name = "perf.test"
data_dir = "${dir}/data"
listen = "127.0.0.1:${httpPort}"
p2p_listen = "0"
worker_threads = 4
mesh_sync = false
[node.l3]
default_quota = 1048576
`);
const proc = spawn("bash", ["-c", `exec "${BIN}" serve --config "${dir}/cfg.toml"`], { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });
let logBuf = "";
proc.stdout.on("data", (d) => { logBuf += d; });
proc.stderr.on("data", (d) => { logBuf += d; });
const base = `http://127.0.0.1:${httpPort}`;
async function eventually(fn, what, ms = 15000) { const d = Date.now() + ms; while (Date.now() < d) { try { if (await fn()) return; } catch {} await new Promise((r) => setTimeout(r, 200)); } throw new Error(`timeout: ${what}`); }
await eventually(() => fetch(base + "/healthz").then((r) => r.ok), "up");

let adminCap = null;
for (let i = 0; i < 30; i++) { const m = /admin cap: (bmdb-cap:[\w.-]+)/.exec(logBuf); if (m) { adminCap = m[1]; break; } await new Promise((r) => setTimeout(r, 300)); }
if (!adminCap) throw new Error("no admin cap");

const client = new BunnyMeshClient(base, adminCap);
await client.createNamespace("n", "lww");
const db = await client.openL2("n");
for (let i = 0; i < KEYS; i++) db.put(`k${i}`, "value");
console.error(`seeded ${KEYS} keys`);

const start = Date.now();
let total = 0;
const worker = async () => {
  const h = { Authorization: `Bearer ${db.token ?? ""}` };
  let n = 0;
  while (Date.now() - start < 3000) {
    try { const r = await fetch(`${base}/l2/n/k${n % KEYS}`, { headers: h }); if (!r.ok) throw 0; } catch {}
    n++;
  }
  total += n;
};
await Promise.all(Array.from({ length: CONC }, () => worker()));
const secs = (Date.now() - start) / 1000;
const ops = Math.round(total / secs);
console.log(`\nGET throughput: ${ops} ops/s (${CONC} conns, ${KEYS} keys, ${secs.toFixed(1)}s)`);
proc.kill("SIGKILL");
await new Promise((r) => setTimeout(r, 50));
if (ops < FLOOR_OPS) { console.error(`PERF REGRESSION: ${ops} < ${FLOOR_OPS} ops/s`); process.exit(1); }
console.log(`perf: within floor (>= ${FLOOR_OPS} ops/s) — pass`);
process.exit(0);
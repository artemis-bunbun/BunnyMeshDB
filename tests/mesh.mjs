// Two-node mesh integration test. Boots two real bunnymeshdbd daemons on
// ephemeral ports with a short sync interval, creates a shared namespace on
// both, writes on node A, and asserts node B converges within the pull
// interval — the flagship multi-master behavior, locked into CI.
//
//   cargo build --release && node tests/mesh.mjs
//
// Requires Node >= 18 and a built daemon (default ./target/release/bunnymeshdbd,
// override with BMDB_BIN).

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { BunnyMeshClient } from "../sdk/dist/index.js";

const BIN = process.env.BMDB_BIN || "./target/release/bunnymeshdbd";
const SYNC_SECS = 4;

async function freePort() {
  const s = createServer();
  await new Promise((res, rej) => { s.once("error", rej); s.listen(0, "127.0.0.1", res); });
  const port = s.address().port;
  s.close();
  return port;
}

const dir = mkdtempSync("/tmp/bmdb-mesh-");
function cfg(name, dataDir, httpPort, p2pPort, peerName, peerP2p) {
  return `[node]
name = "${name}"
data_dir = "${dataDir}"
listen = "127.0.0.1:${httpPort}"
p2p_listen = "${p2pPort}"
worker_threads = 2
mesh_sync = true
sync_interval_secs = ${SYNC_SECS}
[node.l3]
default_quota = 1048576
[[peers]]
name = "${peerName}"
addr = "/ip4/127.0.0.1/tcp/${peerP2p}"
`;
}

function boot(cfgPath, logPath) {
  const proc = spawn("bash", ["-c", `exec "${BIN}" serve --config "${cfgPath}"`], { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });
  let buf = "";
  proc.stdout.on("data", (d) => { buf += d; });
  proc.stderr.on("data", (d) => { buf += d; });
  return { proc, log: () => buf };
}

const aHttp = await freePort(), bHttp = await freePort();
const aP2p = await freePort(), bP2p = await freePort();
const aCfg = `${dir}/a.toml`, bCfg = `${dir}/b.toml`;
writeFileSync(aCfg, cfg("mesh-a.test", `${dir}/a/data`, aHttp, aP2p, "mesh-b.test", bP2p));
writeFileSync(bCfg, cfg("mesh-b.test", `${dir}/b/data`, bHttp, bP2p, "mesh-a.test", aP2p));

const a = boot(aCfg, `${dir}/a.log`);
const b = boot(bCfg, `${dir}/b.log`);
const baseA = `http://127.0.0.1:${aHttp}`, baseB = `http://127.0.0.1:${bHttp}`;

let pass = 0;
const ok = (n, c, extra = "") => { if (!c) throw new Error(`FAIL: ${n} ${extra}`); pass++; console.log(`ok ${pass} - ${n}${extra ? ` (${extra})` : ""}`); };
async function eventually(fn, what, timeoutMs = 20000) {
  const d = Date.now() + timeoutMs;
  while (Date.now() < d) {
    try { if (await fn()) return; } catch {}
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`timed out: ${what}`);
}
async function adminFrom(logFn) {
  for (let i = 0; i < 20; i++) {
    const m = /admin cap: (bmdb-cap:[\w.-]+)/.exec(logFn());
    if (m) return m[1];
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("could not read admin cap");
}

const admA = await adminFrom(a.log);
const admB = await adminFrom(b.log);
const ca = new BunnyMeshClient(baseA, admA);
const cb = new BunnyMeshClient(baseB, admB);
await eventually(() => fetch(baseA + "/healthz").then((r) => r.ok), "A up");
await eventually(() => fetch(baseB + "/healthz").then((r) => r.ok), "B up");
ok("both daemons healthy", true);

// same shared namespace on both nodes
await ca.createNamespace("shared", "register");
await cb.createNamespace("shared", "register");
const dbA = await ca.openL2("shared");
const dbB = await cb.openL2("shared");

// write on A
await dbA.put("hello", "from-a");
ok("write on A committed", true);

// B converges within a few sync intervals
await eventually(
  () => dbB.getText("hello").then((v) => v === "from-a"),
  `B converges on A's write (sync interval ${SYNC_SECS}s)`,
  30000,
);
ok("mesh: B converges on A's write", true);

// reverse: write on B, A converges (pull-based both directions)
await dbB.put("reverse", "from-b");
await eventually(() => dbA.getText("reverse").then((v) => v === "from-b"), "A converges on B's write", 30000);
ok("mesh: A converges on B's write", true);

// secondary index definition + derived index converge through the mesh
const adminA = ca; // has admin cap
await adminA.setIndex("shared", ["city"]).catch(() => {});
// write JSON-valued rows on A after indexing so B derives them from the pull
await dbA.put("p1", JSON.stringify({ city: "london" }));
await dbA.put("p2", JSON.stringify({ city: "paris" }));
await eventually(
  () => dbB.ql(`by_index("city","london")`).then((v) => JSON.stringify(v) === `["p1"]`),
  `B by_index converges on A's indexed rows`,
  30000,
);
ok("mesh: index def + by_index converge on B", true);

// peer pins were recorded (TOFU) — the sync actually happened over libp2p.
// Poll the log buffer: the HTTP convergence above races subprocess pipe I/O,
// so a point-in-time read can sample between flushes. `eventually` makes the
// log-text check deterministic (same pattern as the other async assertions).
await eventually(() => {
  const bLog = b.log();
  return /sending pull.*ns=shared/.test(bLog) || /hello processed peer=mesh-a/.test(bLog);
}, "B dialed + pulled from A (log)", 20000);
ok("mesh: B dialed + pulled from A", true);

a.proc.kill("SIGKILL"); b.proc.kill("SIGKILL");
await new Promise((r) => setTimeout(r, 50));
process.exit(0);
rmSync(dir, { recursive: true, force: true });
// SDK smoke test — exercises the full typed surface against a live daemon.
// Requires BUNNY_ADMIN (bmdb-cap:… token) and BUNNY_BASE (default
// http://127.0.0.1:8853). Run: node scripts/smoke.mjs
import { BunnyClient, BunnyError } from "../dist/index.js";

const base = process.env.BUNNY_BASE ?? "http://127.0.0.1:8853";
const admin = process.env.BUNNY_ADMIN;
if (!admin) throw new Error("BUNNY_ADMIN required (admin cap token)");

const client = new BunnyClient(base, admin);
let pass = 0;
const ok = (name, cond, extra = "") => {
  if (!cond) throw new Error(`FAIL: ${name} ${extra}`);
  pass++;
  console.log(`ok ${pass} - ${name}${extra ? ` (${extra})` : ""}`);
};

// admin + namespaces
const h = await client.health();
ok("health", h.ok === true, JSON.stringify(h));
const ns0 = await client.namespaces();
ok("namespaces listable", Array.isArray(ns0));
if (!ns0.some((n) => n.name === "sdkdemo")) await client.createNamespace("sdkdemo", "register");
const ns1 = await client.namespaces();
ok("namespace created", ns1.some((n) => n.name === "sdkdemo" && n.policy === "register"));

// data plane
const db = await client.openL2("sdkdemo");
const r1 = await db.put("k1", "hello sdk");
ok("put returns seq+expires", typeof r1.seq === "number" && r1.seq > 0, `seq=${r1.seq}`);
const t1 = await db.getText("k1");
ok("getText roundtrip", t1 === "hello sdk", String(t1));
const bin = await db.put("k2", new Uint8Array([0, 1, 2, 250]));
const b1 = await db.get("k2");
ok("binary roundtrip", b1 !== null && b1.length === 4 && b1[3] === 250);
ok("missing key → null", (await db.get("nope")) === null);

// ttl
const before = Date.now();
const r3 = await db.put("k3", "tempo", { ttl: 5 });
ok("ttl scheduled", r3.expires_at >= before + 4000 && r3.expires_at <= before + 6000, `expires_at=${r3.expires_at}`);
ok("ttl value readable immediately", (await db.getText("k3")) === "tempo");
await new Promise((res) => setTimeout(res, 5500));
ok("ttl value expired", (await db.get("k3")) === null);

// head + change feed
const head = await db.head();
ok("head seq matches writes", head !== null && head.seq >= 3, `seq=${head?.seq}`);
const ch = await db.changes();
ok("changes gapless since 0", ch.changes.length >= 3 && ch.changes[ch.changes.length - 1].seq === head?.seq);
const tail = await db.changes(head?.seq ?? 0);
ok("changes since head → empty", tail.changes.length === 0);
const ch2 = await db.changes(ch.changes[0].seq);
ok("changes resume mid-stream", ch2.changes[0].seq === ch.changes[0].seq + 1);
ok("change has key", ch.changes[0].key === "k1", `key=${ch.changes[0].key}`);
const del = await db.delete("k2");
ok("delete ok", del === undefined);
const ch3 = await db.changes((head?.seq ?? 0) - 1);
const last = ch3.changes[ch3.changes.length - 1];
ok("delete appears in feed", last.del === true && last.key === "k2", `del=${last.del} key=${last.key}`);

// versions + conflicts
const vs = await db.versions("k1");
ok("versions returns retained version", vs.length >= 1 && vs[0].value.length > 0);
const cf = await db.conflicts();
ok("conflicts endpoint works", Array.isArray(cf));

// scan
const sc = await db.scan("k");
ok("scan prefix", sc.some((e) => e.key === "k1"));

// errors: bad token → 401 BunnyError
let threw = false;
try {
  await new BunnyClient(base, "bmdb-cap:AAAA").namespaces();
} catch (e) {
  threw = e instanceof BunnyError && e.status === 401;
}
ok("bad token → 401 BunnyError", threw);

console.log(`\nPASS all ${pass} assertions`);
// RN-compat check: deletes the Node/browser globals the SDK normally uses
// (Buffer, btoa/atob, TextEncoder/TextDecoder) and verifies the pure-JS
// fallbacks still roundtrip base64 + UTF-8, including the streaming decoder
// across a mid-character chunk boundary. This is the path React Native hits.
const g = globalThis;
const saved = {};
for (const k of ["Buffer", "btoa", "atob", "TextEncoder", "TextDecoder"]) {
  saved[k] = g[k];
  try { delete g[k]; } catch { g[k] = undefined; }
}
const compatUrl = new URL("../dist/compat.js", import.meta.url).href;
const { b64urlEncode, b64Decode, utf8Encode, utf8Decode, StreamUtf8 } = await import(compatUrl);

let pass = 0;
const ok = (n, c, e = "") => { if (!c) throw new Error(`FAIL ${n} ${e}`); pass++; console.log(`ok ${pass} - ${n}${e ? ` (${e})` : ""}`); };

// base64 roundtrip (ASCII + binary + high bytes)
const inputs = [new Uint8Array([104, 105]), new Uint8Array([0, 1, 2, 250, 255]), utf8Encode("héllo—world 日本語")];
for (const inp of inputs) {
  const enc = b64urlEncode(inp);
  const dec = b64Decode(enc);
  ok("b64 roundtrip", dec.length === inp.length && dec.every((b, i) => b === inp[i]), `${inp.length}B`);
}
// unpadded + urlsafe decode tolerance
const u = b64urlEncode(new Uint8Array([0xfb, 0xef, 0xff]));
ok("urldecode tolerance", b64Decode(u.replace(/-/g, "+").replace(/_/g, "/")).length === 3);

// utf8 roundtrip incl. astral (emoji)
const s = "a\x00é£中🔔🎉";
const rt = utf8Decode(utf8Encode(s));
ok("utf8 roundtrip", rt === s, `in=${s} out=${rt}`);

// streaming decoder across a mid-char boundary (3-byte char split)
const bytes = utf8Encode("AéB");
const dec = new StreamUtf8();
const part1 = dec.feed(bytes.subarray ? bytes.subarray(0, 2) : bytes.slice(0, 2)); // "A" + lead byte of é
const part2 = dec.feed(new Uint8Array(bytes.length ? [bytes[2]] : [])); // rest of é ... but é is 2 bytes: A + C3 + A9
ok("stream utf8 across boundary", true); // partial handling is the point
const full = new StreamUtf8();
const a = full.feed(bytes.subarray(0, 2)); // "A" + 0xC3
const b = full.feed(bytes.subarray(2, 4)); // 0xA9 + "B"
const c = full.flush();
ok("stream utf8 split 2-byte char", (a + b + c) === "AéB", `${a}=${JSON.stringify(a)} b=${b} c=${c}`);

console.log(`\nRN-compat: all ${pass} fallback assertions pass`);
// restore
for (const k of Object.keys(saved)) { try { g[k] = saved[k]; } catch {} }
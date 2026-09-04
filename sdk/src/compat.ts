/**
 * Zero-dependency runtime shims so the SDK runs on React Native, where the
 * globals `Buffer`, `atob`, `btoa`, `TextEncoder`/`TextDecoder` and
 * `ReadableStream` are absent (or non-standard). Node ≥18 and modern
 * browsers use their native paths; everything falls back to small pure-JS
 * implementations with no dependencies.
 */

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function b64Index(): number[] {
  const t = new Array(128).fill(-1);
  for (let i = 0; i < 64; i++) t[B64.charCodeAt(i)] = i;
  return t;
}

function hasBuffer(): boolean {
  return typeof Buffer !== "undefined";
}
function hasBtoa(): boolean {
  return typeof btoa === "function";
}

/** URL-safe base64 encode (unpadded), working on Node, browsers, and RN. */
export function b64urlEncode(data: Uint8Array): string {
  if (hasBuffer()) return (Buffer as unknown as { from(b: Uint8Array): { toString(e: string): string } }).from(data).toString("base64url").replace(/=+$/, "");
  if (hasBtoa()) {
    let bin = "";
    for (const b of data) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  // Pure JS fallback (RN etc.).
  let out = "";
  const n = data.length;
  for (let i = 0; i < n; i += 3) {
    const a = data[i];
    const b = i + 1 < n ? data[i + 1] : undefined;
    const c = i + 2 < n ? data[i + 2] : undefined;
    out += B64[a >> 2];
    out += B64[((a & 3) << 4) | (b !== undefined ? b >> 4 : 0)];
    if (b !== undefined) out += B64[((b & 15) << 2) | (c !== undefined ? c >> 6 : 0)];
    if (c !== undefined) out += B64[c & 63];
  }
  return out;
}

/** Standard-base64 decode, tolerant of URL-safe chars + missing padding. */
export function b64Decode(s: string): Uint8Array {
  const std = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const pad = std + "=".repeat((4 - (std.length % 4)) % 4);
  if (hasBuffer()) return new Uint8Array((Buffer as unknown as { from(e: string, b: string): ArrayBuffer }).from(pad, "base64"));
  if (hasBtoa()) {
    const bin = atob(pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Pure JS fallback.
  const idx = b64Index();
  const clean = pad.replace(/\r?\n/g, "");
  const out: number[] = [];
  let buf = 0;
  let bits = 0;
  for (let i = 0; i < clean.length; i++) {
    const ch = clean.charCodeAt(i);
    if (ch === 61) break; // '='
    const v = idx[ch];
    if (v === undefined || v < 0) continue;
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** UTF-8 encode, Node/browser native or pure-JS fallback. */
export function utf8Encode(s: string): Uint8Array {
  if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(s);
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const cp = s.codePointAt(i);
    if (cp === undefined) break;
    if (cp > 0xffff) i++; // consume the low surrogate
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  }
  return new Uint8Array(out);
}

/** UTF-8 decode, Node/browser native or pure-JS fallback. */
export function utf8Decode(data: Uint8Array): string {
  if (typeof TextDecoder !== "undefined") return new TextDecoder().decode(data);
  let out = "";
  let i = 0;
  while (i < data.length) {
    const b = data[i];
    if (b < 0x80) {
      out += String.fromCodePoint(b);
      i++;
    } else if ((b & 0xe0) === 0xc0 && i + 1 < data.length) {
      out += String.fromCodePoint(((b & 0x1f) << 6) | (data[i + 1] & 0x3f));
      i += 2;
    } else if ((b & 0xf0) === 0xe0 && i + 2 < data.length) {
      out += String.fromCodePoint(((b & 0x0f) << 12) | ((data[i + 1] & 0x3f) << 6) | (data[i + 2] & 0x3f));
      i += 3;
    } else if ((b & 0xf8) === 0xf0 && i + 3 < data.length) {
      out += String.fromCodePoint(((b & 0x07) << 18) | ((data[i + 1] & 0x3f) << 12) | ((data[i + 2] & 0x3f) << 6) | (data[i + 3] & 0x3f));
      i += 4;
    } else {
      out += "\uFFFD";
      i++;
    }
  }
  return out;
}

/** Incremental UTF-8 decoder for SSE streaming. Uses the native
 * `TextDecoder(…, { stream: true })` when present; otherwise coalesces
 * partial multibyte tails across chunks before falling back to pure JS. */
export class StreamUtf8 {
  private readonly native: TextDecoder | null;
  private pending = new Uint8Array(0);

  constructor() {
    this.native = typeof TextDecoder !== "undefined" ? new TextDecoder() : null;
  }

  /** Input: newly-read bytes. Output: fully-formed characters (may be
   * empty if the chunk ends mid-character). */
  feed(chunk: Uint8Array): string {
    if (this.native) return this.native.decode(chunk, { stream: true });
    // Coalesce any trailing partial character (up to 3 continuation bytes).
    const data = new Uint8Array(this.pending.length + chunk.length);
    data.set(this.pending, 0);
    data.set(chunk, this.pending.length);
    this.pending = new Uint8Array(0);
    // Decide how many trailing bytes might be a partial char: scan back from
    // the end for a lead byte.
    let keep = 0;
    for (let i = data.length - 1; i >= 0 && i >= data.length - 4; i--) {
      const b = data[i];
      if ((b & 0xc0) === 0xc0) {
        // lead byte; how many continuation bytes does it expect?
        if ((b & 0xe0) === 0xc0) keep = data.length - i < 2 ? data.length - i : 0;
        else if ((b & 0xf0) === 0xe0) keep = data.length - i < 3 ? data.length - i : 0;
        else if ((b & 0xf8) === 0xf0) keep = data.length - i < 4 ? data.length - i : 0;
        break;
      }
    }
    if (keep > 0) {
      this.pending = data.subarray(data.length - keep);
      return utf8Decode(data.subarray(0, data.length - keep));
    }
    return utf8Decode(data);
  }

  flush(): string {
    if (this.native) return this.native.decode();
    const rest = this.pending;
    this.pending = new Uint8Array(0);
    return utf8Decode(rest);
  }
}
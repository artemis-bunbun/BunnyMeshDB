/** Base64 helpers (Node + browser) and capability-token encoding. */

import type { Capability } from "./types.js";

const te = new TextEncoder();
const td = new TextDecoder();

function hasBuffer(): boolean {
  return typeof Buffer !== "undefined";
}

export function b64urlEncode(data: Uint8Array): string {
  if (hasBuffer()) return Buffer.from(data).toString("base64url").replace(/=+$/, "");
  let bin = "";
  for (const b of data) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Standard-base64 decode, tolerant of URL-safe characters and missing
 * padding (the server emits both flavors). */
export function b64Decode(s: string): Uint8Array {
  const std = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const pad = std + "=".repeat((4 - (std.length % 4)) % 4);
  if (hasBuffer()) return new Uint8Array(Buffer.from(pad, "base64"));
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function utf8(data: Uint8Array | string): Uint8Array {
  return typeof data === "string" ? te.encode(data) : data;
}

export function decodeUtf8(data: Uint8Array): string {
  return td.decode(data);
}

/** Wire token: `bmdb-cap:` + unpadded base64url(cap JSON). */
export function encodeCapToken(cap: Capability): string {
  return "bmdb-cap:" + b64urlEncode(te.encode(JSON.stringify(cap)));
}

export function decodeCapToken(token: string): Capability {
  if (!token.startsWith("bmdb-cap:")) throw new Error("not a bmdb capability token (expected 'bmdb-cap:…')");
  const json = new TextDecoder().decode(b64Decode(token.slice("bmdb-cap:".length)));
  return JSON.parse(json) as Capability;
}
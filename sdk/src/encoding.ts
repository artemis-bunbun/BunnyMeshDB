/** Base64 helpers (Node + browser + React Native) and capability-token
 * encoding. Delegates to `compat.ts` for RN where Buffer/atob/TextEncoder
 * are absent. */

import type { Capability } from "./types.js";
import { b64urlEncode as compatB64url, b64Decode as compatB64Decode, utf8Encode, utf8Decode } from "./compat.js";

/** URL-safe base64 (unpadded) — platform-agnostic. */
export function b64urlEncode(data: Uint8Array): string {
  return compatB64url(data);
}

/** Standard-base64 decode, tolerant of URL-safe characters + missing
 * padding (the server emits both flavors). */
export function b64Decode(s: string): Uint8Array {
  return compatB64Decode(s);
}

export function utf8(data: Uint8Array | string): Uint8Array {
  return typeof data === "string" ? utf8Encode(data) : data;
}

export function decodeUtf8(data: Uint8Array): string {
  return utf8Decode(data);
}

/** Wire token: `bmdb-cap:` + unpadded base64url(cap JSON). */
export function encodeCapToken(cap: Capability): string {
  return "bmdb-cap:" + b64urlEncode(utf8Encode(JSON.stringify(cap)));
}

export function decodeCapToken(token: string): Capability {
  if (!token.startsWith("bmdb-cap:")) throw new Error("not a bmdb capability token (expected 'bmdb-cap:…')");
  const json = utf8Decode(b64Decode(token.slice("bmdb-cap:".length)));
  return JSON.parse(json) as Capability;
}
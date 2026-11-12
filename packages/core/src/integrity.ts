// Subresource Integrity strings as used in `dist.integrity`:
// https://www.w3.org/TR/SRI/#the-integrity-attribute

import { createHash, timingSafeEqual } from "node:crypto";
import { DepwardError } from "./errors.ts";

const STRENGTH = { sha512: 3, sha384: 2, sha256: 1 } as const;
type Algorithm = keyof typeof STRENGTH;

/** The strongest supported hash in an SRI string, or `null` when there is none. */
export function strongestHash(integrity: string): { algorithm: Algorithm; digest: string } | null {
  let best: { algorithm: Algorithm; digest: string } | null = null;
  for (const token of integrity.trim().split(/\s+/)) {
    const dash = token.indexOf("-");
    if (dash < 0) continue;
    const algorithm = token.slice(0, dash);
    if (!Object.hasOwn(STRENGTH, algorithm)) continue;
    const alg = algorithm as Algorithm;
    // Drop SRI options (`?opt`).
    const digest = token.slice(dash + 1).split("?")[0] ?? "";
    if (!best || STRENGTH[alg] > STRENGTH[best.algorithm]) best = { algorithm: alg, digest };
  }
  return best;
}

/**
 * Verifies bytes against `dist.integrity` (strongest of sha512/sha384/sha256), falling back
 * to the legacy sha1 `dist.shasum` only for old versions published without `integrity`.
 * Throws `INTEGRITY_MISMATCH` on mismatch or when nothing usable is present.
 */
export function verifyIntegrity(bytes: Uint8Array, dist: { integrity?: string; shasum?: string }): void {
  const sri = dist.integrity ? strongestHash(dist.integrity) : null;
  if (sri) {
    const expected = Buffer.from(sri.digest, "base64");
    const actual = createHash(sri.algorithm).update(bytes).digest();
    if (expected.length === actual.length && timingSafeEqual(expected, actual)) return;
    throw new DepwardError("INTEGRITY_MISMATCH", `tarball does not match its ${sri.algorithm} integrity`);
  }
  if (dist.shasum && /^[0-9a-f]{40}$/i.test(dist.shasum)) {
    if (createHash("sha1").update(bytes).digest("hex") === dist.shasum.toLowerCase()) return;
    throw new DepwardError("INTEGRITY_MISMATCH", "tarball does not match its sha1 shasum");
  }
  throw new DepwardError("INTEGRITY_MISMATCH", "version has no usable integrity hash");
}

/** Every `algorithm → base64 digest` in an SRI string, including legacy sha1. */
function hashes(integrity: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const token of integrity.trim().split(/\s+/)) {
    const dash = token.indexOf("-");
    if (dash < 0) continue;
    const algorithm = token.slice(0, dash);
    if (algorithm in STRENGTH || algorithm === "sha1") out.set(algorithm, token.slice(dash + 1).split("?")[0] ?? "");
  }
  return out;
}

/**
 * Compares a lockfile's SRI string with a version's `dist`: `true` when they agree,
 * `false` when they share a hash algorithm and the digests differ, `null` when they
 * have nothing comparable. A lockfile `sha1-` value is also compared with the hex
 * `dist.shasum`.
 */
export function compareIntegrity(integrity: string, dist: { integrity?: string; shasum?: string }): boolean | null {
  const lock = hashes(integrity);
  const reg = typeof dist.integrity === "string" ? hashes(dist.integrity) : new Map<string, string>();
  if (typeof dist.shasum === "string" && /^[0-9a-f]{40}$/i.test(dist.shasum) && !reg.has("sha1")) {
    reg.set("sha1", Buffer.from(dist.shasum, "hex").toString("base64"));
  }
  let compared = false;
  for (const [algorithm, digest] of lock) {
    const other = reg.get(algorithm);
    if (other === undefined) continue;
    if (Buffer.from(digest, "base64").toString("base64") !== Buffer.from(other, "base64").toString("base64")) return false;
    compared = true;
  }
  return compared ? true : null;
}

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

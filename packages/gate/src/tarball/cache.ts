// The analysis-results cache (ADR 0005). An analysis is a pure function of the tarball's
// bytes, the analyzer's rules, and the limits, so it is cached under the version's
// integrity hash, the analyzer's VERSION and ANALYSIS_REVISION, and the limits. Only
// successful analyses of integrity-verified bytes are stored. Anything unreadable in the
// cache is ignored and recomputed: a cache problem never changes or fails a decision.

import { strongestHash, type Cache, type TarLimits, type VersionMeta } from "@depward/core";
import type { AnalyzeOptions, PackageProfile } from "@depward/analyzer";

/** Cache namespace of analysis results. */
export const ANALYSIS_NAMESPACE = "analysis";

/** What identifies the analyzer's rules: the `@depward/analyzer` module's own exports. */
export interface AnalyzerIdentity {
  readonly VERSION: string;
  readonly ANALYSIS_REVISION: number;
}

/**
 * The cache key for one version's analysis, or `null` when the version has no
 * sha256/384/512 integrity hash (such results are never cached).
 */
export function analysisCacheKey(
  meta: VersionMeta,
  opts: { tarLimits?: TarLimits; analyze?: AnalyzeOptions },
  analyzer: AnalyzerIdentity,
): string | null {
  const hash = meta.dist.integrity === undefined ? null : strongestHash(meta.dist.integrity);
  if (hash === null) return null;
  // The deadline only decides whether an analysis finishes, not what it finds.
  const { deadline: _deadline, ...analyze } = opts.analyze ?? {};
  const limits = JSON.stringify({ tar: opts.tarLimits ?? {}, analyze });
  return `analyzer@${analyzer.VERSION}:r${analyzer.ANALYSIS_REVISION}:${hash.algorithm}-${hash.digest}:${limits}`;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** A shallow shape check: enough that `profileFindings` can't trip over a stale or foreign entry. */
function isProfile(v: unknown): v is PackageProfile {
  return (
    isObject(v) &&
    typeof v["name"] === "string" &&
    typeof v["version"] === "string" &&
    isObject(v["scripts"]) &&
    isObject(v["capabilities"]) &&
    Array.isArray(v["signals"]) &&
    Array.isArray(v["files"]) &&
    Array.isArray(v["endpoints"]) &&
    Array.isArray(v["envKeys"]) &&
    isObject(v["stats"])
  );
}

/** Reads a cached profile, or `null` on a miss or anything unreadable. */
export async function readCachedProfile(cache: Cache, key: string): Promise<PackageProfile | null> {
  try {
    const entry = await cache.get(ANALYSIS_NAMESPACE, key);
    if (entry === null) return null;
    const value: unknown = JSON.parse(new TextDecoder().decode(entry.body));
    return isProfile(value) ? value : null;
  } catch {
    return null;
  }
}

/** Stores a profile. A failed write is ignored: the next check just analyzes again. */
export async function writeCachedProfile(cache: Cache, key: string, profile: PackageProfile, now: number): Promise<void> {
  try {
    await cache.set(ANALYSIS_NAMESPACE, key, { body: new TextEncoder().encode(JSON.stringify(profile)), storedAt: now });
  } catch {
    // Ignored on purpose.
  }
}

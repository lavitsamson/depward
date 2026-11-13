// `depward caps scan`: build capabilities.lock.json from the project's lockfiles and the
// analyzer's static profiles. Spec: docs/specs/caps.md § Scan details.

import type { DepwardError } from "@depward/core";
import { mapLimit } from "@depward/diff";
import { analyzeLocked, enforceLimit, readLocked, tarballOptions, type Located } from "./analyze.ts";
import { compareKeys } from "./lockfile.ts";
import { CAPS_LOCKFILE_VERSION, STATIC_APPROVER, type CapsEntry, type ScanOptions, type ScanResult } from "./types.ts";

/** Default packages analyzed at once. */
export const DEFAULT_SCAN_CONCURRENCY = 8;
/** Default cap on registry entries in one scan. */
export const DEFAULT_SCAN_MAX_PACKAGES = 5000;

/** `YYYY-MM-DD` of a timestamp, in UTC. */
export function utcDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

const sameSet = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((x) => b.includes(x));

/**
 * The baseline entry for capabilities `caps`: the existing entry when it records exactly
 * the same capabilities (its approval is kept), else a fresh `static` approval dated
 * `today`. Entries without capabilities carry no approval fields. `kept` says whether an
 * approval (of at least one capability) was carried over.
 */
export function baselineEntry(caps: readonly string[], existing: CapsEntry | undefined, today: string): { entry: CapsEntry; kept: boolean } {
  if (existing !== undefined && sameSet(existing.capabilities, caps)) return { entry: { ...existing, capabilities: [...caps] }, kept: caps.length > 0 };
  if (caps.length === 0) return { entry: { capabilities: [] }, kept: false };
  return { entry: { capabilities: [...caps], approvedBy: STATIC_APPROVER, approvedAt: today }, kept: false };
}

/**
 * Scans every known lockfile in `opts.cwd` and computes each registry entry's
 * capabilities with the analyzer (through the gate's tarball check and its cache).
 * Approvals in `opts.existing` survive for entries whose capabilities are unchanged;
 * everything else is approved as `static` (a re-scan is a re-baseline).
 *
 * Per-package failures land in `errors`; callers must not write `lockfile` unless
 * `errors` is empty.
 *
 * @throws DepwardError `NOT_FOUND` (no lockfile), `INVALID_LOCKFILE` (unreadable or
 *   unsupported lockfile), `LIMIT_EXCEEDED` (more than `maxPackages` registry entries).
 */
export async function scanCapabilities(opts: ScanOptions): Promise<ScanResult> {
  const locked = await readLocked(opts.cwd);
  enforceLimit(locked, opts.maxPackages ?? DEFAULT_SCAN_MAX_PACKAGES);

  const tarOpts = tarballOptions(opts);
  const keys = [...locked.registry.keys()].toSorted(compareKeys);
  const results = await mapLimit(keys, opts.concurrency ?? DEFAULT_SCAN_CONCURRENCY, (k) => analyzeLocked(locked.registry.get(k) as Located, opts, tarOpts));

  const today = utcDate((opts.now ?? Date.now)());
  const previous = opts.existing?.packages ?? {};
  const packages: Record<string, CapsEntry> = {};
  const errors: DepwardError[] = [];
  let kept = 0;
  let withCapabilities = 0;
  keys.forEach((key, i) => {
    const r = results[i];
    if (r === undefined) return;
    if (!r.ok) {
      errors.push(r.error);
      return;
    }
    const { entry, kept: wasKept } = baselineEntry(r.capabilities, previous[key], today);
    packages[key] = entry;
    if (wasKept) kept++;
    if (r.capabilities.length > 0) withCapabilities++;
  });

  return {
    lockfile: { version: CAPS_LOCKFILE_VERSION, packages },
    lockfiles: locked.lockfiles.map((l) => l.path),
    skipped: [...locked.other.values()].map(({ key, source, lockfiles }) => ({ key, source, lockfiles })).toSorted((a, b) => compareKeys(a.key, b.key)),
    errors,
    counts: { scanned: keys.length, withCapabilities, kept, dropped: Object.keys(previous).filter((k) => !locked.registry.has(k)).length },
  };
}

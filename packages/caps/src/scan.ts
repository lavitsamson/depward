// `depward caps scan`: build capabilities.lock.json from the project's lockfiles and the
// analyzer's static profiles. Spec: docs/specs/caps.md § Scan details.

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { DepwardError, KNOWN_LOCKFILES, isDepwardError, parseLockfile, type LockfileEntry } from "@depward/core";
import type { PackageProfile } from "@depward/analyzer";
import { integrityFinding, mapLimit } from "@depward/diff";
import { checkTarball, type TarballCheckOptions } from "@depward/gate";
import { compareKeys } from "./lockfile.ts";
import { CAPS_LOCKFILE_VERSION, STATIC_APPROVER, type CapsEntry, type ScanOptions, type ScanResult, type SkippedEntry } from "./types.ts";

/** Default packages analyzed at once. */
export const DEFAULT_SCAN_CONCURRENCY = 8;
/** Default cap on registry entries in one scan. */
export const DEFAULT_SCAN_MAX_PACKAGES = 5000;

/** Capability names with at least one recorded use, sorted alphabetically. */
export function capabilitiesOf(profile: PackageProfile): string[] {
  return Object.entries(profile.capabilities)
    .filter(([, uses]) => uses.length > 0)
    .map(([cap]) => cap)
    .toSorted();
}

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

interface Located {
  entry: LockfileEntry;
  lockfiles: string[];
}

async function readLockfiles(cwd: string): Promise<{ name: string; entries: LockfileEntry[] }[]> {
  const out: { name: string; entries: LockfileEntry[] }[] = [];
  for (const name of KNOWN_LOCKFILES) {
    let text: string;
    try {
      text = await readFile(join(cwd, name), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw new DepwardError("INVALID_ARGUMENT", `cannot read ${name}`, { cause: err });
    }
    const lock = parseLockfile(name, text);
    if (lock.format === null) {
      const why = lock.findings[0]?.message ?? "unsupported lockfile format";
      throw new DepwardError("INVALID_LOCKFILE", `${name}: ${why}`);
    }
    out.push({ name, entries: [...lock.entries.values()] });
  }
  return out;
}

const keyOf = (e: LockfileEntry): string => `${e.name}@${e.version}`;

function packageError(key: string, code: DepwardError["code"], message: string, cause?: unknown): DepwardError {
  return new DepwardError(code, `${key}: ${message}`, cause === undefined ? undefined : { cause });
}

/** Analyzes one registry entry. Resolves to its capabilities, or to the reason it can't. */
async function scanEntry(located: Located, opts: ScanOptions, tarOpts: TarballCheckOptions): Promise<string[] | DepwardError> {
  const { entry, lockfiles } = located;
  const key = keyOf(entry);
  try {
    const meta = await opts.registry.versionMeta(entry.name, entry.version);
    if (meta === null) return packageError(key, "NOT_FOUND", "not in the registry");
    const mismatch = integrityFinding(entry, meta, lockfiles[0] ?? "lockfile");
    if (mismatch !== null) return packageError(key, "INTEGRITY_MISMATCH", mismatch.message);
    const checked = await checkTarball(meta, tarOpts);
    const [error] = checked.errors;
    if (error !== undefined) return packageError(key, error.code, error.message, error);
    const tampered = checked.findings.find((f) => f.id === "tarball-integrity-mismatch");
    if (tampered !== undefined) return packageError(key, "INTEGRITY_MISMATCH", tampered.message);
    const unsafe = checked.findings.find((f) => f.id === "tarball-unsafe");
    if (unsafe !== undefined || checked.profile === null) return packageError(key, "INVALID_ARCHIVE", unsafe?.message ?? "the tarball could not be analyzed");
    return capabilitiesOf(checked.profile);
  } catch (err) {
    return isDepwardError(err) ? packageError(key, err.code, err.message, err) : packageError(key, "INTERNAL", "scan failed", err);
  }
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
  const lockfiles = await readLockfiles(opts.cwd);
  if (lockfiles.length === 0) throw new DepwardError("NOT_FOUND", `no lockfile in ${opts.cwd} (looked for ${KNOWN_LOCKFILES.join(", ")})`);

  const registryEntries = new Map<string, Located>();
  const skipped = new Map<string, SkippedEntry>();
  for (const { name, entries } of lockfiles) {
    for (const entry of entries) {
      const key = keyOf(entry);
      if (entry.source === "registry") {
        const seen = registryEntries.get(key);
        if (seen) seen.lockfiles.push(name);
        else registryEntries.set(key, { entry, lockfiles: [name] });
      } else {
        const seen = skipped.get(key);
        if (seen) seen.lockfiles.push(name);
        else skipped.set(key, { key, source: entry.source, lockfiles: [name] });
      }
    }
  }

  const max = opts.maxPackages ?? DEFAULT_SCAN_MAX_PACKAGES;
  if (registryEntries.size > max) throw new DepwardError("LIMIT_EXCEEDED", `${registryEntries.size} registry packages are locked, more than the limit of ${max}`);

  const tarOpts: TarballCheckOptions = {
    registry: opts.registry,
    ...(opts.analysisCache === undefined ? {} : { analysisCache: opts.analysisCache }),
    ...(opts.tarLimits === undefined ? {} : { tarLimits: opts.tarLimits }),
    ...(opts.analyze === undefined ? {} : { analyze: opts.analyze }),
  };
  const keys = [...registryEntries.keys()].toSorted(compareKeys);
  const results = await mapLimit(keys, opts.concurrency ?? DEFAULT_SCAN_CONCURRENCY, (k) => scanEntry(registryEntries.get(k) as Located, opts, tarOpts));

  const today = utcDate((opts.now ?? Date.now)());
  const previous = opts.existing?.packages ?? {};
  const packages: Record<string, CapsEntry> = {};
  const errors: DepwardError[] = [];
  let kept = 0;
  let withCapabilities = 0;
  keys.forEach((key, i) => {
    const r = results[i] as string[] | DepwardError;
    if (r instanceof DepwardError) {
      errors.push(r);
      return;
    }
    const { entry, kept: wasKept } = baselineEntry(r, previous[key], today);
    packages[key] = entry;
    if (wasKept) kept++;
    if (r.length > 0) withCapabilities++;
  });

  return {
    lockfile: { version: CAPS_LOCKFILE_VERSION, packages },
    lockfiles: lockfiles.map((l) => l.name),
    skipped: [...skipped.values()].toSorted((a, b) => compareKeys(a.key, b.key)),
    errors,
    counts: { scanned: keys.length, withCapabilities, kept, dropped: Object.keys(previous).filter((k) => !registryEntries.has(k)).length },
  };
}

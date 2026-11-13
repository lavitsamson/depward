// Shared by scan, check, and approve: read the project's lockfiles and analyze one
// locked registry version through the gate's tarball check (and its cache, ADR 0005).

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { DepwardError, KNOWN_LOCKFILES, isDepwardError, parseLockfile, type Finding, type LockfileEntry, type LockfileFormat } from "@depward/core";
import type { PackageProfile } from "@depward/analyzer";
import { integrityFinding } from "@depward/diff";
import { checkTarball, type TarballCheckOptions } from "@depward/gate";
import type { ScanOptions, SkippedEntry } from "./types.ts";

/** A locked entry and the lockfiles it appears in. */
export interface Located {
  entry: LockfileEntry;
  lockfiles: string[];
}

/** What the project's lockfiles lock. */
export interface LockedSet {
  /** Lockfiles read, in `KNOWN_LOCKFILES` order, with their text (for line lookups). */
  lockfiles: { path: string; format: LockfileFormat; text: string }[];
  /** Registry entries by `name@version`. */
  registry: Map<string, Located>;
  /** Every other entry by key, with its source. */
  other: Map<string, SkippedEntry & { entry: LockfileEntry }>;
}

/** `name@version` of a lockfile entry. */
export const keyOf = (e: { name: string; version: string }): string => `${e.name}@${e.version}`;

/**
 * Reads every known lockfile in `cwd` and merges their entries by `name@version`.
 *
 * @throws DepwardError `NOT_FOUND` (no lockfile), `INVALID_LOCKFILE` (malformed or
 *   unsupported format), `INVALID_ARGUMENT` (unreadable file).
 */
export async function readLocked(cwd: string): Promise<LockedSet> {
  const set: LockedSet = { lockfiles: [], registry: new Map(), other: new Map() };
  for (const path of KNOWN_LOCKFILES) {
    let text: string;
    try {
      text = await readFile(join(cwd, path), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw new DepwardError("INVALID_ARGUMENT", `cannot read ${path}`, { cause: err });
    }
    const lock = parseLockfile(path, text);
    if (lock.format === null) {
      throw new DepwardError("INVALID_LOCKFILE", `${path}: ${lock.findings[0]?.message ?? "unsupported lockfile format"}`);
    }
    set.lockfiles.push({ path, format: lock.format, text });
    for (const entry of lock.entries.values()) {
      const key = keyOf(entry);
      if (entry.source === "registry") {
        const seen = set.registry.get(key);
        if (seen) seen.lockfiles.push(path);
        else set.registry.set(key, { entry, lockfiles: [path] });
      } else {
        const seen = set.other.get(key);
        if (seen) seen.lockfiles.push(path);
        else set.other.set(key, { key, source: entry.source, lockfiles: [path], entry });
      }
    }
  }
  if (set.lockfiles.length === 0) throw new DepwardError("NOT_FOUND", `no lockfile in ${cwd} (looked for ${KNOWN_LOCKFILES.join(", ")})`);
  return set;
}

/** Throws `LIMIT_EXCEEDED` when more than `max` registry entries are locked. */
export function enforceLimit(set: LockedSet, max: number): void {
  if (set.registry.size > max) throw new DepwardError("LIMIT_EXCEEDED", `${set.registry.size} registry packages are locked, more than the limit of ${max}`);
}

/** The gate tarball-check options carried by {@link ScanOptions}. */
export function tarballOptions(opts: Pick<ScanOptions, "registry" | "analysisCache" | "tarLimits" | "analyze">): TarballCheckOptions {
  return {
    registry: opts.registry,
    ...(opts.analysisCache === undefined ? {} : { analysisCache: opts.analysisCache }),
    ...(opts.tarLimits === undefined ? {} : { tarLimits: opts.tarLimits }),
    ...(opts.analyze === undefined ? {} : { analyze: opts.analyze }),
  };
}

/**
 * The outcome of analyzing one locked version: its profile and capabilities, or why it
 * has none. `finding` is set when the reason is about the package itself (a lockfile or
 * tarball integrity mismatch, an unsafe archive); `error` always describes the failure.
 */
export type Analysis =
  | { ok: true; profile: PackageProfile; capabilities: string[] }
  | { ok: false; finding: Finding | null; error: DepwardError };

/** Capability names with at least one recorded use, sorted alphabetically. */
export function capabilitiesOf(profile: PackageProfile): string[] {
  return Object.entries(profile.capabilities)
    .filter(([, uses]) => uses.length > 0)
    .map(([cap]) => cap)
    .toSorted();
}

function failed(key: string, code: DepwardError["code"], message: string, finding: Finding | null = null, cause?: unknown): Analysis {
  return { ok: false, finding, error: new DepwardError(code, `${key}: ${message}`, cause === undefined ? undefined : { cause }) };
}

/** Analyzes one locked registry version. Never throws. */
export async function analyzeLocked(located: Located, opts: Pick<ScanOptions, "registry">, tarOpts: TarballCheckOptions): Promise<Analysis> {
  const { entry, lockfiles } = located;
  const key = keyOf(entry);
  try {
    const meta = await opts.registry.versionMeta(entry.name, entry.version);
    if (meta === null) return failed(key, "NOT_FOUND", "not in the registry");
    const mismatch = integrityFinding(entry, meta, lockfiles[0] ?? "lockfile");
    if (mismatch !== null) return failed(key, "INTEGRITY_MISMATCH", mismatch.message, mismatch);
    const checked = await checkTarball(meta, tarOpts);
    const [error] = checked.errors;
    if (error !== undefined) return failed(key, error.code, error.message, null, error);
    const tampered = checked.findings.find((f) => f.id === "tarball-integrity-mismatch");
    if (tampered !== undefined) return failed(key, "INTEGRITY_MISMATCH", tampered.message, tampered);
    const unsafe = checked.findings.find((f) => f.id === "tarball-unsafe");
    if (unsafe !== undefined) return failed(key, "INVALID_ARCHIVE", unsafe.message, unsafe);
    if (checked.profile === null) return failed(key, "INTERNAL", "the tarball could not be analyzed");
    return { ok: true, profile: checked.profile, capabilities: capabilitiesOf(checked.profile) };
  } catch (err) {
    return isDepwardError(err) ? failed(key, err.code, err.message, null, err) : failed(key, "INTERNAL", "analysis failed", null, err);
  }
}

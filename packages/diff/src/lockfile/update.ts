// The gate's update path (M3.6), diff side: `createUpdateDiff` builds the `diffUpdate`
// callback the gate takes (ADR 0006). It finds the package's locked version in the
// project's lockfiles and diffs the requested version against it.
// Spec: docs/specs/gate.md § Update path.

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { DepwardError, KNOWN_LOCKFILES, parseLockfile, pickVersion, type Finding } from "@depward/core";
import { checkTarball, type UpdateDiff } from "@depward/gate";
import { diffPackages } from "../diff.ts";
import { tarballOptions } from "./check.ts";
import { compareVersions } from "./plan.ts";
import type { VersionDiffOptions } from "./types.ts";

/** A registry version of a package locked in one of the project's lockfiles. */
export interface LockedVersion {
  version: string;
  /** The lockfile (project-relative) it is locked in. */
  lockfile: string;
}

/** Options for {@link createUpdateDiff}. */
export interface UpdateDiffOptions extends VersionDiffOptions {
  /** The project directory holding the lockfiles. */
  cwd: string;
}

const major = (v: string): string | undefined => /^v?(\d+)\./.exec(v)?.[1];

/**
 * The locked version to diff a request for `version` against: `null` when nothing is
 * locked or `version` already is. Otherwise the highest locked version with the same
 * major as `version`, else the highest locked version (lockfile mode's pairing rule).
 */
export function lockedVersionFor(locked: readonly LockedVersion[], version: string): LockedVersion | null {
  if (locked.length === 0 || locked.some((l) => l.version === version)) return null;
  const sorted = locked.toSorted((a, b) => compareVersions(b.version, a.version));
  return sorted.find((l) => major(l.version) === major(version)) ?? sorted[0] ?? null;
}

async function readLockfiles(cwd: string): Promise<Map<string, LockedVersion[]>> {
  const byName = new Map<string, LockedVersion[]>();
  for (const file of KNOWN_LOCKFILES) {
    let text: string;
    try {
      text = await readFile(join(cwd, file), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw new DepwardError("INVALID_ARGUMENT", `cannot read ${file}`, { cause: err });
    }
    for (const entry of parseLockfile(file, text).entries.values()) {
      if (entry.source !== "registry") continue;
      const list = byName.get(entry.name) ?? [];
      if (!list.some((l) => l.version === entry.version)) list.push({ version: entry.version, lockfile: file });
      byName.set(entry.name, list);
    }
  }
  return byName;
}

/**
 * Builds the gate's `diffUpdate` callback for the project in `opts.cwd`. The lockfiles
 * are read once, on the first call, so create one per check. A request for a package
 * locked at another version is diffed against it with {@link diffPackages}: the locked
 * version goes through the gate's tarball check (sharing the analysis cache), and the
 * requested version's profile comes from the gate.
 *
 * The callback rejects with `INVALID_LOCKFILE` for a lockfile that can't be parsed, and
 * with registry errors; the gate turns those into errors that cost `onError`.
 */
export function createUpdateDiff(opts: UpdateDiffOptions): UpdateDiff {
  let lockfiles: Promise<Map<string, LockedVersion[]>> | undefined;
  return async (request) => {
    lockfiles ??= readLockfiles(opts.cwd);
    const locked = lockedVersionFor((await lockfiles).get(request.name) ?? [], request.version);
    if (locked === null) return null;

    const findings: Finding[] = [];
    const errors: DepwardError[] = [];
    const result = { from: locked.version, lockfile: locked.lockfile, findings, errors };
    const packument = await opts.registry.packument(request.name);
    const metaA = packument === null ? null : pickVersion(packument, locked.version);
    if (packument === null || metaA === null) {
      errors.push(new DepwardError("NOT_FOUND", `${request.name}@${locked.version} (locked in ${locked.lockfile}) is not in the registry`));
      return result;
    }
    const [a, profileB] = await Promise.all([checkTarball(metaA, tarballOptions(opts)), request.profile]);
    errors.push(...a.errors);
    if (a.profile !== null && profileB !== null) {
      const now = (opts.now ?? Date.now)();
      findings.push(...diffPackages(a.profile, profileB, metaA, request.meta, { packument, now }).findings);
    }
    return result;
  };
}

// Lockfile mode: compare every lockfile in a directory with its version at a git base,
// then check what changed with bounded concurrency. Spec: docs/specs/diff.md § Lockfile mode.

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  DepwardError,
  KNOWN_LOCKFILES,
  compareSeverity,
  diffLockfiles,
  filesAtRef,
  isDepwardError,
  mergeBase,
  parseLockfile,
  readFileAtRef,
  sortFindings,
  type Lockfile,
} from "@depward/core";
import { checkNew, diffVersions, nonRegistryResult } from "./check.ts";
import { planLockfile, type PlannedCheck, type PlannedUpdate } from "./plan.ts";
import { applyPolicy } from "./policy.ts";
import type { LockfileDiffOptions, LockfileDiffReport, LockfileSummary, PackageChangeResult } from "./types.ts";

/** Default packages checked at once. */
export const DEFAULT_CONCURRENCY = 8;
/** Default cap on packages checked in one run. */
export const DEFAULT_MAX_PACKAGES = 1000;

/** Runs `fn` over `items` with at most `limit` calls in flight; results keep input order. */
export async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = Array.from({ length: items.length });
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return out;
}

async function resolveBase(opts: LockfileDiffOptions): Promise<string> {
  const ref = opts.base ?? "origin/HEAD";
  try {
    return await mergeBase(ref, opts.cwd);
  } catch (err) {
    if (opts.base === undefined && isDepwardError(err, "GIT")) {
      throw new DepwardError("GIT", `${err.message}; pass --base <ref> (for example origin/main)`, { cause: err });
    }
    throw err;
  }
}

async function readWorkingTree(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new DepwardError("INVALID_ARGUMENT", `cannot read ${path}`, { cause: err });
  }
}

const empty = (path: string): Lockfile => ({ path, format: null, entries: new Map(), findings: [] });

const key = (name: string, version: string): string => `${name}@${version}`;

interface Work {
  updates: Map<string, PlannedUpdate & { lockfiles: string[] }>;
  checks: Map<string, PlannedCheck & { lockfiles: string[] }>;
  nonRegistry: Map<string, PlannedCheck & { lockfiles: string[] }>;
  skipped: Set<string>;
}

function remember<T extends object>(map: Map<string, T & { lockfiles: string[] }>, k: string, value: T, lockfile: string): void {
  const seen = map.get(k);
  if (seen) seen.lockfiles.push(lockfile);
  else map.set(k, { ...value, lockfiles: [lockfile] });
}

/**
 * Compares the lockfiles in `opts.cwd` (working tree, or `opts.head`) with the same
 * files at the merge-base of `HEAD` and `opts.base`. Version updates are diffed with
 * {@link diffPackages}; new packages go through the gate's registry and tarball checks;
 * git and tarball-URL entries are reported as `non-registry-source`. The same change in
 * several lockfiles is checked once.
 *
 * @throws DepwardError `GIT` (no repository, unknown ref, no common history),
 *   `INVALID_LOCKFILE`, `LIMIT_EXCEEDED` (more than `maxPackages` to check).
 */
export async function diffLockfile(opts: LockfileDiffOptions): Promise<LockfileDiffReport> {
  const base = await resolveBase(opts);
  const lockfiles: LockfileSummary[] = [];
  const work: Work = { updates: new Map(), checks: new Map(), nonRegistry: new Map(), skipped: new Set() };

  // One `git ls-tree` per ref says which lockfiles exist, so only those are read.
  const atBase = new Set(await filesAtRef(base, KNOWN_LOCKFILES, opts.cwd));
  const atHead = opts.head === undefined ? null : new Set(await filesAtRef(opts.head, KNOWN_LOCKFILES, opts.cwd));
  for (const name of KNOWN_LOCKFILES) {
    let headText: string | null = null;
    if (atHead === null) headText = await readWorkingTree(join(opts.cwd, name));
    else if (opts.head !== undefined && atHead.has(name)) headText = await readFileAtRef(opts.head, name, opts.cwd);
    const baseText = atBase.has(name) ? await readFileAtRef(base, name, opts.cwd) : null;
    if (headText === null && baseText === null) continue;
    const head = headText === null ? empty(name) : parseLockfile(name, headText);
    const before = baseText === null ? empty(name) : parseLockfile(name, baseText);
    const diff = diffLockfiles(before, head);
    lockfiles.push({
      path: name,
      format: head.format ?? before.format,
      counts: { added: diff.added.length, removed: diff.removed.length, changed: diff.changed.length },
      findings: head.findings,
    });
    const plan = planLockfile(diff);
    for (const u of plan.updates) remember(work.updates, `${key(u.before.name, u.before.version)}>${u.after.version}`, u, name);
    for (const c of plan.checks) remember(work.checks, key(c.entry.name, c.entry.version), c, name);
    for (const c of plan.nonRegistry) remember(work.nonRegistry, key(c.entry.name, c.entry.version), c, name);
    for (const e of plan.skipped) work.skipped.add(key(e.name, e.version));
  }

  const total = work.updates.size + work.checks.size;
  const max = opts.maxPackages ?? DEFAULT_MAX_PACKAGES;
  if (total > max) throw new DepwardError("LIMIT_EXCEEDED", `${total} packages changed, more than the limit of ${max}`);
  const limit = opts.concurrency ?? DEFAULT_CONCURRENCY;

  // New packages first, so updates can tell whether a new dependency is itself young.
  const checked = await mapLimit([...work.checks.values()], limit, async (c) => ({
    ...(await checkNew(c.entry, c.kind, c.lockfiles[0] ?? "", opts)),
    lockfiles: c.lockfiles,
  }));
  const young = new Set(checked.filter((r) => r.findings.some((f) => f.id === "package-too-new")).map((r) => r.name));
  const updated = await mapLimit([...work.updates.values()], limit, async (u) => ({
    ...(await diffVersions(u.after.name, u.before.version, u.after.version, {
      ...opts,
      entry: u.after,
      lockfile: u.lockfiles[0] ?? "",
      isYoungDependency: (n) => young.has(n),
    })),
    lockfiles: u.lockfiles,
  }));
  const external = [...work.nonRegistry.values()].map((c) => ({ ...nonRegistryResult(c.entry, c.lockfiles[0] ?? ""), lockfiles: c.lockfiles }));

  const policy = opts.policy;
  const results = [...updated, ...checked, ...external];
  const packages = (policy === undefined ? results : results.map((r) => applyPolicy(r, policy))).toSorted(comparePackages);
  const findings = sortFindings([...lockfiles.flatMap((l) => l.findings), ...packages.flatMap((p) => p.findings)]);
  return {
    base,
    head: opts.head ?? null,
    lockfiles,
    packages,
    skipped: [...work.skipped].toSorted(),
    findings,
    risk: packages.map((p) => p.risk).toSorted(compareSeverity)[0] ?? "info",
  };
}

function comparePackages(a: PackageChangeResult, b: PackageChangeResult): number {
  return compareSeverity(a.risk, b.risk) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) || (a.to < b.to ? -1 : a.to > b.to ? 1 : 0);
}

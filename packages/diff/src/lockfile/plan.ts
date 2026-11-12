// Turns a lockfile diff into work: version updates to diff, new packages to check, and
// entries that come from outside the registry. Pure. Spec: docs/specs/diff.md § Lockfile mode.

import type { DependencySource, LockfileDiff, LockfileEntry } from "@depward/core";

/** A version change of one package: `before` was removed and `after` added. */
export interface PlannedUpdate {
  before: LockfileEntry;
  after: LockfileEntry;
}

/** A registry entry with no earlier version to compare with. */
export interface PlannedCheck {
  /** `added`: a new name@version. `changed`: same name@version with a different integrity or source. */
  kind: "added" | "changed";
  entry: LockfileEntry;
}

/** What lockfile mode does with each entry of a {@link LockfileDiff}. */
export interface LockfilePlan {
  updates: PlannedUpdate[];
  checks: PlannedCheck[];
  /** Git, tarball-URL, and other non-npm entries: reported, not analyzed. */
  nonRegistry: PlannedCheck[];
  /** Local entries (file, link, workspace) and bundled ones, which their parent's tarball covers. */
  skipped: LockfileEntry[];
}

const NON_REGISTRY: ReadonlySet<DependencySource> = new Set(["git", "tarball", "other"]);

const NUMS = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/;

/** Semver-ish comparison: numeric core, then a release sorts after its prereleases. Unparseable versions sort first. */
export function compareVersions(a: string, b: string): number {
  const x = NUMS.exec(a);
  const y = NUMS.exec(b);
  if (!x || !y) return x ? 1 : y ? -1 : a < b ? -1 : a > b ? 1 : 0;
  for (let i = 1; i <= 3; i++) {
    const d = Number(x[i]) - Number(y[i]);
    if (d !== 0) return d;
  }
  const pa = x[4];
  const pb = y[4];
  if (pa === pb) return 0;
  if (pa === undefined) return 1;
  if (pb === undefined) return -1;
  return pa < pb ? -1 : 1;
}

const major = (v: string): string | undefined => NUMS.exec(v)?.[1];

/**
 * Pairs removed and added registry entries of the same name into updates. Each added
 * version (lowest first) takes the highest unused removed version with the same major,
 * else the highest unused removed version. Added entries left over are new packages.
 */
export function planLockfile(diff: LockfileDiff): LockfilePlan {
  const plan: LockfilePlan = { updates: [], checks: [], nonRegistry: [], skipped: [] };
  const removedByName = new Map<string, LockfileEntry[]>();
  for (const e of diff.removed) {
    if (e.source !== "registry") continue;
    const list = removedByName.get(e.name) ?? [];
    list.push(e);
    removedByName.set(e.name, list);
  }
  for (const list of removedByName.values()) list.sort((a, b) => compareVersions(b.version, a.version));

  const added = diff.added.toSorted((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : compareVersions(a.version, b.version)));
  for (const entry of added) {
    if (entry.source !== "registry") {
      route(plan, { kind: "added", entry });
      continue;
    }
    const pool = removedByName.get(entry.name) ?? [];
    let i = pool.findIndex((r) => major(r.version) === major(entry.version));
    if (i < 0 && pool.length > 0) i = 0;
    const before = i >= 0 ? pool.splice(i, 1)[0] : undefined;
    if (before) plan.updates.push({ before, after: entry });
    else plan.checks.push({ kind: "added", entry });
  }

  for (const { before, after } of diff.changed) {
    if (after.source === before.source && (after.integrity === null || before.integrity === null || after.integrity === before.integrity)) continue;
    route(plan, { kind: "changed", entry: after });
  }
  return plan;
}

function route(plan: LockfilePlan, check: PlannedCheck): void {
  if (check.entry.source === "registry") plan.checks.push(check);
  else if (NON_REGISTRY.has(check.entry.source)) plan.nonRegistry.push(check);
  else plan.skipped.push(check.entry);
}

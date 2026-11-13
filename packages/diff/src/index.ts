/** The version of `@depward/diff`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

export { diffPackages } from "./diff.ts";
export {
  LARGE_CHANGE_BYTES,
  LARGE_CHANGE_RATIO,
  SCRIPT_NAMES,
  declaredDependencies,
  isLargeChange,
} from "./deltas.ts";
export { DIFF_FINDING_IDS, HIGH_RISK_CAPABILITIES, MAX_EVIDENCE, diffRisk, isPatchBump, isRawIpEndpoint } from "./rules.ts";
export type { DiffContext, PackageDiff, ScriptChange } from "./types.ts";
export { diffLockfile, mapLimit, DEFAULT_CONCURRENCY, DEFAULT_MAX_PACKAGES } from "./lockfile/run.ts";
export { checkNew, diffVersions, integrityFinding, nonRegistryResult } from "./lockfile/check.ts";
export { compareVersions, planLockfile, type LockfilePlan, type PlannedCheck, type PlannedUpdate } from "./lockfile/plan.ts";
export type {
  LockfileDiffOptions,
  LockfileDiffReport,
  LockfileSummary,
  PackageChangeKind,
  PackageChangeResult,
  VersionDiffOptions,
} from "./lockfile/types.ts";
export { locateEntry, lockfileLocator } from "./lockfile/locate.ts";
export { createUpdateDiff, lockedVersionFor, type LockedVersion, type UpdateDiffOptions } from "./lockfile/update.ts";
export { FAIL_ON_LEVELS, applyPolicy, reachesFailOn, type FailOn } from "./lockfile/policy.ts";

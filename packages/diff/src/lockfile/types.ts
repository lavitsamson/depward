import type { AnalyzeOptions } from "@depward/analyzer";
import type { Cache, DepwardError, Finding, LockfileFormat, RegistryClient, Severity, TarLimits } from "@depward/core";
import type { GateData, ListMatch, Policy } from "@depward/gate";
import type { PackageDiff } from "../types.ts";

/** Registry access and limits shared by {@link diffVersions} and {@link diffLockfile}. */
export interface VersionDiffOptions {
  registry: RegistryClient;
  /** Analysis results cache, shared with the gate (ADR 0005). Default: none. */
  analysisCache?: Cache | null;
  /** Popular and hallucinated name lists for the checks of new packages. Default: the bundled data. */
  data?: GateData;
  /** Clock, for tests. Default `Date.now`. */
  now?: () => number;
  tarLimits?: TarLimits;
  analyze?: AnalyzeOptions;
  /**
   * The project's policy (`createPolicy(config)`). When given, `diffLockfile` applies it
   * with {@link applyPolicy}: allowed findings and allow-listed packages don't count
   * toward risk, and deny-listed packages are `critical`. Default: none.
   */
  policy?: Policy;
}

/** Options for {@link diffLockfile}. */
export interface LockfileDiffOptions extends VersionDiffOptions {
  /** Repository directory holding the lockfiles. */
  cwd: string;
  /**
   * Git ref to compare with. The base lockfile is read at the merge-base of `HEAD` and
   * this ref. Default `origin/HEAD`.
   */
  base?: string;
  /** Git ref to read the head lockfiles from. Default: the working tree. */
  head?: string;
  /** Packages checked at once. Default 8. */
  concurrency?: number;
  /** More packages to check than this throws `LIMIT_EXCEEDED`. Default 1,000. */
  maxPackages?: number;
}

/** How a package got into the report. */
export type PackageChangeKind =
  /** A version update, diffed against the old version. */
  | "updated"
  /** A new package or version with nothing to compare with: gate registry and tarball checks. */
  | "added"
  /** Same version, but the lockfile's integrity or source changed: checked like `added`. */
  | "changed"
  /** Locked to git, a tarball URL, or another non-npm source: not analyzed. */
  | "non-registry";

/** The result for one package of a lockfile change. */
export interface PackageChangeResult {
  kind: PackageChangeKind;
  name: string;
  /** The old version, for `updated`. */
  from?: string;
  to: string;
  /** Lockfiles (repository-relative) the change appears in. */
  lockfiles: string[];
  /** The behavioral diff, for `updated` when both versions could be analyzed. */
  diff?: PackageDiff;
  /** Findings that count toward risk. Sorted by severity, then package, then id. */
  findings: Finding[];
  /** Findings the config allows (a `policy` override to `allow`, or the `allow` list). Shown, not counted. */
  allowedFindings?: Finding[];
  /** The config list entry matching this package, when a policy was applied. */
  listed?: ListMatch | null;
  /** Failed lookups (network, timeout, missing versions). */
  errors: DepwardError[];
  /**
   * `updated`: the diff's risk rules. Otherwise the highest finding severity. `info` when
   * there are none. `critical` for a deny-listed package.
   */
  risk: Severity;
}

/** One lockfile that was compared. */
export interface LockfileSummary {
  path: string;
  /** `null` when the format is recognized but unsupported (see `findings`). */
  format: LockfileFormat | null;
  /** Entries added, removed, and changed by `diffLockfiles`. */
  counts: { added: number; removed: number; changed: number };
  /** Lockfile-level findings such as `unsupported-lockfile`. */
  findings: Finding[];
}

/** Result of {@link diffLockfile}. */
export interface LockfileDiffReport {
  /** The commit the base lockfiles were read at. */
  base: string;
  /** The head ref, or `null` for the working tree. */
  head: string | null;
  lockfiles: LockfileSummary[];
  /** Sorted by risk (most severe first), then name, then version. */
  packages: PackageChangeResult[];
  /** Local and bundled entries that were skipped, as `name@version`. */
  skipped: string[];
  /** Every finding of every package and lockfile, sorted. */
  findings: Finding[];
  /** The highest package risk. `info` when nothing changed. */
  risk: Severity;
}

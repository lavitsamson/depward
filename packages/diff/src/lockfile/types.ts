import type { AnalyzeOptions } from "@depward/analyzer";
import type { Cache, DepwardError, Finding, LockfileFormat, RegistryClient, Severity, TarLimits } from "@depward/core";
import type { GateData } from "@depward/gate";
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
  /** Sorted by severity, then package, then id. */
  findings: Finding[];
  /** Failed lookups (network, timeout, missing versions). */
  errors: DepwardError[];
  /** `updated`: the diff's risk rules. Otherwise the highest finding severity. `info` when there are none. */
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

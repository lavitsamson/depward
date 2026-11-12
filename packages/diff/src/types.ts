import type { Capability, Signal } from "@depward/analyzer";
import type { Finding, Packument, Severity } from "@depward/core";

/** A script that differs between the two versions. A missing side means "not present". */
export interface ScriptChange {
  from?: string;
  to?: string;
}

/**
 * What changed between two versions of one package, and the findings that follow from
 * it. Spec: `docs/specs/diff.md`. Every string comes from untrusted package data or
 * registry metadata; finding messages and evidence are escaped, the raw delta fields
 * are not.
 */
export interface PackageDiff {
  name: string;
  from: string;
  to: string;
  /** Capabilities used in B and not in A, and the reverse. In {@link CAPABILITIES} order. */
  capabilityDelta: { added: Capability[]; removed: Capability[] };
  /** Signals whose id is in B and not in A (`added`), and the reverse. Compared by id only. */
  signalDelta: { added: Signal[]; removed: Signal[] };
  /** Install scripts (`preinstall`, `install`, `postinstall`, `prepare`) that differ. */
  scriptDelta: Record<string, ScriptChange>;
  /** Dependency names, sorted. `changed` means the declared range changed. */
  dependencyDelta: { added: string[]; removed: string[]; changed: string[] };
  /** Package-relative paths, sorted. */
  fileDelta: { added: string[]; removed: string[]; changedLarge: string[] };
  /** Endpoints in B and not in A, sorted. */
  endpointDelta: { added: string[] };
  /** Literal `process.env` keys read in B and not in A, sorted. */
  envKeyDelta: { added: string[] };
  /** Set when `_npmUser.name` differs between A and B. */
  publisherDelta?: { from: string; to: string };
  /** Set when attestations appear or disappear between A and B. */
  provenanceDelta?: "dropped" | "added";
  /** Sorted by severity, then package, then id. */
  findings: Finding[];
  /** The highest finding severity, or `critical` when there are two or more `high` findings. `info` when there are none. */
  risk: Severity;
}

/** Optional registry context for {@link diffPackages}. */
export interface DiffContext {
  /**
   * The package's packument. When given, `diff-publisher-changed` uses the publish
   * history (core's `publisherChange`) instead of comparing the two versions only.
   */
  packument?: Packument;
  /** Current time in ms, for the publisher check's age cutoff. */
  now?: number;
  /**
   * True when a new dependency is itself young (its own check found `package-too-new`).
   * `diff-new-dependency` is then `high` instead of `low`. Lockfile mode sets it.
   */
  isYoungDependency?: (name: string) => boolean;
}

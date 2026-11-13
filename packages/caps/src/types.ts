// Types of the capability lockfile. Spec: docs/specs/caps.md § Static layer.

import type { Cache, DepwardError, RegistryClient, TarLimits } from "@depward/core";
import type { AnalyzeOptions } from "@depward/analyzer";

/** Default file name of the capability lockfile. */
export const CAPS_LOCKFILE_NAME = "capabilities.lock.json";

/** The one format version this release reads and writes. */
export const CAPS_LOCKFILE_VERSION = 1;

/** `approvedBy` of entries recorded by `depward caps scan`. */
export const STATIC_APPROVER = "static";

/** The approved capabilities of one `name@version`. */
export interface CapsEntry {
  /** Capability names, sorted alphabetically (analyzer names, for example `fs`, `net`). */
  capabilities: string[];
  /** Who approved them: `static` for a scan baseline, or a person. Absent when there are none. */
  approvedBy?: string;
  /** UTC date of the approval, `YYYY-MM-DD`. */
  approvedAt?: string;
  /** Free-text justification, set by `depward caps approve`. */
  reason?: string;
}

/** A parsed `capabilities.lock.json`. Keys of `packages` are `name@version`. */
export interface CapsLockfile {
  version: typeof CAPS_LOCKFILE_VERSION;
  packages: Record<string, CapsEntry>;
}

/** Options for {@link scanCapabilities}. */
export interface ScanOptions {
  /** Directory whose lockfiles are scanned. */
  cwd: string;
  registry: RegistryClient;
  /** Shared analysis cache (ADR 0005). Default: none. */
  analysisCache?: Cache | null;
  tarLimits?: TarLimits;
  analyze?: AnalyzeOptions;
  /** The current capability lockfile; its approvals survive for unchanged entries. */
  existing?: CapsLockfile | null;
  /** Packages analyzed at once. Default 8. */
  concurrency?: number;
  /** Most registry entries scanned. Default 5,000. */
  maxPackages?: number;
  /** Clock for `approvedAt`, in ms since the epoch. Default `Date.now`. */
  now?: () => number;
}

/** A lockfile entry the scan did not analyze, and why. */
export interface SkippedEntry {
  /** `name@version` (or the raw reference for non-registry entries). */
  key: string;
  /** The lockfile's dependency source, for example `workspace` or `git`. */
  source: string;
  lockfiles: string[];
}

/** Result of {@link scanCapabilities}. */
export interface ScanResult {
  /** The new capability lockfile. Only complete when `errors` is empty. */
  lockfile: CapsLockfile;
  /** Lockfiles that were read, in {@link KNOWN_LOCKFILES} order. */
  lockfiles: string[];
  /** Non-registry entries, sorted by key. */
  skipped: SkippedEntry[];
  /** Packages that could not be analyzed. A non-empty list means the scan failed. */
  errors: DepwardError[];
  counts: {
    /** Registry entries scanned. */
    scanned: number;
    /** Of those, entries with at least one capability. */
    withCapabilities: number;
    /** Entries whose approval was kept from `existing`. */
    kept: number;
    /** Entries of `existing` no longer locked. */
    dropped: number;
  };
}

/**
 * Per-package least privilege for Node.js: a capability lockfile built from static
 * analysis (`capabilities.lock.json`), checked in CI and approved per package. The runtime layer (`@depward/caps/register`)
 * arrives in M4.3. Spec: docs/specs/caps.md.
 *
 * @module
 */

/** The version of `@depward/caps`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

export {
  CAPS_LOCKFILE_NAME,
  CAPS_LOCKFILE_VERSION,
  STATIC_APPROVER,
  type CapsEntry,
  type CapsLockfile,
  type ScanOptions,
  type ScanResult,
  type SkippedEntry,
} from "./types.ts";
export { compareKeys, parseCapsLockfile, serializeCapsLockfile, splitKey } from "./lockfile.ts";
export { DEFAULT_SCAN_CONCURRENCY, DEFAULT_SCAN_MAX_PACKAGES, baselineEntry, scanCapabilities, utcDate } from "./scan.ts";
export { analyzeLocked, capabilitiesOf, keyOf, readLocked, type Analysis, type Located, type LockedSet } from "./analyze.ts";
export {
  CAPS_FINDING_IDS,
  capsCheckExitCode,
  checkCapabilities,
  referenceIndex,
  unapprovedFindings,
  type CapsCheckReport,
  type CapsReference,
  type CheckOptions,
} from "./check.ts";
export { approveCapabilities, parseTarget, type ApproveOptions, type ApproveResult, type ApproveTarget, type ApprovedEntry } from "./approve.ts";

// The update path (M3.6): when the requested package is already in the project's
// lockfile at another version, the gate also diffs the new version against the locked
// one. The gate never imports @depward/diff (ADR 0006); callers that have it pass
// `diffUpdate` (the CLI and the MCP server pass diff's `createUpdateDiff`).
// Spec: docs/specs/gate.md § Update path.

import { DepwardError, isDepwardError, type Finding, type VersionMeta } from "@depward/core";
import type { PackageProfile } from "@depward/analyzer";

/** What the gate hands {@link UpdateDiff} once a version has resolved. */
export interface UpdateRequest {
  readonly name: string;
  /** The version the request resolved to. */
  readonly version: string;
  readonly meta: VersionMeta;
  /**
   * The analyzer profile of `version`, from the gate's own tarball check (which runs at
   * the same time). `null` when the tarball couldn't be analyzed.
   */
  readonly profile: Promise<PackageProfile | null>;
}

/** The diff of a requested version against the version locked in the project. */
export interface UpdateDiffResult {
  /** The locked version the request was compared with. */
  readonly from: string;
  /** The lockfile (project-relative) holding `from`. */
  readonly lockfile: string;
  /** `diff-*` findings for `version`. */
  readonly findings: readonly Finding[];
  /** Failed lookups while diffing (the locked version's metadata or tarball). */
  readonly errors: readonly DepwardError[];
}

/**
 * Diffs a requested version against the project's locked version of the same package.
 * Resolves to `null` when the package isn't locked, or is already locked at
 * `request.version`: then there is no update to diff.
 */
export type UpdateDiff = (request: UpdateRequest) => Promise<UpdateDiffResult | null>;

/** The update a package decision was diffed as. */
export interface UpdateInfo {
  readonly from: string;
  readonly lockfile: string;
}

/** What {@link runUpdateDiff} adds to a package check. */
export interface UpdateOutcome {
  readonly update: UpdateInfo | null;
  readonly findings: Finding[];
  readonly errors: DepwardError[];
}

// The registry checks already compare a version with the package's history. When they
// report the same thing, the diff's copy against the locked version is dropped.
const DUPLICATES: Readonly<Record<string, string>> = {
  "diff-publisher-changed": "publisher-changed",
  "diff-provenance-dropped": "provenance-dropped",
};

/**
 * Calls `diffUpdate` and normalizes the result. Never throws: a callback that throws
 * becomes an error (which costs `onError`), and findings that duplicate a registry
 * finding in `existing` are dropped.
 */
export async function runUpdateDiff(diffUpdate: UpdateDiff, request: UpdateRequest, existing: readonly Finding[]): Promise<UpdateOutcome> {
  let result: UpdateDiffResult | null;
  try {
    result = await diffUpdate(request);
  } catch (err) {
    const error = isDepwardError(err) ? err : new DepwardError("INTERNAL", `the update diff for ${request.name} failed`, { cause: err });
    return { update: null, findings: [], errors: [error] };
  }
  if (result === null) return { update: null, findings: [], errors: [] };
  const present = new Set(existing.map((f) => f.id));
  const findings = result.findings.filter((f) => {
    const twin = Object.hasOwn(DUPLICATES, f.id) ? DUPLICATES[f.id] : undefined;
    return twin === undefined || !present.has(twin);
  });
  return { update: { from: result.from, lockfile: result.lockfile }, findings, errors: [...result.errors] };
}

// The machine-readable form of a diff (`depward diff --format json`, the MCP tool
// `diff_versions`, and the GitHub Action). Key order is fixed, so output is
// deterministic. Text is escaped by JSON only: consumers that print it must sanitize it.

import { sortFindings, type Finding, type Severity, type ToolInfo } from "@depward/core";
import type { LockfileSummary, PackageChangeResult } from "./lockfile/types.ts";

/** Version of the `depward diff --format json` document. Bumped on breaking changes. */
export const DIFF_JSON_VERSION: number = 1;

/** What `depward diff` reports: one package (from the CLI arguments) or a lockfile change. */
export interface DiffView {
  packages: PackageChangeResult[];
  /** Every finding, sorted. */
  findings: Finding[];
  risk: Severity;
  lockfiles: LockfileSummary[];
  skipped: string[];
  /** Base commit, in lockfile mode. */
  base: string | null;
  /** Head ref, or `null` for the working tree (lockfile mode) or no head (single package). */
  head: string | null;
}

/** The view of one package's diff (`diffVersions`, after any policy). */
export function packageView(result: PackageChangeResult): DiffView {
  return { packages: [result], findings: sortFindings(result.findings), risk: result.risk, lockfiles: [], skipped: [], base: null, head: null };
}

/** The JSON document of `depward diff --format json`. Key order is fixed. */
export function serializeDiff(view: DiffView, tool: ToolInfo, outcome?: { failOn: string; failed: boolean }): Record<string, unknown> {
  return {
    reportVersion: DIFF_JSON_VERSION,
    tool: { name: tool.name, ...(tool.version === undefined ? {} : { version: tool.version }) },
    base: view.base,
    head: view.head,
    risk: view.risk,
    ...(outcome === undefined ? {} : { failOn: outcome.failOn, failed: outcome.failed }),
    lockfiles: view.lockfiles,
    packages: view.packages.map((p) => ({
      kind: p.kind,
      name: p.name,
      ...(p.from === undefined ? {} : { from: p.from }),
      to: p.to,
      lockfiles: p.lockfiles,
      risk: p.risk,
      findings: p.findings,
      allowedFindings: p.allowedFindings ?? [],
      ...(p.listed ? { listed: p.listed } : {}),
      errors: p.errors.map((e) => ({ code: e.code, message: e.message })),
      ...(p.diff === undefined
        ? {}
        : {
            delta: {
              capabilities: p.diff.capabilityDelta,
              signals: { added: [...new Set(p.diff.signalDelta.added.map((s) => s.id))], removed: [...new Set(p.diff.signalDelta.removed.map((s) => s.id))] },
              scripts: p.diff.scriptDelta,
              dependencies: p.diff.dependencyDelta,
              files: p.diff.fileDelta,
              endpoints: p.diff.endpointDelta,
              envKeys: p.diff.envKeyDelta,
              ...(p.diff.publisherDelta === undefined ? {} : { publisher: p.diff.publisherDelta }),
              ...(p.diff.provenanceDelta === undefined ? {} : { provenance: p.diff.provenanceDelta }),
            },
          }),
    })),
    skipped: view.skipped,
  };
}

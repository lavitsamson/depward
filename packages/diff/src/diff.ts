import type { PackageProfile } from "@depward/analyzer";
import { DepwardError, type VersionMeta } from "@depward/core";
import {
  capabilityDelta,
  dependencyDelta,
  endpointDelta,
  envKeyDelta,
  fileDelta,
  provenanceDelta,
  publisherDelta,
  scriptDelta,
  signalDelta,
} from "./deltas.ts";
import { diffFindings, diffRisk } from "./rules.ts";
import type { DiffContext, PackageDiff } from "./types.ts";

/**
 * Compares what version A of a package could do with what version B can do, and reports
 * the changes that matter for supply-chain risk. Pure: it never touches the network.
 * Spec: `docs/specs/diff.md`.
 *
 * @param a - Analyzer profile of the old version.
 * @param b - Analyzer profile of the new version.
 * @param metaA - Registry metadata of the old version (dependencies, publisher, provenance).
 * @param metaB - Registry metadata of the new version.
 * @param ctx - Optional registry context; with a packument the publisher check uses the
 *   package's publish history.
 * @throws DepwardError `INVALID_ARGUMENT` when the profiles and metadata are not all for
 *   the same package, or a profile's version doesn't match its metadata.
 *
 * @example
 * ```ts
 * const diff = diffPackages(profileA, profileB, metaA, metaB);
 * if (diff.risk === "critical") console.log(diff.findings.map((f) => f.message));
 * ```
 */
export function diffPackages(a: PackageProfile, b: PackageProfile, metaA: VersionMeta, metaB: VersionMeta, ctx: DiffContext = {}): PackageDiff {
  if (a.name !== b.name || metaA.name !== a.name || metaB.name !== a.name) {
    throw new DepwardError("INVALID_ARGUMENT", "diffPackages needs two versions of the same package");
  }
  if (metaA.version !== a.version || metaB.version !== b.version) {
    throw new DepwardError("INVALID_ARGUMENT", "diffPackages: profile and metadata versions differ");
  }
  const publisher = publisherDelta(metaA, metaB);
  const provenance = provenanceDelta(metaA, metaB);
  const delta: Omit<PackageDiff, "findings" | "risk"> = {
    name: a.name,
    from: a.version,
    to: b.version,
    capabilityDelta: capabilityDelta(a, b),
    signalDelta: signalDelta(a, b),
    scriptDelta: scriptDelta(a, b),
    dependencyDelta: dependencyDelta(metaA, metaB),
    fileDelta: fileDelta(a, b),
    endpointDelta: endpointDelta(a, b),
    envKeyDelta: envKeyDelta(a, b),
    ...(publisher === undefined ? {} : { publisherDelta: publisher }),
    ...(provenance === undefined ? {} : { provenanceDelta: provenance }),
  };
  const findings = diffFindings({ delta, a, b, metaA, metaB, ctx });
  return { ...delta, findings, risk: diffRisk(findings) };
}

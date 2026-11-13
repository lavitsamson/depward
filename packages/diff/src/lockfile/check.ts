// Checks for one package of a lockfile change: diff a version update, run the gate on a
// new package, or report a non-registry source. None of these throw for registry,
// network, or archive failures: those become `errors` or `tarball-*` findings.

import {
  compareIntegrity,
  compareSeverity,
  DepwardError,
  escapeUnsafe,
  findingDocsUrl,
  isDepwardError,
  pickVersion,
  sortFindings,
  type Finding,
  type LockfileEntry,
  type Severity,
  type VersionMeta,
} from "@depward/core";
import { checkPackage, checkTarball, type TarballCheckOptions } from "@depward/gate";
import { diffPackages } from "../diff.ts";
import { diffRisk } from "../rules.ts";
import type { PackageChangeKind, PackageChangeResult, VersionDiffOptions } from "./types.ts";

function toError(err: unknown): DepwardError {
  return isDepwardError(err) ? err : new DepwardError("INTERNAL", "package check failed", { cause: err });
}

/** The highest severity, or `info`. */
export function maxSeverity(findings: readonly Finding[]): Severity {
  return findings.map((f) => f.severity).toSorted(compareSeverity)[0] ?? "info";
}

/**
 * `lockfile-integrity-mismatch` when the lockfile's integrity for a registry entry
 * disagrees with the registry's `dist` for that version. `null` when they agree or have
 * no hash algorithm in common.
 */
export function integrityFinding(entry: LockfileEntry, meta: VersionMeta, lockfile: string): Finding | null {
  if (entry.integrity === null || compareIntegrity(entry.integrity, meta.dist) !== false) return null;
  return {
    id: "lockfile-integrity-mismatch",
    severity: "critical",
    package: entry.name,
    version: entry.version,
    message: `${lockfile} locks ${entry.name}@${entry.version} to a different tarball than the registry publishes for that version`,
    evidence: [
      { file: lockfile, snippet: escapeUnsafe(entry.integrity), detail: "lockfile integrity" },
      { snippet: escapeUnsafe(meta.dist.integrity ?? `sha1 ${meta.dist.shasum ?? "?"}`), detail: "registry integrity" },
      ...(entry.resolved === null ? [] : [{ snippet: escapeUnsafe(entry.resolved), detail: "lockfile resolved URL" }]),
    ],
    docsUrl: findingDocsUrl("lockfile-integrity-mismatch"),
  };
}

const tarballFindings = (fs: readonly Finding[]): Finding[] => fs.filter((f) => f.id.startsWith("tarball-"));

/** The gate tarball-check options carried by {@link VersionDiffOptions}. */
export function tarballOptions(opts: VersionDiffOptions): TarballCheckOptions {
  return {
    registry: opts.registry,
    ...(opts.analysisCache === undefined ? {} : { analysisCache: opts.analysisCache }),
    ...(opts.tarLimits === undefined ? {} : { tarLimits: opts.tarLimits }),
    ...(opts.analyze === undefined ? {} : { analyze: opts.analyze }),
  };
}

/**
 * Diffs version `from` of a package against version `to`: both tarballs are analyzed
 * (through the gate's tarball check and its analysis cache) and compared with
 * `diffPackages`, using the packument for the publisher check. With `entry`, the
 * lockfile's integrity for `to` is also checked against the registry.
 */
export async function diffVersions(
  name: string,
  from: string,
  to: string,
  opts: VersionDiffOptions & { entry?: LockfileEntry; lockfile?: string; isYoungDependency?: (name: string) => boolean },
): Promise<PackageChangeResult> {
  const result: PackageChangeResult = { kind: "updated", name, from, to, lockfiles: opts.lockfile === undefined ? [] : [opts.lockfile], findings: [], errors: [], risk: "info" };
  try {
    const packument = await opts.registry.packument(name);
    if (packument === null) throw new DepwardError("NOT_FOUND", `${name} is not in the registry`);
    const metaA = pickVersion(packument, from);
    const metaB = pickVersion(packument, to);
    for (const [v, m] of [[from, metaA], [to, metaB]] as const) {
      if (m === null) result.errors.push(new DepwardError("NOT_FOUND", `${name}@${v} is not in the registry`));
    }
    if (metaA === null || metaB === null) return result;

    const tarOpts = tarballOptions(opts);
    const [a, b] = await Promise.all([checkTarball(metaA, tarOpts), checkTarball(metaB, tarOpts)]);
    result.errors.push(...a.errors, ...b.errors);
    const findings = tarballFindings(b.findings);
    if (a.profile !== null && b.profile !== null) {
      const now = (opts.now ?? Date.now)();
      result.diff = diffPackages(a.profile, b.profile, metaA, metaB, {
        packument,
        now,
        ...(opts.isYoungDependency === undefined ? {} : { isYoungDependency: opts.isYoungDependency }),
      });
      findings.push(...result.diff.findings);
    }
    const mismatch = opts.entry ? integrityFinding(opts.entry, metaB, opts.lockfile ?? "lockfile") : null;
    if (mismatch) findings.push(mismatch);
    result.findings = sortFindings(findings);
    result.risk = diffRisk(result.findings);
  } catch (err) {
    result.errors.push(toError(err));
  }
  return result;
}

/**
 * Runs the gate's registry and tarball checks on a lockfile entry that has no earlier
 * version to compare with, plus the lockfile integrity check.
 */
export async function checkNew(entry: LockfileEntry, kind: Extract<PackageChangeKind, "added" | "changed">, lockfile: string, opts: VersionDiffOptions): Promise<PackageChangeResult> {
  const result: PackageChangeResult = { kind, name: entry.name, to: entry.version, lockfiles: [lockfile], findings: [], errors: [], risk: "info" };
  try {
    const checked = await checkPackage(
      { name: entry.name, range: entry.version },
      {
        registry: opts.registry,
        ...(opts.data === undefined ? {} : { data: opts.data }),
        ...(opts.now === undefined ? {} : { now: opts.now }),
        ...(opts.analysisCache === undefined ? {} : { analysisCache: opts.analysisCache }),
        ...(opts.tarLimits === undefined ? {} : { tarLimits: opts.tarLimits }),
        ...(opts.analyze === undefined ? {} : { analyze: opts.analyze }),
      },
    );
    result.errors.push(...checked.errors);
    const mismatch = checked.meta ? integrityFinding(entry, checked.meta, lockfile) : null;
    result.findings = sortFindings(mismatch ? [...checked.findings, mismatch] : checked.findings);
    result.risk = maxSeverity(result.findings);
  } catch (err) {
    result.errors.push(toError(err));
  }
  return result;
}

const SOURCE_NAMES: Partial<Record<LockfileEntry["source"], string>> = { git: "a git repository", tarball: "a tarball URL", other: "a non-npm source" };

/** `non-registry-source` for an entry locked to git, a tarball URL, or another non-npm source. */
export function nonRegistryResult(entry: LockfileEntry, lockfile: string): PackageChangeResult {
  const finding: Finding = {
    id: "non-registry-source",
    severity: "medium",
    package: entry.name,
    version: entry.version,
    message: `${lockfile} installs ${entry.name} from ${SOURCE_NAMES[entry.source] ?? "a non-npm source"}, not the npm registry, so depward can't check it`,
    evidence: [{ file: lockfile, snippet: escapeUnsafe(entry.resolved ?? entry.version) }],
    docsUrl: findingDocsUrl("non-registry-source"),
  };
  return { kind: "non-registry", name: entry.name, to: entry.version, lockfiles: [lockfile], findings: [finding], errors: [], risk: "medium" };
}

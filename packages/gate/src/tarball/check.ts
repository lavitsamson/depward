// Tarball checks: download one version's tarball, read it in memory, and run the static
// analyzer. Package code is never executed and never written to disk (the registry
// client's cache stores the integrity-verified archive, never extracted files).
// Spec: docs/specs/gate.md §Tarball checks. Finding catalog: docs/findings.md.
//
// Escalations (install-script + package-too-new or low-downloads → deny, any critical →
// deny) belong to the policy engine (M2.4), like the registry-check escalations.

import { analyzePackage, profileFindings, type AnalyzeOptions, type PackageProfile } from "@depward/analyzer";
import {
  DepwardError,
  findingDocsUrl,
  isDepwardError,
  readTarball,
  sortFindings,
  type DepwardErrorCode,
  type Finding,
  type RegistryClient,
  type TarLimits,
  type VersionMeta,
} from "@depward/core";

/** Options for {@link checkTarball}. */
export interface TarballCheckOptions {
  registry: RegistryClient;
  /** Archive limits for `readTarball`. Defaults: 50 MB compressed, 200 MB unpacked, 20,000 entries. */
  tarLimits?: TarLimits;
  /** Analyzer limits. Defaults: 5 MB per analyzed file, 20,000 files. */
  analyze?: AnalyzeOptions;
}

/** Result of {@link checkTarball}. */
export interface TarballCheckResult {
  readonly name: string;
  readonly version: string;
  /** Analyzer signals as findings, plus `tarball-*` findings. Sorted by severity, package, id. */
  readonly findings: Finding[];
  /** The analyzer's profile, or `null` when the archive couldn't be read. */
  readonly profile: PackageProfile | null;
  /** Transient failures (network, timeout). The policy engine applies `onError` to these. */
  readonly errors: DepwardError[];
}

// Failures that describe the archive itself. They are reported as findings, not errors,
// so a crafted archive can't downgrade its own result to `onError`.
const UNSAFE_CODES: ReadonlySet<DepwardErrorCode> = new Set(["UNSAFE_PATH", "INVALID_ARCHIVE", "LIMIT_EXCEEDED"]);

function failure(meta: VersionMeta, err: unknown): { finding?: Finding; error?: DepwardError } {
  if (!isDepwardError(err)) return { error: new DepwardError("INTERNAL", "tarball check failed", { cause: err }) };
  const base = { package: meta.name, version: meta.version, evidence: [{ detail: err.message }] };
  if (err.code === "INTEGRITY_MISMATCH") {
    return {
      finding: {
        id: "tarball-integrity-mismatch",
        severity: "critical",
        ...base,
        message: `The tarball of ${meta.name}@${meta.version} does not match the integrity hash the registry published for it. It may have been tampered with.`,
        docsUrl: findingDocsUrl("tarball-integrity-mismatch"),
      },
    };
  }
  if (UNSAFE_CODES.has(err.code)) {
    return {
      finding: {
        id: "tarball-unsafe",
        severity: "high",
        ...base,
        message: `The tarball of ${meta.name}@${meta.version} can't be analyzed safely: it is malformed, contains unsafe paths, or exceeds a size limit.`,
        docsUrl: findingDocsUrl("tarball-unsafe"),
      },
    };
  }
  return { error: err };
}

/**
 * Downloads and statically analyzes one version. It never throws for registry,
 * network, or archive failures: archive problems become `tarball-*` findings, and
 * transient failures land in `errors`.
 */
export async function checkTarball(meta: VersionMeta, opts: TarballCheckOptions): Promise<TarballCheckResult> {
  const { name, version } = meta;
  const done = (findings: Finding[], profile: PackageProfile | null, errors: DepwardError[]): TarballCheckResult => ({
    name, version, findings: sortFindings(findings), profile, errors,
  });

  let profile: PackageProfile;
  try {
    const bytes = await opts.registry.tarball(meta);
    profile = analyzePackage(readTarball(bytes, opts.tarLimits), opts.analyze);
  } catch (err) {
    const { finding, error } = failure(meta, err);
    return done(finding ? [finding] : [], null, error ? [error] : []);
  }

  // Report under the requested name and version, not whatever the archive's own
  // package.json claims: that file is attacker-controlled.
  const findings = profileFindings(profile).map((f) => ({ ...f, package: name, version }));
  return done(findings, profile, []);
}

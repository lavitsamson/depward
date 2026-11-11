// Tarball checks: download one version's tarball, read it in memory, and run the static
// analyzer. Package code is never executed and never written to disk (the registry
// client's cache stores the integrity-verified archive, never extracted files).
// Spec: docs/specs/gate.md §Tarball checks. Finding catalog: docs/findings.md.
//
// Escalations (install-script + package-too-new or low-downloads → deny, any critical →
// deny) belong to the policy engine (policy/engine.ts), like the registry ones.

import type { AnalyzeOptions, PackageProfile } from "@depward/analyzer";
import { analysisCacheKey, readCachedProfile, writeCachedProfile } from "./cache.ts";
import {
  DepwardError,
  findingDocsUrl,
  type Cache,
  isDepwardError,
  readTarball,
  sortFindings,
  type DepwardErrorCode,
  type Finding,
  type RegistryClient,
  type TarLimits,
  type VersionMeta,
} from "@depward/core";

/**
 * Loads `@depward/analyzer` (and acorn). The tarball stage does this on first use, so
 * hook calls that never reach it don't pay for it. Long-running processes can call this
 * at startup to keep their first check fast.
 */
export function preloadAnalyzer(): Promise<typeof import("@depward/analyzer")> {
  return import("@depward/analyzer");
}

/** Options for {@link checkTarball}. */
export interface TarballCheckOptions {
  registry: RegistryClient;
  /** Archive limits for `readTarball`. Defaults: 50 MB compressed, 200 MB unpacked, 20,000 entries. */
  tarLimits?: TarLimits;
  /** Analyzer limits. Defaults: 5 MB per analyzed file, 20,000 files. */
  analyze?: AnalyzeOptions;
  /**
   * Where to keep analysis results, keyed by the version's integrity hash, the
   * analyzer's version and revision, and the limits (ADR 0005). A hit skips the download
   * and the analysis. Default: none, so every check analyzes.
   */
  analysisCache?: Cache | null;
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

  const analyzer = await preloadAnalyzer();
  const cache = opts.analysisCache ?? null;
  const key = cache === null ? null : analysisCacheKey(meta, opts, analyzer);
  let profile = cache !== null && key !== null ? await readCachedProfile(cache, key) : null;
  if (profile !== null) {
    try {
      return done(reported(analyzer.profileFindings(profile), name, version), profile, []);
    } catch {
      profile = null; // A stale entry the shape check let through: analyze again.
    }
  }

  try {
    // `tarball()` verifies the bytes against `dist.integrity`, so what gets cached under
    // that hash was computed from exactly those bytes.
    const bytes = await opts.registry.tarball(meta);
    profile = analyzer.analyzePackage(readTarball(bytes, opts.tarLimits), opts.analyze);
  } catch (err) {
    const { finding, error } = failure(meta, err);
    return done(finding ? [finding] : [], null, error ? [error] : []);
  }

  const findings = reported(analyzer.profileFindings(profile), name, version);
  if (cache !== null && key !== null) await writeCachedProfile(cache, key, profile, Date.now());
  return done(findings, profile, []);
}

// Report under the requested name and version, not whatever the archive's own
// package.json claims: that file is attacker-controlled.
function reported(findings: Finding[], name: string, version: string): Finding[] {
  return findings.map((f) => ({ ...f, package: name, version }));
}

// One package, end to end: registry checks, then tarball checks on the resolved version,
// and (with `diffUpdate`) the update diff against the locked version beside them.
// Spec: docs/specs/gate.md §Flow. Turning the findings into allow / ask / deny is the
// policy engine's job (policy/engine.ts); `analyzeTarball` lets it skip the tarball
// when the registry stage already decides the outcome.

import { sortFindings, type DepwardError, type Finding } from "@depward/core";
import type { PackageProfile } from "@depward/analyzer";
import { checkRegistry, type RegistryCheckInput, type RegistryCheckOptions, type RegistryCheckResult } from "./registry/checks.ts";
import { checkTarball, type TarballCheckOptions } from "./tarball/check.ts";
import { runUpdateDiff, type UpdateDiff, type UpdateInfo } from "./update.ts";

/** Options for {@link checkPackage}. */
export interface PackageCheckOptions extends RegistryCheckOptions, Omit<TarballCheckOptions, "registry"> {
  /** Set to `false` to skip downloading and analyzing the tarball. Default `true`. */
  tarball?: boolean;
  /** Called after the registry stage; return `false` to skip the tarball. Default: always analyze. */
  analyzeTarball?: (registry: RegistryCheckResult) => boolean;
  /**
   * The update path: diffs the resolved version against the project's locked version,
   * at the same time as the tarball check, whenever the tarball is analyzed. Default:
   * none (no update diff). See {@link UpdateDiff}.
   */
  diffUpdate?: UpdateDiff;
}

/** Result of {@link checkPackage}: the registry result, extended with the tarball's. */
export interface PackageCheckResult extends RegistryCheckResult {
  /** Registry, tarball, and update-diff findings together, sorted by severity, package, id. */
  readonly findings: Finding[];
  /** Failed lookups from every stage. */
  readonly errors: DepwardError[];
  /** The analyzer profile, or `null` if the tarball wasn't (or couldn't be) analyzed. */
  readonly profile: PackageProfile | null;
  /** The locked version the request was diffed against, or `null` when it wasn't an update. */
  readonly update: UpdateInfo | null;
}

/**
 * Runs the registry checks, then (when a version resolved) the tarball checks and, with
 * `opts.diffUpdate`, the update diff. Never throws for registry, network, or archive
 * failures; see `errors` and the `tarball-*` findings.
 */
export async function checkPackage(input: RegistryCheckInput, opts: PackageCheckOptions): Promise<PackageCheckResult> {
  const registry = await checkRegistry(input, opts);
  if (registry.meta === null || opts.tarball === false || opts.analyzeTarball?.(registry) === false) {
    return { ...registry, profile: null, update: null };
  }
  const meta = registry.meta;
  const tarballCheck = checkTarball(meta, opts);
  const updateCheck = opts.diffUpdate === undefined
    ? null
    : runUpdateDiff(opts.diffUpdate, { name: meta.name, version: meta.version, meta, profile: tarballCheck.then((t) => t.profile, () => null) }, registry.findings);
  const [tarball, update] = await Promise.all([tarballCheck, updateCheck]);
  return {
    ...registry,
    findings: sortFindings([...registry.findings, ...tarball.findings, ...(update?.findings ?? [])]),
    errors: [...registry.errors, ...tarball.errors, ...(update?.errors ?? [])],
    profile: tarball.profile,
    update: update?.update ?? null,
  };
}

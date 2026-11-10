// One package, end to end: registry checks, then tarball checks on the resolved version.
// Spec: docs/specs/gate.md §Flow. Turning the findings into allow / ask / deny (and
// skipping the tarball once a registry finding already denies) is the policy engine's
// job (M2.4).

import { sortFindings, type DepwardError, type Finding } from "@depward/core";
import type { PackageProfile } from "@depward/analyzer";
import { checkRegistry, type RegistryCheckInput, type RegistryCheckOptions, type RegistryCheckResult } from "./registry/checks.ts";
import { checkTarball, type TarballCheckOptions } from "./tarball/check.ts";

/** Options for {@link checkPackage}. */
export interface PackageCheckOptions extends RegistryCheckOptions, Omit<TarballCheckOptions, "registry"> {
  /** Set to `false` to skip downloading and analyzing the tarball. Default `true`. */
  tarball?: boolean;
}

/** Result of {@link checkPackage}: the registry result, extended with the tarball's. */
export interface PackageCheckResult extends RegistryCheckResult {
  /** Registry and tarball findings together, sorted by severity, package, id. */
  readonly findings: Finding[];
  /** Failed lookups from both stages. */
  readonly errors: DepwardError[];
  /** The analyzer profile, or `null` if the tarball wasn't (or couldn't be) analyzed. */
  readonly profile: PackageProfile | null;
}

/**
 * Runs the registry checks, then (when a version resolved) the tarball checks. Never
 * throws for registry, network, or archive failures; see `errors` and the `tarball-*`
 * findings.
 */
export async function checkPackage(input: RegistryCheckInput, opts: PackageCheckOptions): Promise<PackageCheckResult> {
  const registry = await checkRegistry(input, opts);
  if (registry.meta === null || opts.tarball === false) return { ...registry, profile: null };
  const tarball = await checkTarball(registry.meta, opts);
  return {
    ...registry,
    findings: sortFindings([...registry.findings, ...tarball.findings]),
    errors: [...registry.errors, ...tarball.errors],
    profile: tarball.profile,
  };
}

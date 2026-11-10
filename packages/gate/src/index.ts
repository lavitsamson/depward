/** The version of `@depward/gate`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

export { parseInstallCommand } from "./command/analyze.ts";
export {
  createPackageSpec,
  parsePackageSpec,
  type InvalidSpec,
  type NonRegistrySpec,
  type PackageSpec,
  type RegistrySpec,
  type SpecSource,
} from "./command/spec.ts";
export {
  checkRegistry,
  type RegistryCheckInput,
  type RegistryCheckOptions,
  type RegistryCheckResult,
  type RegistryThresholds,
  type Suggestion,
} from "./registry/checks.ts";
export {
  createGateData,
  loadGateData,
  parseHallucinated,
  parsePopular,
  type GateData,
  type HallucinatedName,
} from "./registry/data.ts";
export { editDistance } from "./registry/edit-distance.ts";
export {
  createPopularIndex,
  type PopularIndex,
  type PopularPackage,
  type SimilarPackage,
  type SimilarityKind,
} from "./registry/typosquat.ts";
export type { CommandAnalysis, Invocation, InvocationKind, PackageManager, PackageRequest } from "./command/types.ts";

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
export { checkPackage, type PackageCheckOptions, type PackageCheckResult } from "./check.ts";
export { checkCommand, checkSpecs, type Decision, type GateOptions, type PackageDecision } from "./gate.ts";
export { DEFAULT_ACTIONS, defaultAction, stricter, strictest } from "./policy/actions.ts";
export {
  HOOK_ADAPTERS,
  claudeAdapter,
  hookVerdict,
  type HookAdapter,
  type HookParse,
  type HookRequest,
  type HookResponse,
  type HookVerdict,
} from "./adapters/index.ts";
export {
  DECISION_JSON_VERSION,
  decisionFindings,
  serializeDecision,
  type DecidedFindingJson,
  type DecisionJson,
  type PackageDecisionJson,
} from "./report.ts";
export {
  createPolicy,
  type ActionSource,
  type DecidedFinding,
  type PackageEvidence,
  type PackageVerdict,
  type Policy,
} from "./policy/engine.ts";
export { compileList, type ListMatch, type ListMatcher } from "./policy/lists.ts";
export { checkTarball, preloadAnalyzer, type TarballCheckOptions, type TarballCheckResult } from "./tarball/check.ts";
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

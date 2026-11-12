/** The version of `@depward/diff`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

export { diffPackages } from "./diff.ts";
export {
  LARGE_CHANGE_BYTES,
  LARGE_CHANGE_RATIO,
  SCRIPT_NAMES,
  declaredDependencies,
  isLargeChange,
} from "./deltas.ts";
export { DIFF_FINDING_IDS, HIGH_RISK_CAPABILITIES, MAX_EVIDENCE, diffRisk, isPatchBump, isRawIpEndpoint } from "./rules.ts";
export type { DiffContext, PackageDiff, ScriptChange } from "./types.ts";

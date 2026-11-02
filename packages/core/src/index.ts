/** The version of `@depward/core`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

export { DepwardError, isDepwardError, type DepwardErrorCode } from "./errors.ts";
export {
  SEVERITIES,
  compareFindings,
  compareSeverity,
  type Evidence,
  type Finding,
  type Severity,
} from "./findings.ts";

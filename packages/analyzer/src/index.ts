/** The version of `@depward/analyzer`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

export { analyzePackage } from "./analyze.ts";
export { binaryFormat, classifyFile, looksBundled, looksMinified, type Classification } from "./classify.ts";
export { compareSignals, profileFindings, SIGNAL_SEVERITY } from "./signals.ts";
export {
  CAPABILITIES,
  type AnalyzeOptions,
  type Capability,
  type CapabilityUse,
  type FileKind,
  type FileSummary,
  type InstallScripts,
  type PackageProfile,
  type Signal,
  type SignalId,
} from "./types.ts";

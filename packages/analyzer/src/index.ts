/** The version of `@depward/analyzer`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

/**
 * Revision of the analyzer's output. Caches of {@link analyzePackage} results key on it
 * together with {@link VERSION}, so bump it in any change that can alter a profile (a
 * rule, a severity, a classifier), even between releases.
 */
export const ANALYSIS_REVISION: number = 2;

export { analyzePackage } from "./analyze.ts";
export { binaryFormat, classifyFile, looksBundled, looksMinified, type Classification } from "./classify.ts";
export { compareSignals, profileFindings, SIGNAL_SEVERITY } from "./signals.ts";
export { isSensitiveEnvKey } from "./text.ts";
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

/** The version of `@depward/core`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

export { DepwardError, isDepwardError, type DepwardErrorCode } from "./errors.ts";
export {
  SEVERITIES,
  compareFindings,
  compareSeverity,
  findingDocsUrl,
  type Evidence,
  type Finding,
  type Severity,
} from "./findings.ts";
export { Secret, redactUrl } from "./secret.ts";
export { createDiskCache, createMemoryCache, defaultCacheDir, type Cache, type CacheEntry } from "./cache.ts";
export { strongestHash, verifyIntegrity } from "./integrity.ts";
export {
  createRegistryClient,
  type RegistryClient,
  type RegistryClientOptions,
  type RegistryLimits,
  type RegistryTtls,
} from "./registry/client.ts";
export {
  NPM_REGISTRY,
  authHeaderFor,
  loadNpmConfig,
  nerfDart,
  normalizeRegistry,
  npmConfigFrom,
  parseNpmrc,
  registryFor,
  type LoadNpmConfigOptions,
  type NpmConfig,
  type RegistryAuth,
} from "./registry/npmrc.ts";
export {
  assertPackageName,
  type Attestations,
  type Dist,
  type DistAttestations,
  type Packument,
  type Person,
  type VersionMeta,
} from "./registry/types.ts";
export { isDeprecated, isPrerelease, publishTime, resolveVersion, type ResolveOptions } from "./registry/resolve.ts";
export { readTarball, type PackageFile, type PackageFiles, type PackageLink, type TarLimits } from "./tar.ts";
export { diffLockfiles, parseLockfile, type LockfileChange, type LockfileDiff } from "./lockfile/index.ts";
export {
  type DependencySource,
  type Lockfile,
  type LockfileEntry,
  type LockfileFormat,
  type ParseLockfileOptions,
} from "./lockfile/types.ts";
export { readFileAtRef, type ReadFileAtRefOptions } from "./git.ts";
export {
  REPORT_FORMATS,
  JSON_REPORT_VERSION,
  colorEnabled,
  countBySeverity,
  escapeMarkdown,
  escapeUnsafe,
  renderJson,
  renderMarkdown,
  renderReport,
  renderSarif,
  renderTerminal,
  sortFindings,
  summaryText,
  type JsonOptions,
  type MarkdownOptions,
  type ReportFormat,
  type ReportOptions,
  type SarifLocation,
  type SarifOptions,
  type TerminalOptions,
  type ToolInfo,
} from "./report/index.ts";

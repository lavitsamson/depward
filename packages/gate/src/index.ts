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
export type { CommandAnalysis, Invocation, InvocationKind, PackageManager, PackageRequest } from "./command/types.ts";

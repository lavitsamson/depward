import type { Finding } from "@depward/core";
import type { SpecSource } from "./spec.ts";

/** A package manager whose install and exec commands depward recognizes. */
export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

/**
 * What a package-manager invocation does: `install` adds packages, `exec` downloads and
 * runs one (`npx`, `dlx`, `bunx`, `create`), `lockfile` installs exactly what the
 * lockfile says (`npm ci`, `pnpm install` with no packages), and `other` is anything
 * else (`npm run`, `pnpm exec`, …).
 */
export type InvocationKind = "install" | "exec" | "lockfile" | "other";

/** One package-manager invocation found in a command line. */
export interface Invocation {
  readonly manager: PackageManager;
  readonly kind: InvocationKind;
  /** The invocation's words, starting with the package manager itself. */
  readonly argv: readonly string[];
}

/** A package that a command would install or run. */
export interface PackageRequest {
  /** The spec as written (for initializers, after `foo` → `create-foo` mapping). */
  readonly raw: string;
  readonly source: SpecSource;
  /** Registry specs: the real package name. Others: the alias if any, else `raw`. */
  readonly name: string;
  /** Registry specs: range or dist-tag (`latest` if none). Others: `raw`. */
  readonly range: string;
  /** Local alias, for `alias@npm:real` and `alias@<git|url|file>` specs. */
  readonly alias?: string;
  readonly via: "install" | "exec";
  readonly manager: PackageManager;
  readonly global: boolean;
  /** The invocation's flags, kept as written (`--flag value` becomes `--flag=value`). */
  readonly flags: readonly string[];
  /** Source text of the simple command the request came from. */
  readonly command: string;
}

/** Result of {@link parseInstallCommand}. */
export interface CommandAnalysis {
  readonly requests: readonly PackageRequest[];
  /** `non-registry-source`, `unparseable-command`, and `global-install` findings. */
  readonly findings: readonly Finding[];
  readonly invocations: readonly Invocation[];
}

// Package spec parsing, following the forms npm accepts (npm-package-arg), written
// ourselves to avoid a dependency. Only the classification matters here: range and
// tag validity are checked later, against the packument.

import { assertPackageName } from "@depward/core";

/** Where a spec installs from. Only `registry` specs can be checked against npm. */
export type SpecSource = "registry" | "git" | "url" | "file" | "workspace" | "other";

/** A package spec from the npm registry. */
export interface RegistrySpec {
  readonly source: "registry";
  /** The spec as written. */
  readonly raw: string;
  /** The real package name (for `alias@npm:real@range`, this is `real`). */
  readonly name: string;
  /** Semver range or dist-tag: `latest` when none was given, `*` for a bare `name@`. */
  readonly range: string;
  /** The local alias, for `alias@npm:real` specs. */
  readonly alias?: string;
}

/** A spec that installs from somewhere other than the npm registry. */
export interface NonRegistrySpec {
  readonly source: Exclude<SpecSource, "registry">;
  readonly raw: string;
  /** The local name, for `name@<git|url|file|…>` specs. */
  readonly alias?: string;
}

/** A spec that isn't a valid package spec. */
export interface InvalidSpec {
  readonly source: "invalid";
  readonly raw: string;
  readonly reason: string;
}

/** Result of {@link parsePackageSpec}. */
export type PackageSpec = RegistrySpec | NonRegistrySpec | InvalidSpec;

const GIT_PREFIX = /^(?:git\+[a-z]+:|git:\/\/|git@|ssh:\/\/|(?:github|gitlab|bitbucket|gist):)/i;
const SCHEME = /^[a-z][a-z0-9+.-]*:/i;
const LOCAL_PATH = /^(?:\.{1,2}|~)?[\\/]|^\.{1,2}$|^[a-z]:[\\/]/i;
const TARBALL = /\.(?:tgz|tar|tar\.gz)$/i;
// `user/repo` or `user/repo#ref`, as npm-package-arg defines it.
const GITHUB_SHORTHAND = /^[^@%/\s.-][^:@%/\s]*\/[^@\s/%]+(?:#.*)?$/;

function nonRegistrySource(spec: string, afterName: boolean): NonRegistrySpec["source"] | undefined {
  if (GIT_PREFIX.test(spec)) return "git";
  if (/^https?:\/\//i.test(spec)) return /\.git(?:#.*)?$/i.test(spec) ? "git" : "url";
  if (/^(?:file|link|portal):/i.test(spec)) return "file";
  if (/^workspace:/i.test(spec)) return "workspace";
  if (LOCAL_PATH.test(spec)) return "file";
  if (/^npm:/i.test(spec)) return undefined;
  if (SCHEME.test(spec)) return "other";
  if (afterName || spec.includes("@", 1)) return undefined; // `name@…`: classify the part after `@`
  if (TARBALL.test(spec)) return "file";
  if (GITHUB_SHORTHAND.test(spec)) return "git";
  return undefined;
}

function isValidName(name: string): boolean {
  try {
    assertPackageName(name);
    return true;
  } catch {
    return false;
  }
}

/** Split `name@rest` (the first `@` after a scope's leading `@`). */
function splitName(spec: string): [name: string, rest: string | undefined] {
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  return at < 0 ? [spec, undefined] : [spec.slice(0, at), spec.slice(at + 1)];
}

/**
 * Classify a package spec as written on an install command line.
 *
 * Handles `name`, `name@range`, `@scope/name@tag`, `alias@npm:real@range`, and the
 * non-registry forms (git, GitHub shorthand, URL, `file:` and local paths, `workspace:`).
 *
 * @example
 * parsePackageSpec("my-lodash@npm:lodash@^4");
 * // { source: "registry", raw: "my-lodash@npm:lodash@^4", name: "lodash", range: "^4", alias: "my-lodash" }
 */
export function parsePackageSpec(raw: string): PackageSpec {
  if (raw === "") return { source: "invalid", raw, reason: "empty package spec" };
  const direct = nonRegistrySource(raw, false);
  if (direct !== undefined) return { source: direct, raw };

  const [name, rest] = splitName(raw);
  if (!isValidName(name)) return { source: "invalid", raw, reason: "not a valid package name" };
  if (rest === undefined) return { source: "registry", raw, name, range: "latest" };

  if (/^npm:/i.test(rest)) {
    const real = parsePackageSpec(rest.slice(4));
    if (real.source !== "registry" || real.alias !== undefined) {
      return { source: "invalid", raw, reason: "npm: alias must name a registry package" };
    }
    return { source: "registry", raw, name: real.name, range: real.range, alias: name };
  }
  const aliased = nonRegistrySource(rest, true);
  if (aliased !== undefined) return { source: aliased, raw, alias: name };
  return { source: "registry", raw, name, range: rest === "" ? "*" : rest };
}

/**
 * Map an initializer argument to its package, as `npm init <x>`, `npm create`, `pnpm
 * create`, `yarn create`, and `bun create` do: `foo` → `create-foo`, `@scope` →
 * `@scope/create`, `@scope/foo` → `@scope/create-foo`. Versions are kept. Non-registry
 * specs (GitHub shorthand, local paths) are returned unchanged.
 */
export function createPackageSpec(arg: string): string {
  if (nonRegistrySource(arg, false) !== undefined) return arg;
  const [name, rest] = splitName(arg);
  const version = rest === undefined ? "" : `@${rest}`;
  if (!name.startsWith("@")) return `create-${name}${version}`;
  const slash = name.indexOf("/");
  if (slash < 0) return `${name}/create${version}`;
  return `${name.slice(0, slash)}/create-${name.slice(slash + 1)}${version}`;
}

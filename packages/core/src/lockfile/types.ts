import { DepwardError } from "../errors.ts";
import type { Finding } from "../findings.ts";

/** Lockfile formats depward understands. */
export type LockfileFormat = "npm" | "pnpm" | "yarn-classic" | "yarn-berry" | "bun";

/**
 * Where a locked package comes from. Anything other than `registry` bypasses registry
 * metadata checks, so the gate and diff treat it specially.
 */
export type DependencySource =
  | "registry"
  | "git"
  | "tarball" // an arbitrary http(s) tarball URL
  | "file" // a local directory or tarball
  | "link" // a symlinked directory (npm/pnpm `link:`, yarn `portal:`)
  | "workspace"
  | "bundled" // shipped inside its parent's tarball (npm `inBundle`)
  | "other"; // e.g. yarn `patch:` / `exec:`

/** One locked package, normalized across formats. */
export interface LockfileEntry {
  name: string;
  /** A semver version, or the raw reference (`file:…`, a URL) when the format has no version. */
  version: string;
  source: DependencySource;
  /** SRI string, or `null` when the format records none (yarn berry checksums are not SRI). */
  integrity: string | null;
  resolved: string | null;
  /** `null` when the format does not record it. */
  dev: boolean | null;
  /** `null` when the format does not record it. */
  optional: boolean | null;
}

/** A parsed lockfile. Entries are keyed by `name@version`. */
export interface Lockfile {
  path: string;
  /** `null` for recognized but unsupported formats (see `findings`). */
  format: LockfileFormat | null;
  entries: Map<string, LockfileEntry>;
  /** For example `unsupported-lockfile`. */
  findings: Finding[];
}

/** Options for {@link parseLockfile}. */
export interface ParseLockfileOptions {
  /** Default 100 MB. */
  maxBytes?: number;
}

export function invalidLockfile(path: string, why: string, cause?: unknown): DepwardError {
  return new DepwardError("INVALID_LOCKFILE", `${path}: ${why}`, cause === undefined ? undefined : { cause });
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Own entries of a record-like value; empty for anything else. */
export function entriesOf(value: unknown): [string, unknown][] {
  return isRecord(value) ? Object.entries(value) : [];
}

export function str(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

/** Splits `name@ref` (scoped names keep their leading `@`). */
export function splitIdent(ident: string): { name: string; ref: string } | null {
  const at = ident.indexOf("@", 1);
  if (at <= 0) return null;
  return { name: ident.slice(0, at), ref: ident.slice(at + 1) };
}

const SEMVER = /^v?\d+\.\d+\.\d+(?:[-+][\w.+-]*)?$/;

/** True for a plain semver version (what registries publish). */
export function isSemver(s: string): boolean {
  return SEMVER.test(s);
}

/** Classifies a dependency reference or resolution string. */
export function classifyRef(ref: string): DependencySource {
  if (ref.startsWith("workspace:")) return "workspace";
  if (ref.startsWith("link:") || ref.startsWith("portal:")) return "link";
  if (ref.startsWith("file:") || /^\.{0,2}\//.test(ref) || (/\.(?:tgz|tar\.gz|tar)$/.test(ref) && !/^https?:/.test(ref))) {
    return "file";
  }
  if (ref.startsWith("patch:") || ref.startsWith("exec:")) return "other";
  if (
    /^(?:git\+|git:|git@|github:|gitlab:|bitbucket:)/.test(ref) ||
    ref.startsWith("https://codeload.github.com/") ||
    ref.startsWith("github.com/") ||
    /\.git(?:#|$)/.test(ref)
  ) {
    return "git";
  }
  if (/^https?:\/\//.test(ref)) return "tarball";
  return "registry";
}

/**
 * Adds an entry, merging duplicates (the same `name@version` installed at several paths):
 * the merged package is dev/optional only if every copy is.
 */
export function addEntry(entries: Map<string, LockfileEntry>, entry: LockfileEntry): void {
  const key = `${entry.name}@${entry.version}`;
  const prev = entries.get(key);
  if (!prev) {
    entries.set(key, entry);
    return;
  }
  prev.dev = andNullable(prev.dev, entry.dev);
  prev.optional = andNullable(prev.optional, entry.optional);
  prev.integrity ??= entry.integrity;
  prev.resolved ??= entry.resolved;
}

function andNullable(a: boolean | null, b: boolean | null): boolean | null {
  if (a === null) return b;
  if (b === null) return a;
  return a && b;
}

/** Returns a new map with keys in code-unit order, for deterministic output. */
export function sortedEntries(entries: Map<string, LockfileEntry>): Map<string, LockfileEntry> {
  return new Map([...entries].toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

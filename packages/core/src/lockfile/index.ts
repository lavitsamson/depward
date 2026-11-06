import { parseAllDocuments, parse as parseYaml } from "yaml";
import { DepwardError } from "../errors.ts";
import { findingDocsUrl, type Finding } from "../findings.ts";
import { parseBun, parseJsonc } from "./bun.ts";
import { parseNpm } from "./npm.ts";
import { parsePnpm } from "./pnpm.ts";
import { addEntry, invalidLockfile, isRecord, sortedEntries, type Lockfile, type LockfileEntry, type LockfileFormat, type ParseLockfileOptions } from "./types.ts";
import { parseYarnBerry } from "./yarn-berry.ts";
import { parseYarnClassic } from "./yarn-classic.ts";

const KNOWN = new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]);

/**
 * Parses a lockfile into normalized `name@version` entries. The format is chosen by file
 * name (and, for `yarn.lock`, by content). Recognized but unsupported formats (npm
 * lockfileVersion 1, pnpm < 6, binary `bun.lockb`) return no entries and an
 * `unsupported-lockfile` finding.
 *
 * @throws DepwardError `INVALID_ARGUMENT` for an unknown file name, `INVALID_LOCKFILE`
 *   when the contents cannot be parsed, `LIMIT_EXCEEDED` above `maxBytes`.
 */
export function parseLockfile(path: string, contents: string, opts: ParseLockfileOptions = {}): Lockfile {
  const base = path.split(/[/\\]/).pop() ?? "";
  if (!KNOWN.has(base)) throw new DepwardError("INVALID_ARGUMENT", `not a known lockfile name: ${base}`);
  if (contents.length > (opts.maxBytes ?? 100 * 1024 * 1024)) {
    throw new DepwardError("LIMIT_EXCEEDED", `${path} is larger than the lockfile size limit`);
  }

  const done = (format: LockfileFormat, entries: Map<string, LockfileEntry> | null, detail: string): Lockfile =>
    entries ? { path, format, entries: sortedEntries(entries), findings: [] } : unsupported(path, detail);

  switch (base) {
    case "package-lock.json":
    case "npm-shrinkwrap.json":
      return done("npm", parseNpm(asObject(path, () => JSON.parse(contents))), "npm lockfileVersion 1 is not supported; run npm 7+ to upgrade it");
    case "pnpm-lock.yaml": {
      // pnpm 11+ may write two YAML documents: an "env" document (pnpm itself and config
      // dependencies) followed by the project lockfile. Each is an inventory of packages
      // that pnpm installs, so all of them are read and merged.
      // https://pnpm.io/lockfile
      const merged = new Map<string, LockfileEntry>();
      for (const doc of tryParse(path, () => yamlDocuments(contents))) {
        const entries = parsePnpm(checkObject(path, doc));
        if (!entries) return unsupported(path, "only pnpm lockfileVersion 6.x and 9.x are supported");
        for (const entry of entries.values()) addEntry(merged, entry);
      }
      return done("pnpm", merged, "");
    }
    case "bun.lock":
      return done("bun", parseBun(asObject(path, () => parseJsonc(contents))), "");
    case "bun.lockb":
      return unsupported(path, "the binary bun.lockb format is not supported; run `bun install --save-text-lockfile`");
    default: {
      // yarn.lock
      if (/^# yarn lockfile v1\s*$/m.test(contents)) {
        return done("yarn-classic", tryParse(path, () => parseYarnClassic(contents)), "");
      }
      const doc = asObject(path, () => yaml(contents));
      if (!isRecord(doc["__metadata"])) throw invalidLockfile(path, "yarn.lock is neither yarn v1 nor yarn berry");
      return done("yarn-berry", parseYarnBerry(doc), "");
    }
  }
}

// maxAliasCount bounds "billion laughs" expansion; real lockfiles use no aliases.
const MAX_ALIASES = 50;

function yaml(text: string): unknown {
  return parseYaml(text, { maxAliasCount: MAX_ALIASES, uniqueKeys: false });
}

function yamlDocuments(text: string): unknown[] {
  const docs = parseAllDocuments(text, { uniqueKeys: false });
  if (!Array.isArray(docs) || docs.length === 0) throw new Error("no YAML documents");
  return docs.map((doc) => {
    const [error] = doc.errors;
    if (error) throw error;
    return doc.toJS({ maxAliasCount: MAX_ALIASES });
  });
}

function tryParse<T>(path: string, parse: () => T): T {
  try {
    return parse();
  } catch (cause) {
    throw invalidLockfile(path, "could not be parsed", cause);
  }
}

function asObject(path: string, parse: () => unknown): Record<string, unknown> {
  return checkObject(path, tryParse(path, parse));
}

function checkObject(path: string, doc: unknown): Record<string, unknown> {
  if (!isRecord(doc)) throw invalidLockfile(path, "top level is not an object");
  for (const key of ["packages", "snapshots", "importers"]) {
    if (key in doc && doc[key] !== null && !isRecord(doc[key])) throw invalidLockfile(path, `"${key}" is not an object`);
  }
  return doc;
}

function unsupported(path: string, detail: string): Lockfile {
  const finding: Finding = {
    id: "unsupported-lockfile",
    severity: "info",
    package: path,
    message: `${path} uses a lockfile format depward cannot read, so its dependencies were not checked`,
    evidence: detail ? [{ file: path, detail }] : [{ file: path }],
    docsUrl: findingDocsUrl("unsupported-lockfile"),
  };
  return { path, format: null, entries: new Map(), findings: [finding] };
}

/** One entry present in both lockfiles whose content differs. */
export interface LockfileChange {
  before: LockfileEntry;
  after: LockfileEntry;
}

/** The difference between two lockfiles, keyed by `name@version`. */
export interface LockfileDiff {
  /** In `head` only. A version bump shows up as one removed and one added entry. */
  added: LockfileEntry[];
  /** In `base` only. */
  removed: LockfileEntry[];
  /** Same `name@version` with a different source, integrity, resolution, or dev/optional flag. */
  changed: LockfileChange[];
}

/**
 * Compares two lockfiles. Fields one side does not record (`null`) are not compared, so
 * switching package managers does not report every entry as changed. When neither side
 * has integrity, a different `resolved` (for example a new git commit) counts as a change.
 */
export function diffLockfiles(base: Lockfile, head: Lockfile): LockfileDiff {
  const added: LockfileEntry[] = [];
  const removed: LockfileEntry[] = [];
  const changed: LockfileChange[] = [];
  for (const [key, after] of head.entries) {
    const before = base.entries.get(key);
    if (!before) added.push(after);
    else if (entryChanged(before, after)) changed.push({ before, after });
  }
  for (const [key, before] of base.entries) if (!head.entries.has(key)) removed.push(before);
  return {
    added: added.toSorted(byKey),
    removed: removed.toSorted(byKey),
    changed: changed.toSorted((x, y) => byKey(x.after, y.after)),
  };
}

function byKey(a: LockfileEntry, b: LockfileEntry): number {
  const ka = `${a.name}@${a.version}`;
  const kb = `${b.name}@${b.version}`;
  return ka < kb ? -1 : ka > kb ? 1 : 0;
}

/** True when both sides record a value and the values differ. */
function differs<T>(x: T | null, y: T | null): boolean {
  return x !== null && y !== null && x !== y;
}

function entryChanged(a: LockfileEntry, b: LockfileEntry): boolean {
  if (a.source !== b.source) return true;
  if (differs(a.integrity, b.integrity)) return true;
  if (a.integrity === null && b.integrity === null && differs(a.resolved, b.resolved)) return true;
  return differs(a.dev, b.dev) || differs(a.optional, b.optional);
}

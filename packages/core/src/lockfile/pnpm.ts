// pnpm-lock.yaml, lockfileVersion 6.x and 9.x.
// v9 spec: https://github.com/pnpm/spec/blob/master/lockfile/9.0.md
//
// v6: package keys are `/name@version(peer@x)`, and each entry has `dev` (absent means
//     used by both prod and dev) and `optional`. Non-registry keys (`file:…`,
//     `github.com/…`) carry `name` and `version` fields.
// v9: keys are `name@version`; `snapshots` holds the dependency graph and `optional`,
//     and there is no dev flag, so dev-ness is derived by walking from the importers.

import { addEntry, classifyRef, entriesOf, isRecord, isSemver, splitIdent, str, type DependencySource, type LockfileEntry } from "./types.ts";

const DEP_FIELDS = ["dependencies", "optionalDependencies"] as const;
// pnpm 11+ env document roots: pnpm itself and config dependencies run code, so they count as prod.
const PROD_ROOT_FIELDS = ["dependencies", "optionalDependencies", "packageManagerDependencies", "configDependencies"];

/** Returns `null` for unsupported lockfile versions (below 6, or above 9). */
export function parsePnpm(doc: Record<string, unknown>): Map<string, LockfileEntry> | null {
  const major = Math.trunc(Number.parseFloat(String(doc["lockfileVersion"] ?? "")));
  if (major !== 6 && major !== 9) return null;
  const v9 = major === 9;
  const importers = importersOf(doc);
  const entries = new Map<string, LockfileEntry>();

  const reach = v9 ? walkSnapshots(doc, importers) : null;
  const snapshotOptional = v9 ? optionalByPackage(doc) : null;

  for (const [key, raw] of entriesOf(doc["packages"])) {
    if (!isRecord(raw)) continue;
    const id = stripPeers(v9 ? key : key.replace(/^\//, ""));
    const ident = splitIdent(id);
    const name = str(raw["name"]) ?? ident?.name;
    if (!name) continue;
    const ref = ident && ident.name === name ? ident.ref : id;
    const version = str(raw["version"]) ?? ref;
    const resolution = isRecord(raw["resolution"]) ? raw["resolution"] : {};

    let dev: boolean | null;
    let optional: boolean | null;
    if (reach) {
      dev = reach.prod.has(id) ? false : reach.dev.has(id) ? true : null;
      optional = snapshotOptional?.get(id) ?? false;
    } else {
      dev = raw["dev"] === true;
      optional = raw["optional"] === true;
    }

    addEntry(entries, {
      name,
      version,
      source: sourceOf(ref, resolution),
      integrity: str(resolution["integrity"]),
      resolved: str(resolution["tarball"]) ?? str(resolution["repo"]) ?? str(resolution["directory"]),
      dev,
      optional,
    });
  }

  // `link:` dependencies only appear in importers.
  for (const [, deps] of importers) {
    for (const [field, map] of deps) {
      for (const [name, version] of map) {
        if (!version.startsWith("link:")) continue;
        addEntry(entries, {
          name, version, source: "link", integrity: null, resolved: version.slice(5),
          dev: field === "devDependencies", optional: field === "optionalDependencies",
        });
      }
    }
  }
  return entries;
}

function stripPeers(id: string): string {
  const paren = id.indexOf("(");
  return paren < 0 ? id : id.slice(0, paren);
}

function sourceOf(ref: string, resolution: Record<string, unknown>): DependencySource {
  if (resolution["type"] === "git" || resolution["gitHosted"] === true) return "git";
  if (resolution["type"] === "directory") return "file";
  if (isSemver(ref)) return "registry";
  return classifyRef(ref);
}

type DepMaps = Map<string, Map<string, string>>; // field → name → version

/** Importers as `path → field → name → version`. v6 single-project files keep deps at the top level. */
function importersOf(doc: Record<string, unknown>): Map<string, DepMaps> {
  const out = new Map<string, DepMaps>();
  const read = (src: Record<string, unknown>): DepMaps => {
    const maps: DepMaps = new Map();
    for (const field of [...PROD_ROOT_FIELDS, "devDependencies"]) {
      const m = new Map<string, string>();
      for (const [name, val] of entriesOf(src[field])) {
        const version = isRecord(val) ? str(val["version"]) : str(val);
        if (version) m.set(name, version);
      }
      maps.set(field, m);
    }
    return maps;
  };
  if (isRecord(doc["importers"])) {
    for (const [path, imp] of entriesOf(doc["importers"])) if (isRecord(imp)) out.set(path, read(imp));
  } else {
    out.set(".", read(doc));
  }
  return out;
}

/** v9: which package ids are reachable from prod roots, and which from dev roots. */
function walkSnapshots(doc: Record<string, unknown>, importers: Map<string, DepMaps>): { prod: Set<string>; dev: Set<string> } {
  const snapshots = new Map(entriesOf(doc["snapshots"]));
  const resolve = (name: string, value: string): string | null => {
    if (snapshots.has(`${name}@${value}`)) return `${name}@${value}`;
    if (snapshots.has(value)) return value; // aliases: `string-width@4.2.3`
    return null;
  };
  const walk = (roots: string[]): Set<string> => {
    const seen = new Set<string>();
    const stack = [...roots];
    while (stack.length > 0) {
      const key = stack.pop()!;
      if (seen.has(key)) continue;
      seen.add(key);
      const snap = snapshots.get(key);
      if (!isRecord(snap)) continue;
      for (const field of DEP_FIELDS) {
        for (const [n, v] of entriesOf(snap[field])) {
          const next = typeof v === "string" ? resolve(n, v) : null;
          if (next && !seen.has(next)) stack.push(next);
        }
      }
    }
    return new Set([...seen].map(stripPeers));
  };
  const rootsFor = (fields: string[]): string[] => {
    const roots: string[] = [];
    for (const [, maps] of importers) {
      for (const field of fields) {
        for (const [name, version] of maps.get(field) ?? []) {
          const key = resolve(name, version);
          if (key) roots.push(key);
        }
      }
    }
    return roots;
  };
  return { prod: walk(rootsFor(PROD_ROOT_FIELDS)), dev: walk(rootsFor(["devDependencies"])) };
}

/** v9: a package is optional only if every snapshot of it is. */
function optionalByPackage(doc: Record<string, unknown>): Map<string, boolean> {
  const out = new Map<string, boolean>();
  for (const [key, snap] of entriesOf(doc["snapshots"])) {
    const id = stripPeers(key);
    const optional = isRecord(snap) && snap["optional"] === true;
    out.set(id, (out.get(id) ?? true) && optional);
  }
  return out;
}

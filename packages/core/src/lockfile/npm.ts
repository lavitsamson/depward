// package-lock.json / npm-shrinkwrap.json, lockfileVersion 2 and 3 (the `packages` map).
// https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json

import { addEntry, classifyRef, entriesOf, isRecord, isSemver, str, type LockfileEntry } from "./types.ts";

const NM = "node_modules/";

/** Parses the `packages` map. Returns `null` for lockfileVersion 1 (unsupported). */
export function parseNpm(doc: Record<string, unknown>): Map<string, LockfileEntry> | null {
  const lockfileVersion = doc["lockfileVersion"];
  if (typeof lockfileVersion !== "number" || lockfileVersion < 2 || !isRecord(doc["packages"])) return null;
  const packages = doc["packages"];
  const root = isRecord(packages[""]) ? packages[""] : {};
  const workspaceGlobs = (Array.isArray(root["workspaces"]) ? root["workspaces"] : [])
    .filter((g): g is string => typeof g === "string")
    .map(globToRegExp);

  const entries = new Map<string, LockfileEntry>();
  for (const [key, raw] of entriesOf(packages)) {
    // Only installed paths. Other keys ("", "packages/a") are the project's own folders.
    const idx = key.lastIndexOf(NM);
    if (idx < 0 || !isRecord(raw)) continue;
    const installName = key.slice(idx + NM.length);
    const name = str(raw["name"]) ?? installName;
    const resolved = str(raw["resolved"]);
    const integrity = str(raw["integrity"]);
    const flags = { dev: raw["dev"] === true, optional: raw["optional"] === true };

    if (raw["link"] === true) {
      const target = resolved ?? "";
      const targetMeta = packages[target];
      const targetVersion = isRecord(targetMeta) ? str(targetMeta["version"]) : null;
      const isWorkspace = workspaceGlobs.some((re) => re.test(target));
      addEntry(entries, {
        name, version: targetVersion ?? `link:${target}`, source: isWorkspace ? "workspace" : "link",
        integrity: null, resolved, ...flags,
      });
      continue;
    }

    const version = str(raw["version"]) ?? resolved ?? "";
    let source = raw["inBundle"] === true ? "bundled" as const : resolved ? classifyRef(resolved) : "registry" as const;
    // npm records registry packages by their tarball URL: a semver version + /-/ path.
    // Integrity is not required here: an entry that looks like a registry package but
    // lacks it must still be checked as one (diff's `lockfile-untrusted-source`), not
    // waved through as an ordinary tarball dependency.
    if (source === "tarball" && isSemver(version) && resolved?.includes("/-/")) source = "registry";
    addEntry(entries, { name, version, source, integrity, resolved, ...flags });
  }
  return entries;
}

/** Minimal workspace glob support: `*` within a segment, `**` across segments. */
function globToRegExp(glob: string): RegExp {
  const body = glob
    .replace(/^\.\//, "")
    .replace(/\/$/, "")
    .split(/(\*\*|\*)/)
    .map((part) => (part === "**" ? ".*" : part === "*" ? "[^/]*" : part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")))
    .join("");
  return new RegExp(`^${body}$`);
}

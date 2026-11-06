// yarn.lock for yarn 2+ ("berry"): YAML with a `__metadata` block. Each entry's
// `resolution` is `name@<protocol>:<ref>`. `checksum` hashes yarn's cache zip, not the
// npm tarball, so it is not comparable with SRI integrity and is not reported.
// https://yarnpkg.com/protocols

import { addEntry, classifyRef, entriesOf, isRecord, splitIdent, str, type DependencySource, type LockfileEntry } from "./types.ts";

export function parseYarnBerry(doc: Record<string, unknown>): Map<string, LockfileEntry> {
  const entries = new Map<string, LockfileEntry>();
  for (const [key, raw] of entriesOf(doc)) {
    if (key === "__metadata" || !isRecord(raw)) continue;
    const resolution = str(raw["resolution"]);
    const ident = resolution ? splitIdent(resolution) : null;
    if (!ident) continue;
    if (ident.ref === "workspace:.") continue; // the project root itself
    const source = berrySource(ident.ref);
    addEntry(entries, {
      name: ident.name,
      version: str(raw["version"]) ?? ident.ref,
      source,
      integrity: null,
      resolved: source === "registry" ? null : ident.ref,
      dev: null,
      optional: null,
    });
  }
  return entries;
}

function berrySource(ref: string): DependencySource {
  if (ref.startsWith("npm:")) return "registry";
  return classifyRef(ref);
}

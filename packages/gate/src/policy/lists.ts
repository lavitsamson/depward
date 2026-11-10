// The config's `allow` and `deny` lists. Spec: docs/specs/gate.md §Policy engine.
//
// An entry is a name glob, optionally followed by an exact version:
//   "@myorg/*"            every package in the scope
//   "left-pad"            one package, any version
//   "event-stream@3.3.6"  one version
// In names, `*` and `?` match within one path segment (never `/`), and `**` matches
// across segments. Versions match exactly, as strings: no ranges, so an entry can never
// cover a version nobody reviewed.

import { DepwardError } from "@depward/core";

/** Which list matched a package, and the entry that matched. */
export interface ListMatch {
  readonly list: "allow" | "deny";
  readonly entry: string;
}

interface CompiledEntry {
  readonly entry: string;
  readonly name: RegExp;
  readonly version: string | null;
}

const NAME_CHARS = /^(?:@[a-z0-9*?._~-]+\/)?[a-z0-9*?._~-]+$/i;
const VERSION_CHARS = /^[0-9A-Za-z.+-]+$/;

function globToRegExp(glob: string): RegExp {
  let src = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] as string;
    if (c === "*" && glob[i + 1] === "*") {
      src += ".*";
      i++;
    } else if (c === "*") src += "[^/]*";
    else if (c === "?") src += "[^/]";
    else src += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${src}$`);
}

function compile(entry: string, list: string): CompiledEntry {
  const at = entry.indexOf("@", entry.startsWith("@") ? 1 : 0);
  const name = at < 0 ? entry : entry.slice(0, at);
  const version = at < 0 ? null : entry.slice(at + 1);
  if (!NAME_CHARS.test(name) || (version !== null && !VERSION_CHARS.test(version))) {
    throw new DepwardError("INVALID_CONFIG", `"${list}" entry ${JSON.stringify(entry)} must be a package name glob, optionally with an exact @version`);
  }
  return { entry, name: globToRegExp(name), version };
}

/** Matches packages against one list. */
export interface ListMatcher {
  /** The first entry matching `name` (and `version`, for versioned entries), or `null`. */
  match(name: string, version: string | null): string | null;
  /** Whether some entry matches `name` regardless of version, so no lookup is needed. */
  matchesName(name: string): string | null;
}

/**
 * Compiles a list of entries.
 *
 * @throws DepwardError `INVALID_CONFIG` for a malformed entry
 */
export function compileList(entries: readonly string[], list: "allow" | "deny"): ListMatcher {
  const compiled = entries.map((e) => compile(e, list));
  return {
    match(name, version) {
      return compiled.find((c) => c.name.test(name) && (c.version === null || c.version === version))?.entry ?? null;
    },
    matchesName(name) {
      return compiled.find((c) => c.version === null && c.name.test(name))?.entry ?? null;
    },
  };
}

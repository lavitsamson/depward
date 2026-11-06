// bun.lock (text, JSONC). Tuple layouts, from Bun's src/install/lockfile/bun.lock.rs:
//   npm       → ["name@version", registry, INFO, integrity]
//   symlink   → ["name@link:path", INFO]
//   folder    → ["name@file:path", INFO]
//   workspace → ["name@workspace:path"]
//   tarball   → ["name@tarball", INFO, integrity?]
//   root      → ["name@root:", { bin, binDir }]
//   git       → ["name@git+repo", INFO, bun-tag]
//   github    → ["name@github:user/repo", INFO, bun-tag]
// The binary bun.lockb is not supported. dev/optional are not recorded per package.

import { addEntry, classifyRef, entriesOf, isSemver, splitIdent, str, type LockfileEntry } from "./types.ts";

export function parseBun(doc: Record<string, unknown>): Map<string, LockfileEntry> {
  const entries = new Map<string, LockfileEntry>();
  for (const [, tuple] of entriesOf(doc["packages"])) {
    if (!Array.isArray(tuple)) continue;
    const ident = typeof tuple[0] === "string" ? splitIdent(tuple[0]) : null;
    if (!ident || ident.ref.startsWith("root:")) continue;
    const { name, ref } = ident;
    const isRegistry = isSemver(ref);
    const source = isRegistry ? "registry" : classifyRef(ref);
    const integrity = isRegistry ? str(tuple[3]) : source === "tarball" || source === "file" ? sri(tuple[2]) : null;
    addEntry(entries, {
      name,
      version: ref,
      source,
      integrity,
      resolved: isRegistry ? null : ref,
      dev: null,
      optional: null,
    });
  }
  return entries;
}

function sri(value: unknown): string | null {
  const s = str(value);
  return s && /^sha(?:1|256|384|512)-/.test(s) ? s : null;
}

/**
 * Parses JSONC: JSON plus `//` and `/* *\/` comments and trailing commas. Strings are
 * copied verbatim, so comment-like text inside them is preserved.
 */
export function parseJsonc(text: string): unknown {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end < 0 ? text.length : end + 2;
    } else if (c === ",") {
      // Drop the comma if only whitespace/comments stand between it and a closing bracket.
      let j = i + 1;
      for (;;) {
        while (j < text.length && /\s/.test(text[j] ?? "")) j++;
        if (text.startsWith("//", j)) j = text.indexOf("\n", j) < 0 ? text.length : text.indexOf("\n", j);
        else if (text.startsWith("/*", j)) j = text.indexOf("*/", j + 2) < 0 ? text.length : text.indexOf("*/", j + 2) + 2;
        else break;
      }
      if (text[j] !== "}" && text[j] !== "]") out += ",";
      i++;
    } else {
      out += c;
      i++;
    }
  }
  return JSON.parse(out);
}

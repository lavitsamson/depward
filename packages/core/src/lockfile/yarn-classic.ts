// yarn.lock v1 ("# yarn lockfile v1"). Not YAML: an indentation-based format with
// `key value` pairs, optionally quoted, and `key:` opening a nested block.
// Grammar reference: yarn v1 src/lockfile/parse.js.

import { addEntry, classifyRef, splitIdent, type LockfileEntry } from "./types.ts";

interface Block {
  specs: string[];
  fields: Map<string, string>;
}

/** Parses a yarn v1 lockfile. Throws a plain `Error` on syntax errors (wrapped by the caller). */
export function parseYarnClassic(text: string): Map<string, LockfileEntry> {
  const entries = new Map<string, LockfileEntry>();
  for (const block of blocks(text)) {
    const first = block.specs[0];
    const parsed = first ? splitIdent(first) : null;
    const version = block.fields.get("version");
    if (!parsed || !version) continue;
    let { name, ref } = parsed;
    // Aliases: `alias@npm:real@^1.2.3`.
    if (ref.startsWith("npm:")) {
      const real = splitIdent(ref.slice(4));
      if (real) ({ name, ref } = real);
      else ref = ref.slice(4);
    }
    const rawResolved = block.fields.get("resolved") ?? null;
    let source = classifyRef(ref);
    if (source === "registry" && rawResolved && classifyRef(rawResolved) === "git") source = "git";
    addEntry(entries, {
      name,
      version,
      source,
      integrity: block.fields.get("integrity") ?? null,
      // Registry tarball URLs carry a `#<sha1>` fragment; git URLs carry a commit we keep.
      resolved: rawResolved?.replace(/(\.tgz)#[0-9a-f]{40}$/, "$1") ?? null,
      dev: null,
      optional: null,
    });
  }
  return entries;
}

function* blocks(text: string): Generator<Block> {
  let current: Block | null = null;
  let lineNo = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    lineNo++;
    if (rawLine.trim() === "" || rawLine.trimStart().startsWith("#")) continue;
    const indent = rawLine.length - rawLine.trimStart().length;
    const line = rawLine.trim();
    if (indent === 0) {
      if (current) yield current;
      if (!line.endsWith(":")) throw new Error(`line ${lineNo}: expected "<specs>:"`);
      current = { specs: tokens(line.slice(0, -1), lineNo).filter((t) => t !== ","), fields: new Map() };
    } else if (indent === 2 && current) {
      if (line.endsWith(":")) continue; // nested block (dependencies:), whose lines we skip
      const [key, value] = tokens(line, lineNo);
      if (key !== undefined && value !== undefined) current.fields.set(key, value);
    } else if (!current) {
      throw new Error(`line ${lineNo}: unexpected indentation`);
    }
  }
  if (current) yield current;
}

/** Splits a line into tokens: double-quoted strings (JSON escapes), commas, and bare words. */
function tokens(line: string, lineNo: number): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (c === " " || c === "\t") {
      i++;
    } else if (c === ",") {
      out.push(",");
      i++;
    } else if (c === '"') {
      let j = i + 1;
      while (j < line.length && line[j] !== '"') j += line[j] === "\\" ? 2 : 1;
      if (j >= line.length) throw new Error(`line ${lineNo}: unterminated string`);
      out.push(JSON.parse(line.slice(i, j + 1)) as string);
      i = j + 1;
    } else {
      let j = i;
      while (j < line.length && !/[\s,]/.test(line[j] ?? "")) j++;
      out.push(line.slice(i, j));
      i = j;
    }
  }
  // A comma-separated spec list with bare words (`a@^1, b@^2`) also arrives here.
  return out.flatMap((t) => (t !== "," && t.endsWith(",") ? [t.slice(0, -1), ","] : [t]));
}

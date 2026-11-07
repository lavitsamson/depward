// acorn options: https://github.com/acornjs/acorn/tree/master/acorn#interface

import { parse, type Options, type Program } from "acorn";

const errorPos = (e: unknown): number => (e as { pos?: number }).pos ?? -1;

const BASE: Omit<Options, "sourceType"> = {
  ecmaVersion: "latest",
  allowHashBang: true,
  allowReturnOutsideFunction: true,
  locations: true,
};

/** Parses as an ES module first, then as a script. Returns the error message if both fail. */
export function parseJs(text: string): { program: Program } | { error: string } {
  try {
    return { program: parse(text, { ...BASE, sourceType: "module" }) };
  } catch (moduleErr) {
    try {
      return { program: parse(text, { ...BASE, sourceType: "script" }) };
    } catch (scriptErr) {
      // Report whichever parse got further into the file.
      const err = errorPos(moduleErr) > errorPos(scriptErr) ? moduleErr : scriptErr;
      return { error: err instanceof Error ? err.message : "parse error" };
    }
  }
}

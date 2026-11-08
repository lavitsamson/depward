import type { Word } from "./shell.ts";

/** A flag that took a value, in command-line order. */
export interface FlagValue {
  readonly flag: string;
  readonly value: Word;
}

/** Result of {@link scanArgs}. */
export interface ScannedArgs {
  readonly positionals: Word[];
  readonly flags: string[];
  readonly values: FlagValue[];
  /** With `stopAtPositional`: the words after the first positional. */
  readonly rest: readonly Word[];
}

/**
 * Split arguments into flags and positionals. `valueFlags` lists flags that take the next
 * word as their value (`--flag=value` always works). Words after `--` are positionals.
 * With `stopAtPositional`, scanning ends at the first positional; the rest belongs to a
 * subcommand or to the program being run.
 */
export function scanArgs(words: readonly Word[], valueFlags: ReadonlySet<string>, stopAtPositional: boolean): ScannedArgs {
  const result: ScannedArgs = { positionals: [], flags: [], values: [], rest: [] };
  let afterDashes = false;
  for (let i = 0; i < words.length; i++) {
    const word = words[i] as Word;
    const t = word.text;
    if (!afterDashes && !word.dynamic && t === "--") {
      afterDashes = true;
      continue;
    }
    // A flag with a computed value (`--registry=$R`) is still a flag.
    if (!afterDashes && t.length > 1 && t.startsWith("-")) {
      const eq = t.indexOf("=");
      if (eq > 0) {
        result.flags.push(t);
        result.values.push({ flag: t.slice(0, eq), value: { text: t.slice(eq + 1), dynamic: false } });
      } else if (valueFlags.has(t) && i + 1 < words.length) {
        const value = words[++i] as Word;
        result.flags.push(`${t}=${value.text}`);
        result.values.push({ flag: t, value });
      } else result.flags.push(t);
      continue;
    }
    result.positionals.push(word);
    if (stopAtPositional) return { ...result, rest: words.slice(i + 1) };
  }
  return result;
}

/** Values given for any of `names`, in order. */
export function valuesOf(values: readonly FlagValue[], names: readonly string[]): Word[] {
  return values.filter((v) => names.includes(v.flag)).map((v) => v.value);
}

/** The program name of a command word: its basename, lowercased, without a Windows extension. */
export function programName(word: string): string {
  const base = word.slice(Math.max(word.lastIndexOf("/"), word.lastIndexOf("\\")) + 1).toLowerCase();
  return base.replace(/\.(?:exe|cmd|bat|ps1)$/, "");
}

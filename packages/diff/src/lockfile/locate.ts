// Finds the line of a package entry in lockfile text, so SARIF results land on the
// changed lines of a pull request (GitHub shows code-scanning alerts in the PR diff only
// on lines the PR touched). Heuristic and format-agnostic: a miss returns `undefined`
// and the caller falls back to line 1. Pure.

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

/** At most this many occurrences of a name are examined per lookup. */
const MAX_CANDIDATES = 10_000;

/**
 * Returns a lookup `(name, version) => line` over one lockfile's text. The text is
 * indexed once, so many lookups stay cheap. Lines are 1-based.
 *
 * Recognized shapes, tried in this order:
 * - a key that names the exact version: pnpm `name@1.2.3:` / `/name@1.2.3:` /
 *   `/name/1.2.3:`, bun `"name@1.2.3"`;
 * - a header followed within three lines by its version: npm `"node_modules/name": {`
 *   then `"version": "1.2.3"`, yarn `name@^1.0.0:` then `version "1.2.3"`.
 */
export function lockfileLocator(text: string): (name: string, version: string) => number | undefined {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  const lineAt = (offset: number): number => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((starts[mid] ?? 0) <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };
  const lineText = (i: number): string => {
    const end = i + 1 < starts.length ? (starts[i + 1] ?? text.length) - 1 : text.length;
    const s = text.slice(starts[i] ?? 0, end);
    return s.endsWith("\r") ? s.slice(0, -1) : s;
  };

  return (name, version) => {
    if (name === "" || version === "") return undefined;
    const candidates: number[] = [];
    for (let at = text.indexOf(name); at !== -1 && candidates.length < MAX_CANDIDATES; at = text.indexOf(name, at + name.length)) {
      const l = lineAt(at);
      if (candidates.at(-1) !== l) candidates.push(l);
    }
    const n = escapeRegExp(name);
    const v = escapeRegExp(version);
    const direct = new RegExp(`(?:^\\s*|["'\\[]\\s*)["']?/?${n}@${v}(?=[\\s"':(_,]|$)|^\\s*/${n}/${v}(?=[\\s"':(_]|$)`);
    for (const l of candidates) if (direct.test(lineText(l))) return l + 1;

    const header = new RegExp(`node_modules/${n}"|(?:^|[\\s"',])${n}@`);
    const versionLine = new RegExp(`version.*(?<![\\w.+-])${v}(?![\\w.+-])`);
    for (const l of candidates) {
      if (!header.test(lineText(l))) continue;
      for (let j = l + 1; j <= l + 3 && j < starts.length; j++) {
        const t = lineText(j);
        // The entry ends at a blank line, an unindented line, or the next npm key.
        if (t.trim() === "" || !/^\s/.test(t) || t.includes("node_modules/")) break;
        if (versionLine.test(t)) return l + 1;
      }
    }
    return undefined;
  };
}

/** The 1-based line of `name@version` in lockfile text, or `undefined`. See {@link lockfileLocator}. */
export function locateEntry(text: string, name: string, version: string): number | undefined {
  return lockfileLocator(text)(name, version);
}

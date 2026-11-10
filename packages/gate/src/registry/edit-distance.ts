// Edit distance for typosquat detection, written here instead of adding a dependency
// (CLAUDE.md). It is the optimal string alignment (OSA) distance: Levenshtein plus
// swapping two adjacent characters as a single edit, because swapped letters are one
// of the most common typos (`axois` → `axios`, `raect` → `react`).

/**
 * OSA edit distance between `a` and `b`: insertions, deletions, substitutions, and
 * swaps of two adjacent characters each cost 1 (a substring is edited at most once).
 * Compared by UTF-16 code unit. Returns `max + 1` as soon as the distance is known to
 * exceed `max`, so a scan over thousands of names stays cheap.
 */
export function editDistance(a: string, b: string, max: number = Number.POSITIVE_INFINITY): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  if (a.length === 0) return Math.min(b.length, max + 1);
  if (b.length === 0) return Math.min(a.length, max + 1);

  let before = new Uint32Array(b.length + 1); // row i - 2
  let prev = new Uint32Array(b.length + 1); // row i - 1
  let curr = new Uint32Array(b.length + 1); // row i
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  let prevMin = 0;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    let rowMin = i;
    const ca = a.charCodeAt(i - 1);
    for (let j = 1; j <= b.length; j++) {
      const cb = b.charCodeAt(j - 1);
      const cost = ca === cb ? 0 : 1;
      let v = Math.min((prev[j] ?? 0) + 1, (curr[j - 1] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
      if (i > 1 && j > 1 && ca === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === cb) {
        v = Math.min(v, (before[j - 2] ?? 0) + 1);
      }
      curr[j] = v;
      if (v < rowMin) rowMin = v;
    }
    // A swap reaches back two rows, so stop only when both recent rows exceed max.
    if (rowMin > max && prevMin > max) return max + 1;
    prevMin = rowMin;
    [before, prev, curr] = [prev, curr, before];
  }
  const d = prev[b.length] ?? 0;
  return d > max ? max + 1 : d;
}

import { describe, expect, test } from "vitest";
import { createPopularIndex, editDistance, loadGateData } from "../src/index.ts";
import { maxDistanceFor, separatorKey } from "../src/registry/typosquat.ts";

/** Straightforward full-matrix OSA distance, as a reference for the optimized one. */
function referenceOsa(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_unused, j) => (i === 0 ? j : j === 0 ? i : 0)));
  const at = (i: number, j: number): number => d[i]?.[j] ?? 0;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(at(i - 1, j) + 1, at(i, j - 1) + 1, at(i - 1, j - 1) + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, at(i - 2, j - 2) + 1);
      (d[i] as number[])[j] = v;
    }
  }
  return at(a.length, b.length);
}

describe("editDistance (optimal string alignment)", () => {
  test.each([
    ["", "", 0],
    ["a", "", 1],
    ["", "abc", 3],
    ["kitten", "sitting", 3],
    ["lodash", "lodash", 0],
    ["express", "expres", 1],
    ["@types/node", "@types/nodes", 1],
    ["flaw", "lawn", 2],
    // Swapping two adjacent characters is one edit.
    ["ab", "ba", 1],
    ["lodash", "lodahs", 1],
    ["react", "raect", 1],
    ["axios", "axois", 1],
    ["stable", "stabel", 1],
    ["abcdef", "badcfe", 3],
    // OSA edits each substring at most once, so this is 3 (true Damerau would say 2).
    ["ca", "abc", 3],
  ])("%j vs %j = %i", (a, b, d) => {
    expect(editDistance(a, b)).toBe(d);
    expect(editDistance(b, a)).toBe(d);
  });

  test("stops early at max and reports max + 1", () => {
    expect(editDistance("kitten", "sitting", 1)).toBe(2);
    expect(editDistance("abc", "abcdefgh", 2)).toBe(3);
    expect(editDistance("abcdef", "uvwxyz", 2)).toBe(3);
    expect(editDistance("abcdef", "badcfe", 2)).toBe(3);
    expect(editDistance("lodash", "lodahs", 1)).toBe(1);
    expect(editDistance("", "abcd", 2)).toBe(3);
  });

  test("matches the reference on random strings, with and without the early exit", () => {
    let seed = 42;
    const rand = (n: number): number => {
      seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
      return seed % n;
    };
    const word = (): string => Array.from({ length: rand(8) }, () => "abcd"[rand(4)]).join("");
    for (let k = 0; k < 2000; k++) {
      const a = word();
      const b = word();
      const want = referenceOsa(a, b);
      expect(editDistance(a, b), `${a} / ${b}`).toBe(want);
      for (const max of [0, 1, 2, 3]) expect(editDistance(a, b, max), `${a} / ${b} max ${max}`).toBe(Math.min(want, max + 1));
    }
  });
});

describe("separatorKey / maxDistanceFor", () => {
  test("folds case, scope markers, and separators", () => {
    expect(separatorKey("@Types/Node")).toBe("typesnode");
    expect(separatorKey("lodash.merge")).toBe("lodashmerge");
    expect(separatorKey("string_decoder")).toBe(separatorKey("string-decoder"));
  });

  test("names of 5 characters or fewer allow distance 1, longer ones 2", () => {
    expect(maxDistanceFor("react")).toBe(1);
    expect(maxDistanceFor("lodash")).toBe(2);
  });
});

describe("createPopularIndex", () => {
  const index = createPopularIndex([
    { name: "lodash", weeklyDownloads: 90_000_000 },
    { name: "react", weeklyDownloads: 50_000_000 },
    { name: "express", weeklyDownloads: 40_000_000 },
    { name: "@types/node", weeklyDownloads: 150_000_000 },
    { name: "@babel/core", weeklyDownloads: 60_000_000 },
    { name: "string_decoder", weeklyDownloads: 100_000_000 },
    { name: "qs", weeklyDownloads: 80_000_000 },
    { name: "axios", weeklyDownloads: 70_000_000 },
    { name: "lodash", weeklyDownloads: 1 }, // duplicate: ignored
  ]);
  const names = (n: string): string[] => index.similar(n).map((s) => s.name);

  test("size and downloads lookups (case-insensitive)", () => {
    expect(index.size).toBe(8);
    expect(index.downloads("lodash")).toBe(90_000_000);
    expect(index.downloads("LODASH")).toBe(90_000_000);
    expect(index.downloads("left-pad")).toBeUndefined();
  });

  test.each([
    ["lodahs", "lodash", "edit-distance", 1], // swapped letters count as one edit
    ["lodash-", "lodash", "separator", 1],
    ["expresss", "express", "edit-distance", 1],
    ["raect", "react", "edit-distance", 1], // swap in a short name
    ["axois", "axios", "edit-distance", 1],
    ["rakt", undefined, undefined, undefined], // distance 2, but react is short: limit 1
    ["reactt", "react", "edit-distance", 1],
    ["string-decoder", "string_decoder", "separator", 1],
    ["types-node", "@types/node", "scope", 2],
    ["@typess/node", "@types/node", "edit-distance", 1],
    ["babel-core", "@babel/core", "scope", 2],
    ["ms", "qs", "edit-distance", 1],
    ["left-pad", undefined, undefined, undefined],
  ])("%s → %s", (name, target, kind, distance) => {
    const top = index.similar(name)[0];
    if (target === undefined) {
      expect(top).toBeUndefined();
    } else {
      expect(top).toMatchObject({ name: target, kind, distance });
    }
  });

  test("an exact listed name is not similar to itself", () => {
    expect(names("lodash")).toEqual([]);
    expect(names("LoDash")).toEqual([]);
  });

  test("names in the same scope never match: only the scope owner can publish there", () => {
    expect(names("@types/nodes")).toEqual([]);
    expect(names("@babel/cores")).toEqual([]);
  });

  test("results are sorted by distance, then downloads", () => {
    const multi = createPopularIndex([
      { name: "abcdefg", weeklyDownloads: 10 },
      { name: "abcdefx", weeklyDownloads: 20 },
      { name: "abcdexy", weeklyDownloads: 30 },
    ]);
    expect(multi.similar("abcdefz").map((s) => [s.name, s.distance])).toEqual([
      ["abcdefx", 1],
      ["abcdefg", 1],
      ["abcdexy", 2],
    ]);
  });

  test("scanning the real 10,000-name list is fast (best of 5, robust to CI noise)", async () => {
    // Measured at ~0.5 ms per call; the budget leaves 40× headroom for loaded CI runners.
    const { popular } = await loadGateData();
    let best = Number.POSITIVE_INFINITY;
    for (let i = 0; i < 5; i++) {
      const start = performance.now();
      popular.similar("some-long-package-nmae");
      popular.similar("expres");
      best = Math.min(best, performance.now() - start);
    }
    expect(best).toBeLessThan(20);
  });
});

import { describe, expect, test } from "vitest";
import { createPopularIndex, levenshtein, loadGateData } from "../src/index.ts";
import { maxDistanceFor, separatorKey } from "../src/registry/typosquat.ts";

describe("levenshtein", () => {
  test.each([
    ["", "", 0],
    ["a", "", 1],
    ["", "abc", 3],
    ["kitten", "sitting", 3],
    ["lodash", "lodahs", 2],
    ["lodash", "lodash", 0],
    ["react", "raect", 2],
    ["express", "expres", 1],
    ["@types/node", "@types/nodes", 1],
    ["flaw", "lawn", 2],
  ])("%j vs %j = %i", (a, b, d) => {
    expect(levenshtein(a, b)).toBe(d);
    expect(levenshtein(b, a)).toBe(d);
  });

  test("stops early at max and reports max + 1", () => {
    expect(levenshtein("kitten", "sitting", 1)).toBe(2);
    expect(levenshtein("abc", "abcdefgh", 2)).toBe(3);
    expect(levenshtein("abcdef", "uvwxyz", 2)).toBe(3);
    expect(levenshtein("lodash", "lodahs", 2)).toBe(2);
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
    { name: "lodash", weeklyDownloads: 1 }, // duplicate: ignored
  ]);
  const names = (n: string): string[] => index.similar(n).map((s) => s.name);

  test("size and downloads lookups (case-insensitive)", () => {
    expect(index.size).toBe(7);
    expect(index.downloads("lodash")).toBe(90_000_000);
    expect(index.downloads("LODASH")).toBe(90_000_000);
    expect(index.downloads("left-pad")).toBeUndefined();
  });

  test.each([
    ["lodahs", "lodash", "edit-distance", 2],
    ["lodash-", "lodash", "separator", 1],
    ["expresss", "express", "edit-distance", 1],
    ["raect", undefined, undefined, undefined], // distance 2, but react is short: limit 1
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

// Validates the checked-in data files (data/*.json). See ADR 0003 and CONTRIBUTING.md.

import { readFileSync } from "node:fs";
import { assertPackageName } from "@depward/core";
import { describe, expect, test } from "vitest";

const read = (file: string): unknown => JSON.parse(readFileSync(new URL(`../../../data/${file}`, import.meta.url), "utf8"));

interface Popular {
  schemaVersion: number;
  snapshot: string;
  week: { start: string; end: string };
  license: string;
  source: string;
  packages: { name: string; weeklyDownloads: number }[];
}
interface Hallucinated {
  schemaVersion: number;
  entries: { name: string; ecosystem: string; firstSeen: string; source: string; suggestion: string }[];
}

const popular = read("popular-packages.json") as Popular;
const hallucinated = read("hallucinated-names.json") as Hallucinated;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

describe("data/popular-packages.json", () => {
  test("has a header with snapshot date, week, and source", () => {
    expect(popular.schemaVersion).toBe(1);
    expect(popular.snapshot).toMatch(DATE);
    expect(popular.week.start).toMatch(DATE);
    expect(popular.week.end).toMatch(DATE);
    expect(popular.source).toContain("ecosyste.ms");
    expect(popular.license).toBe("CC-BY-SA-4.0");
  });

  test("has about 10,000 packages", () => {
    expect(popular.packages.length).toBeGreaterThanOrEqual(9000);
    expect(popular.packages.length).toBeLessThanOrEqual(10_000);
  });

  test("entries are valid, unique, and sorted by downloads", () => {
    const seen = new Set<string>();
    let previous = Number.POSITIVE_INFINITY;
    for (const p of popular.packages) {
      expect(Object.keys(p)).toEqual(["name", "weeklyDownloads"]);
      expect(() => assertPackageName(p.name), p.name).not.toThrow();
      expect(seen.has(p.name), p.name).toBe(false);
      seen.add(p.name);
      expect(Number.isSafeInteger(p.weeklyDownloads) && p.weeklyDownloads > 0, p.name).toBe(true);
      expect(p.weeklyDownloads, p.name).toBeLessThanOrEqual(previous);
      previous = p.weeklyDownloads;
    }
  });

  test("includes well-known packages", () => {
    const names = new Set(popular.packages.map((p) => p.name));
    for (const name of ["react", "lodash", "express", "typescript", "@types/node", "semver"]) expect(names).toContain(name);
  });
});

describe("data/hallucinated-names.json", () => {
  const popularNames = new Set(popular.packages.map((p) => p.name));

  test("has the documented shape", () => {
    expect(hallucinated.schemaVersion).toBe(1);
    expect(hallucinated.entries.length).toBeGreaterThan(0);
    for (const e of hallucinated.entries) {
      expect(Object.keys(e).toSorted()).toEqual(["ecosystem", "firstSeen", "name", "source", "suggestion"]);
      expect(e.ecosystem).toBe("npm");
      expect(e.firstSeen).toMatch(DATE);
      expect(new URL(e.source).protocol).toBe("https:");
      expect(() => assertPackageName(e.name)).not.toThrow();
      expect(() => assertPackageName(e.suggestion)).not.toThrow();
      expect(e.suggestion).not.toBe(e.name);
    }
  });

  test("is sorted by name, without duplicates", () => {
    const names = hallucinated.entries.map((e) => e.name);
    expect(names).toEqual([...new Set(names)].toSorted());
  });

  test("no entry is a popular package", () => {
    for (const e of hallucinated.entries) expect(popularNames.has(e.name), e.name).toBe(false);
  });
});

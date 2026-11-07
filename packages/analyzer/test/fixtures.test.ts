// Runs every fixture in packages/analyzer/fixtures/<case>/: packs package/ into a tarball
// in memory, reads it back with the real tar reader, analyzes it, and compares the result
// with expected.json. Signal and capability lists are exact, so near-miss negatives are
// checked by omission.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { compareSeverity, readTarball, type Severity } from "@depward/core";
import { packTarball, type PackEntry } from "@depward/core/testing";
import { describe, expect, test } from "vitest";
import { analyzePackage, CAPABILITIES, type AnalyzeOptions, type FileSummary, type PackageProfile } from "../src/index.ts";

interface Expected {
  description: string;
  signals: string[];
  capabilities: string[];
  envKeys?: string[];
  endpoints?: string[];
  scripts?: Record<string, string>;
  files?: Record<string, Partial<FileSummary>>;
  stats?: Partial<PackageProfile["stats"]>;
  signalCounts?: Record<string, number>;
  severityAtLeast?: Severity;
  options?: AnalyzeOptions;
}

const ROOT = new URL("../fixtures/", import.meta.url);
const cases = readdirSync(ROOT).filter((d) => statSync(new URL(d, ROOT)).isDirectory()).toSorted();

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

/** Packs and analyzes a fixture through the real tarball path. */
export function analyzeFixture(name: string, options?: AnalyzeOptions): PackageProfile {
  const dir = new URL(`${name}/package/`, ROOT).pathname.replace(/^\/([A-Za-z]:)/, "$1");
  const entries: PackEntry[] = walk(dir).map((p) => ({ path: relative(dir, p).replaceAll("\\", "/"), data: readFileSync(p) }));
  return analyzePackage(readTarball(packTarball(entries)), options);
}

test("there are at least 30 synthetic fixtures", () => {
  expect(cases.length).toBeGreaterThanOrEqual(30);
});

describe.each(cases)("fixture %s", (name) => {
  const expected = JSON.parse(readFileSync(new URL(`${name}/expected.json`, ROOT), "utf8")) as Expected;
  const profile = analyzeFixture(name, expected.options);

  test(expected.description, () => {
    expect([...new Set(profile.signals.map((s) => s.id))].toSorted()).toEqual(expected.signals.toSorted());
    expect(CAPABILITIES.filter((c) => profile.capabilities[c].length > 0)).toEqual(
      CAPABILITIES.filter((c) => expected.capabilities.includes(c)),
    );
    expect(expected.capabilities.every((c) => (CAPABILITIES as readonly string[]).includes(c))).toBe(true);
    if (expected.envKeys) expect(profile.envKeys).toEqual(expected.envKeys);
    if (expected.endpoints) expect(profile.endpoints).toEqual(expected.endpoints);
    if (expected.scripts) expect(profile.scripts).toMatchObject(expected.scripts);
    if (expected.stats) expect(profile.stats).toMatchObject(expected.stats);
    for (const [path, want] of Object.entries(expected.files ?? {})) {
      expect(profile.files.find((f) => f.path === path), path).toMatchObject(want);
    }
    for (const [id, n] of Object.entries(expected.signalCounts ?? {})) {
      expect(profile.signals.filter((s) => s.id === id)).toHaveLength(n);
    }
    if (expected.severityAtLeast) {
      const worst = profile.signals[0]?.severity ?? "info";
      expect(compareSeverity(worst, expected.severityAtLeast)).toBeLessThanOrEqual(0);
    }
  });

  test("is deterministic", () => {
    expect(JSON.stringify(analyzeFixture(name, expected.options))).toBe(JSON.stringify(profile));
  });
});

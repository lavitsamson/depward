// Runs every pair in packages/diff/fixtures/<case>/: packs a/ and b/ into tarballs in
// memory, analyzes both through the real tar reader, diffs them, and compares the
// findings with expected.json. The finding list is exact, so negatives are checked by
// omission. Spec: docs/specs/diff.md § Tests; roadmap Phase 3 definition of done.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzePackage, type PackageProfile } from "@depward/analyzer";
import { compareSeverity, readTarball, type Severity, type VersionMeta } from "@depward/core";
import { packTarball } from "@depward/core/testing";
import { describe, expect, test } from "vitest";
import { diffPackages } from "../src/index.ts";

interface Expected {
  description: string;
  risk: Severity;
  /** `id:severity`, sorted. */
  findings: string[];
}

const ROOT = fileURLToPath(new URL("../fixtures/", import.meta.url));
const cases = readdirSync(ROOT).filter((d) => statSync(join(ROOT, d)).isDirectory()).toSorted();

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

function side(dir: string): { profile: PackageProfile; meta: VersionMeta } {
  const entries = walk(dir).map((p) => ({ path: relative(dir, p).replaceAll("\\", "/"), data: readFileSync(p) }));
  const profile = analyzePackage(readTarball(packTarball(entries)));
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { name: string; version: string; dependencies?: Record<string, string> };
  const meta: VersionMeta = {
    name: pkg.name,
    version: pkg.version,
    dist: { tarball: `https://registry.example.invalid/${pkg.name}/-/${pkg.name}-${pkg.version}.tgz` },
    ...(pkg.dependencies ? { dependencies: pkg.dependencies } : {}),
    _npmUser: { name: "maintainer" },
  };
  return { profile, meta };
}

test("the three documented attack patterns have replay pairs", () => {
  expect(cases).toEqual(expect.arrayContaining(["replay-postinstall-dropper", "replay-token-stealer", "replay-obfuscated-patch"]));
});

describe.each(cases)("pair %s", (name) => {
  const expected = JSON.parse(readFileSync(join(ROOT, name, "expected.json"), "utf8")) as Expected;
  const a = side(join(ROOT, name, "a"));
  const b = side(join(ROOT, name, "b"));
  const diff = diffPackages(a.profile, b.profile, a.meta, b.meta);

  test(expected.description, () => {
    expect(diff.findings.map((f) => `${f.id}:${f.severity}`).toSorted()).toEqual(expected.findings);
    expect(diff.risk).toBe(expected.risk);
  });

  if (name.startsWith("replay-")) {
    test("is flagged high or above", () => {
      expect(compareSeverity(diff.risk, "high")).toBeLessThanOrEqual(0);
    });
  }

  test("is deterministic", () => {
    expect(JSON.stringify(diffPackages(a.profile, b.profile, a.meta, b.meta))).toBe(JSON.stringify(diff));
  });
});

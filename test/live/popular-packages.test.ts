// Opt-in: Phase 1 definition of done (docs/ROADMAP.md). Downloads 20 popular packages
// from the real npm registry (integrity-checked, in memory, never executed) and checks
// the analyzer's medium-and-above signals against the reviewed baseline below.
// Review notes: docs/benchmarks.md § Phase 1. Run with `pnpm test:live`.
//
// If a package's result changes, re-review it and update REVIEWED (and the doc).
// A `critical` may only appear here with a written justification.

import { describe, expect, test } from "vitest";
import { compareSeverity, createMemoryCache, createRegistryClient, npmConfigFrom, readTarball } from "../../packages/core/src/index.ts";
import { analyzePackage } from "../../packages/analyzer/src/index.ts";

const client = createRegistryClient({ cache: createMemoryCache(), npmConfig: npmConfigFrom(), timeoutMs: 60_000 });

/** `name@version` → reviewed `severity:id` set for signals of medium severity or higher. */
const REVIEWED: Record<string, string[]> = {
  "lodash@4.18.1": [],
  "react@19.3.1": [],
  "express@5.3.0": [],
  "axios@1.21.0": [],
  "chalk@6.0.1": [],
  "commander@15.1.0": [],
  // Object.keys(process.env) to collect DEBUG_* options.
  "debug@4.4.3": ["high:env-sensitive-read"],
  "semver@7.8.6": [],
  "typescript@7.0.2": [],
  // postinstall may download the platform binary; it copies process.env for a child npm.
  "esbuild@0.28.2": ["high:env-sensitive-read", "high:install-script-network", "medium:install-script"],
  // Copies process.env for a child process (libvips build).
  "sharp@0.35.5": ["high:env-sensitive-read"],
  // DotenvPlugin copies and lists process.env to expand .env files.
  "webpack@5.112.2": ["high:env-sensitive-read"],
  "ws@8.22.1": [],
  "uuid@14.0.3": [],
  // Minified; merges parsed .env values with process.env.
  "dotenv@18.0.9": ["high:env-sensitive-read"],
  "yargs@18.2.0": [],
  "node-fetch@3.3.2": [],
  "supports-color@11.0.0": [],
  "cross-spawn@7.0.6": [],
  "ci-info@4.4.0": [],
};

/** Reviewed criticals: none. Add `name@version` with a justification only if clearly correct. */
const REVIEWED_CRITICAL = new Set<string>();

describe("analyzer on popular packages (Phase 1 DoD)", () => {
  test("covers 20 packages", () => {
    expect(Object.keys(REVIEWED)).toHaveLength(20);
  });

  test.each(Object.entries(REVIEWED))("%s", async (spec, reviewed) => {
    const at = spec.lastIndexOf("@");
    const meta = await client.versionMeta(spec.slice(0, at), spec.slice(at + 1));
    expect(meta, `${spec} exists`).not.toBeNull();
    const files = readTarball(await client.tarball(meta!));

    const start = performance.now();
    const profile = analyzePackage(files);
    const ms = performance.now() - start;

    const notable = [...new Set(profile.signals.filter((s) => compareSeverity(s.severity, "medium") <= 0).map((s) => `${s.severity}:${s.id}`))].toSorted();
    expect(notable).toEqual(reviewed.toSorted());
    if (!REVIEWED_CRITICAL.has(spec)) expect(profile.signals.filter((s) => s.severity === "critical")).toEqual([]);
    expect(profile.stats.unparsed).toBe(0);
    // ~300 ms per MB target (ROADMAP M1.4); generous bound for slow machines.
    expect(ms).toBeLessThan(2_000 + (files.unpackedSize / 1e6) * 1_000);
  });
});

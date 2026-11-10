// Opt-in: M2.2 registry checks against the real npm registry (metadata only; nothing is
// downloaded or run). Run with `pnpm test:live`. Assertions avoid anything that changes
// week to week (exact download counts, the newest version of fast-moving packages).

import { describe, expect, test } from "vitest";
import { createMemoryCache, createRegistryClient, npmConfigFrom } from "../../packages/core/src/index.ts";
import { checkRegistry } from "../../packages/gate/src/index.ts";

const registry = createRegistryClient({ cache: createMemoryCache(), npmConfig: npmConfigFrom(), timeoutMs: 60_000 });
const check = (name: string, range = "latest") => checkRegistry({ name, range }, { registry });
const ids = (r: { findings: { id: string }[] }): string[] => r.findings.map((f) => f.id);

describe("live registry checks", () => {
  test("a documented hallucinated name is flagged and the real package suggested", async () => {
    const r = await check("react-codeshift");
    expect(r.errors).toEqual([]);
    expect(ids(r)).toContain("known-hallucinated-name");
    expect(r.suggestion.name).toBe("jscodeshift");
  });

  test("a name that was never registered is not found", async () => {
    const r = await check("depward-live-test-no-such-package-0d9f3");
    expect(r.errors).toEqual([]);
    expect(ids(r)).toEqual(["package-not-found"]);
  });

  test("a well-known typo of lodash is a typosquat suspect", async () => {
    const r = await check("lodahs");
    expect(ids(r)).toContain("typosquat-suspect");
    expect(r.suggestion.name).toBe("lodash");
  });

  test.each([
    ["lodash", "4.17.21"],
    ["express", "4.21.1"],
    ["react", "18.3.1"],
    ["@types/node", "22.15.3"],
    // First release by microsoft1es, a maintainer listed for months before: established.
    ["typescript", "7.0.2"],
    // Stable line never had provenance; only its 8.0 alphas did. Not a drop.
    ["rxjs", "7.8.2"],
  ])("an old release of %s@%s has no findings", async (name, version) => {
    const r = await check(name, version);
    expect(r.errors).toEqual([]);
    expect(r.version).toBe(version);
    expect(r.findings).toEqual([]);
  });

  // Reviewed 2026-11-10 and kept on purpose: express@4.21.2 (Dec 2024) was the first
  // release by jonchurch, who was not a listed maintainer before it. That is a real
  // publisher change; it was legitimate, but it is exactly what the check is for.
  test("known publisher-changed case: express@4.21.2", async () => {
    expect(ids(await check("express", "4.21.2"))).toEqual(["publisher-changed"]);
  });

  test("a swapped-letter typo of axios points to axios", async () => {
    // Whether or not someone registered `axois`, the result names the real package.
    const r = await check("axois");
    expect(ids(r).some((id) => id === "typosquat-suspect" || id === "package-not-found")).toBe(true);
    expect(r.suggestion.name).toBe("axios");
  });

  test("a missing version is reported", async () => {
    expect(ids(await check("lodash", "^99"))).toEqual(["version-not-found"]);
  });
});

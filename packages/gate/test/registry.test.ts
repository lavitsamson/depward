// Registry checks against recorded fixtures (fixtures/registry/). Offline.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DepwardError, type RegistryClient } from "@depward/core";
import { createFixtureRegistryClient } from "@depward/core/testing";
import { describe, expect, test } from "vitest";
import { checkRegistry, createGateData, loadGateData, type RegistryCheckOptions } from "../src/index.ts";

const FIXTURES = fileURLToPath(new URL("../../../fixtures/registry", import.meta.url));
const NOW = Date.parse("2026-11-10T12:00:00.000Z");

const data = createGateData(
  [
    { name: "depward-fixture-stable", weeklyDownloads: 1_234_567 },
    { name: "depward-fixture-takeover", weeklyDownloads: 250_000 },
  ],
  [
    {
      name: "depward-fixture-hallucinated",
      ecosystem: "npm",
      firstSeen: "2025-01-01",
      source: "https://example.invalid/report",
      suggestion: "depward-fixture-stable",
    },
    {
      name: "depward-fixture-fresh",
      ecosystem: "npm",
      firstSeen: "2026-11-01",
      source: "https://example.invalid/report-2",
      suggestion: "depward-fixture-stable",
    },
    {
      name: "depward-fixture-other-ecosystem",
      ecosystem: "pypi",
      firstSeen: "2025-01-01",
      source: "https://example.invalid/report-3",
      suggestion: "depward-fixture-stable",
    },
  ],
);

function opts(extra: Partial<RegistryCheckOptions> = {}): RegistryCheckOptions {
  return { registry: createFixtureRegistryClient(FIXTURES), data, now: () => NOW, ...extra };
}

async function check(name: string, range = "latest", extra: Partial<RegistryCheckOptions> = {}) {
  return checkRegistry({ name, range }, opts(extra));
}

const ids = (r: { findings: { id: string }[] }): string[] => r.findings.map((f) => f.id).toSorted();

describe("checkRegistry: a stable, popular package (negative case for every check)", () => {
  test("latest has no findings", async () => {
    const r = await check("depward-fixture-stable");
    expect(r.findings).toEqual([]);
    expect(r.errors).toEqual([]);
    expect(r.version).toBe("2.0.0");
    expect(r.meta?.version).toBe("2.0.0");
    expect(r.weeklyDownloads).toBe(1_234_567);
    expect(r.suggestion).toEqual({});
  });

  test("resolves ranges and tags", async () => {
    expect((await check("depward-fixture-stable", "^1.0.0")).version).toBe("1.1.0");
    expect((await check("depward-fixture-stable", "legacy")).version).toBe("1.1.0");
    // 1.1.0 lacks attestations, but no earlier version had them: not a drop.
    expect(ids(await check("depward-fixture-stable", "1.1.0"))).toEqual([]);
  });
});

describe("package-not-found", () => {
  test("a missing package is reported, with a suggestion when one is close", async () => {
    const r = await check("depward-fixture-stabl");
    expect(ids(r)).toEqual(["package-not-found"]);
    const [f] = r.findings;
    expect(f).toMatchObject({ severity: "high", package: "depward-fixture-stabl" });
    expect(f?.version).toBeUndefined();
    expect(f?.message).toContain("may be a typo or a name an AI model made up");
    expect(f?.message).toContain("Did you mean depward-fixture-stable?");
    expect(f?.docsUrl).toMatch(/findings\.md#package-not-found$/);
    expect(r.suggestion).toEqual({ name: "depward-fixture-stable" });
    expect(r.version).toBeNull();
  });

  test("no suggestion when nothing is close", async () => {
    const r = await check("depward-fixture-zzzzzzzzzz");
    expect(ids(r)).toEqual(["package-not-found"]);
    expect(r.findings[0]?.message).not.toContain("Did you mean");
    expect(r.suggestion).toEqual({});
  });
});

describe("known-hallucinated-name", () => {
  test("a listed name that doesn't exist: hallucinated + not found", async () => {
    const r = await check("depward-fixture-hallucinated");
    expect(ids(r)).toEqual(["known-hallucinated-name", "package-not-found"]);
    expect(r.findings[0]).toMatchObject({ id: "known-hallucinated-name", severity: "critical" });
    expect(r.findings[0]?.message).toContain("Did you mean depward-fixture-stable?");
    expect(r.findings[0]?.evidence[0]?.detail).toContain("https://example.invalid/report");
    expect(r.suggestion.name).toBe("depward-fixture-stable");
  });

  test("a listed name is flagged even after someone registers it", async () => {
    const r = await check("depward-fixture-fresh");
    expect(ids(r)).toContain("known-hallucinated-name");
  });

  test("matching ignores case; other ecosystems are ignored", async () => {
    expect(ids(await check("Depward-Fixture-Hallucinated"))).toContain("known-hallucinated-name");
    expect(ids(await check("depward-fixture-other-ecosystem"))).toEqual(["package-not-found"]);
  });

  test("not flagged for unlisted names", async () => {
    expect(ids(await check("depward-fixture-stable"))).not.toContain("known-hallucinated-name");
  });
});

describe("version-not-found", () => {
  test.each(["^9", "9.9.9", "no-such-tag"])("%s", async (range) => {
    const r = await check("depward-fixture-stable", range);
    expect(ids(r)).toEqual(["version-not-found"]);
    expect(r.findings[0]?.severity).toBe("high");
    expect(r.findings[0]?.evidence[0]?.detail).toBe("dist-tags: latest: 2.0.0, legacy: 1.1.0");
    expect(r.version).toBeNull();
  });
});

describe("a 2-day-old package with almost no downloads", () => {
  test("version-too-new, package-too-new, and low-downloads", async () => {
    const r = await check("depward-fixture-fresh", "latest", { data: createGateData([], []) });
    expect(ids(r)).toEqual(["low-downloads", "package-too-new", "version-too-new"]);
    const byId = Object.fromEntries(r.findings.map((f) => [f.id, f]));
    expect(byId["package-too-new"]?.message).toBe(
      "depward-fixture-fresh was first published 2 days ago (minimum 30 days).",
    );
    expect(byId["low-downloads"]?.message).toBe(
      "depward-fixture-fresh has 3 downloads in the last week (minimum 500).",
    );
    // No version is old enough, so there is nothing to suggest.
    expect(byId["version-too-new"]?.message).not.toContain("instead");
    expect(r.suggestion).toEqual({});
  });

  test("thresholds are configurable", async () => {
    const r = await check("depward-fixture-fresh", "latest", {
      data: createGateData([], []),
      minVersionAgeDays: 1,
      minPackageAgeDays: 1,
      minWeeklyDownloads: 3,
    });
    expect(r.findings).toEqual([]);
  });
});

describe("a maintainer takeover (depward-fixture-takeover@1.1.0)", () => {
  test("flags the new version on every history check", async () => {
    const r = await check("depward-fixture-takeover", "^1.0.0");
    expect(r.version).toBe("1.1.0");
    expect(ids(r)).toEqual(["maintainer-added-recently", "provenance-dropped", "publisher-changed", "version-too-new"]);
    const byId = Object.fromEntries(r.findings.map((f) => [f.id, f]));
    expect(byId["provenance-dropped"]).toMatchObject({ severity: "high", version: "1.1.0" });
    expect(byId["provenance-dropped"]?.message).toContain("but 1.0.5 did");
    expect(byId["publisher-changed"]?.message).toContain("published by fixture-mallory");
    expect(byId["publisher-changed"]?.evidence[0]?.detail).toBe("previous publishers: fixture-alice");
    expect(byId["maintainer-added-recently"]).toMatchObject({ severity: "low" });
    expect(byId["maintainer-added-recently"]?.version).toBeUndefined();
    expect(byId["maintainer-added-recently"]?.evidence[0]?.detail).toBe("fixture-mallory first listed on 1.1.0");
    expect(byId["version-too-new"]?.message).toBe(
      "depward-fixture-takeover@1.1.0 was published 3 days ago (minimum 7 days). Use depward-fixture-takeover@1.0.5 instead.",
    );
    expect(r.suggestion).toEqual({ version: "1.0.5" });
  });

  test("an older suggestion outside the requested range is labelled", async () => {
    const r = await check("depward-fixture-takeover", "1.1.0");
    expect(r.suggestion).toEqual({ version: "1.0.5" });
    expect(r.findings.find((f) => f.id === "version-too-new")?.message).toContain("(outside the requested range)");
  });

  test("for a dist-tag, the older suggestion is not labelled as outside a range", async () => {
    const r = await check("depward-fixture-takeover", "latest");
    expect(r.suggestion).toEqual({ version: "1.0.5" });
    expect(r.findings.find((f) => f.id === "version-too-new")?.message).toBe(
      "depward-fixture-takeover@1.1.0 was published 3 days ago (minimum 7 days). Use depward-fixture-takeover@1.0.5 instead.",
    );
  });

  test("older versions pass the version-level checks", async () => {
    const r = await check("depward-fixture-takeover", "1.0.5");
    // The maintainer change is about the package, so it is still reported.
    expect(ids(r)).toEqual(["maintainer-added-recently"]);
  });

  test("the maintainer check only looks back the configured window", async () => {
    const r = await check("depward-fixture-takeover", "1.0.5", { maintainerWindowDays: 2 });
    expect(ids(r)).toEqual([]);
  });

  test("findings are sorted by severity, then package, then id", async () => {
    const r = await check("depward-fixture-takeover", "^1.0.0");
    expect(r.findings.map((f) => f.severity)).toEqual(["high", "medium", "medium", "low"]);
  });
});

describe("deprecated", () => {
  test("a deprecated version carries its (escaped) message", async () => {
    const r = await check("depward-fixture-takeover", "1.0.2");
    expect(ids(r)).toEqual(["deprecated", "maintainer-added-recently"]);
    const f = r.findings.find((x) => x.id === "deprecated");
    expect(f).toMatchObject({ severity: "low", version: "1.0.2", message: "depward-fixture-takeover@1.0.2 is deprecated." });
    expect(f?.evidence[0]?.detail).toBe("Critical bug in 1.0.2, use 1.0.3");
  });

  test("the resolver avoids deprecated versions when a range allows others", async () => {
    expect((await check("depward-fixture-takeover", "~1.0.2 <1.0.3")).version).toBe("1.0.2");
    expect((await check("depward-fixture-stable", "1.0.0")).findings.map((f) => f.id)).toEqual(["deprecated"]);
  });
});

describe("typosquat-suspect", () => {
  test("a name close to a much more popular package", async () => {
    const r = await check("depward-fixture-stabel");
    expect(ids(r)).toEqual(["low-downloads", "typosquat-suspect"]);
    const f = r.findings.find((x) => x.id === "typosquat-suspect");
    expect(f?.severity).toBe("high");
    expect(f?.message).toBe(
      "depward-fixture-stabel is 1 character away from the popular package depward-fixture-stable, which has far more downloads. Did you mean depward-fixture-stable?",
    );
    expect(f?.evidence[0]?.detail).toBe("depward-fixture-stable: 1234567 weekly downloads (edit-distance, distance 1)");
    expect(r.suggestion).toEqual({ name: "depward-fixture-stable" });
  });

  test("not flagged when the popular package isn't much more popular", async () => {
    const r = await check("depward-fixture-stabel", "latest", { typosquatRatio: 1_000_000 });
    expect(ids(r)).toEqual(["low-downloads"]);
  });

  test("not flagged for packages on the popular list themselves", async () => {
    // takeover is listed; its distance to other listed names doesn't matter.
    const r = await check("depward-fixture-takeover", "1.0.5", { maintainerWindowDays: 1 });
    expect(ids(r)).not.toContain("typosquat-suspect");
  });
});

function failing(code: "NETWORK" | "TIMEOUT"): RegistryClient {
  return {
    packument: () => Promise.reject(new DepwardError(code, "registry down")),
    versionMeta: () => Promise.reject(new DepwardError(code, "registry down")),
    weeklyDownloads: () => Promise.reject(new DepwardError(code, "downloads down")),
    attestations: () => Promise.resolve(null),
    tarball: () => Promise.reject(new DepwardError(code, "registry down")),
  };
}

describe("errors", () => {
  test("a failed packument lookup is returned, never thrown", async () => {
    const r = await check("depward-fixture-stable", "latest", { registry: failing("TIMEOUT") });
    expect(r.errors.map((e) => e.code)).toEqual(["TIMEOUT"]);
    expect(r.findings).toEqual([]);
    expect(r.version).toBeNull();
  });

  test("offline checks still run when the registry is down", async () => {
    const r = await check("depward-fixture-hallucinated", "latest", { registry: failing("NETWORK") });
    expect(ids(r)).toEqual(["known-hallucinated-name"]);
    expect(r.errors.map((e) => e.code)).toEqual(["NETWORK"]);
  });

  test("a failed downloads lookup keeps the other findings", async () => {
    const real = createFixtureRegistryClient(FIXTURES);
    const registry: RegistryClient = { ...real, weeklyDownloads: () => Promise.reject(new DepwardError("NETWORK", "down")) };
    const r = await check("depward-fixture-takeover", "^1.0.0", { registry });
    expect(r.errors.map((e) => e.code)).toEqual(["NETWORK"]);
    expect(r.weeklyDownloads).toBeNull();
    expect(ids(r)).toContain("provenance-dropped");
  });

  test("non-depward errors are wrapped as INTERNAL", async () => {
    const real = createFixtureRegistryClient(FIXTURES);
    const registry: RegistryClient = { ...real, packument: () => Promise.reject(new Error("boom")) };
    const r = await check("depward-fixture-stable", "latest", { registry });
    expect(r.errors[0]).toBeInstanceOf(DepwardError);
    expect(r.errors[0]?.code).toBe("INTERNAL");
  });

  test("an invalid name is an error, not a request", async () => {
    const r = await check("../-/whoami");
    expect(r.errors.map((e) => e.code)).toEqual(["INVALID_ARGUMENT"]);
  });
});

describe("finding catalog", () => {
  test("every registry finding ID has an entry in docs/findings.md", () => {
    const catalog = readFileSync(new URL("../../../docs/findings.md", import.meta.url), "utf8");
    const catalogIds = [
      "package-not-found", "known-hallucinated-name", "version-not-found", "version-too-new", "package-too-new",
      "low-downloads", "typosquat-suspect", "publisher-changed", "maintainer-added-recently", "provenance-dropped",
      "deprecated",
    ];
    for (const id of catalogIds) expect(catalog, id).toMatch(new RegExp(`^### ${id}\\r?$`, "m"));
  });
});

describe("bundled data", () => {
  test("loads the checked-in data files once", async () => {
    const a = await loadGateData();
    expect(a.popular.size).toBeGreaterThanOrEqual(9000);
    expect(a.popular.downloads("react")).toBeGreaterThan(0);
    expect(a.hallucinated.get("react-codeshift")?.suggestion).toBe("jscodeshift");
    expect(await loadGateData()).toBe(a);
  });

  test("is the default data set", async () => {
    const r = await checkRegistry({ name: "react-codeshift", range: "latest" }, {
      registry: createFixtureRegistryClient(FIXTURES),
      now: () => NOW,
    });
    expect(ids(r)).toEqual(["known-hallucinated-name", "package-not-found"]);
    expect(r.suggestion.name).toBe("jscodeshift");
  });
});

// checkSpecs / checkCommand end to end against recorded fixtures (fixtures/registry/).
// Offline; package code is never executed.

import { fileURLToPath } from "node:url";
import { DepwardError, createMemoryCache, parseConfig, type RegistryClient } from "@depward/core";
import { createFixtureRegistryClient } from "@depward/core/testing";
import { beforeAll, describe, expect, test } from "vitest";
import { checkCommand, checkSpecs, createGateData, createPolicy, preloadAnalyzer, type Decision, type GateOptions } from "../src/index.ts";

const FIXTURES = fileURLToPath(new URL("../../../fixtures/registry", import.meta.url));
const NOW = Date.parse("2026-11-10T12:00:00.000Z");
const data = createGateData(
  [
    { name: "depward-fixture-stable", weeklyDownloads: 1_234_567 },
    { name: "depward-fixture-takeover", weeklyDownloads: 250_000 },
  ],
  [{
    name: "depward-fixture-hallucinated",
    ecosystem: "npm",
    firstSeen: "2025-01-01",
    source: "https://example.invalid/report",
    suggestion: "depward-fixture-stable",
  }],
);

// The analyzer loads on first use; load it up front so its one-time transform isn't timed.
beforeAll(async () => {
  await preloadAnalyzer();
});

type Fixtures = ReturnType<typeof createFixtureRegistryClient>;
const fixtures = (): Fixtures => createFixtureRegistryClient(FIXTURES);
const tgzRequests = (r: Fixtures): number => r.requests.filter((q) => q.url.endsWith(".tgz")).length;

function opts(extra: Partial<Omit<GateOptions, "config">> & { config?: Record<string, unknown> } = {}): GateOptions {
  const { config, ...rest } = extra;
  return {
    registry: fixtures(), data, now: () => NOW,
    ...(config === undefined ? {} : { config: parseConfig(config, "depward.config.json") }),
    ...rest,
  };
}

const summary = (d: Decision) => ({
  action: d.action,
  packages: d.packages.map((p) => [`${p.name}@${p.version ?? p.range}`, p.action, p.findings.filter((x) => x.action !== "allow").map((x) => x.finding.id)]),
});

describe("checkCommand", () => {
  test("commands without a package install are allowed with no network access", async () => {
    const registry = fixtures();
    for (const cmd of ["ls -la", "git status && echo done", "npm run build", "npm ci", "pnpm install"]) {
      const d = await checkCommand(cmd, opts({ registry }));
      expect(d, cmd).toEqual({ action: "allow", packages: [], findings: [], reasons: [] });
    }
    expect(registry.requests).toEqual([]);
  });

  test("a popular, stable package is allowed after the tarball is analyzed", async () => {
    const d = await checkCommand("npm install depward-fixture-stable", opts());
    expect(summary(d)).toEqual({ action: "allow", packages: [["depward-fixture-stable@2.0.0", "allow", []]] });
    expect(d.packages[0]?.analyzed).toBe(true);
    expect(d.reasons).toEqual([]);
  });

  test("a known hallucinated name is denied, with the real name suggested", async () => {
    const registry = fixtures();
    const d = await checkCommand("npm i depward-fixture-hallucinated", opts({ registry }));
    expect(summary(d)).toEqual({
      action: "deny",
      packages: [["depward-fixture-hallucinated@latest", "deny", ["known-hallucinated-name", "package-not-found"]]],
    });
    expect(d.packages[0]?.suggestion.name).toBe("depward-fixture-stable");
    expect(d.reasons[0]).toMatch(/^deny depward-fixture-hallucinated@latest: known-hallucinated-name — /);
    expect(tgzRequests(registry)).toBe(0);
  });

  test("a package first published 2 days ago with few downloads is denied, without fetching its tarball", async () => {
    const registry = fixtures();
    const d = await checkCommand("pnpm add depward-fixture-fresh", opts({ registry }));
    expect(summary(d)).toEqual({
      action: "deny",
      packages: [["depward-fixture-fresh@1.0.0", "deny", ["low-downloads", "package-too-new", "version-too-new"]]],
    });
    expect(d.packages[0]?.findings.find((x) => x.finding.id === "package-too-new")?.source).toBe("escalation");
    expect(d.packages[0]?.analyzed).toBe(false);
    expect(tgzRequests(registry)).toBe(0);
  });

  test("the tarball can turn ask into deny: a token-stealing postinstall", async () => {
    const d = await checkCommand("npx depward-fixture-takeover", opts());
    expect(d.action).toBe("deny");
    const pkg = d.packages[0];
    expect(pkg?.analyzed).toBe(true);
    expect(pkg?.findings.filter((x) => x.action === "deny").map((x) => x.finding.id)).toEqual(["env-exfil-pattern"]);
    // env-sensitive-read is allowed on its own; the exfil flow is what denies.
    expect(pkg?.findings.find((x) => x.finding.id === "env-sensitive-read")?.action).toBe("allow");
    expect(d.reasons[0]).toMatch(/^deny depward-fixture-takeover@1\.1\.0: env-exfil-pattern — /);
  });

  test("an unsafe archive is denied", async () => {
    expect(summary(await checkCommand("yarn add depward-fixture-unsafe", opts()))).toEqual({
      action: "deny", packages: [["depward-fixture-unsafe@1.0.0", "deny", ["tarball-unsafe"]]],
    });
  });

  test("a typosquat asks", async () => {
    const d = await checkCommand("npm i depward-fixture-stabel", opts());
    expect(d.action).toBe("ask");
    expect(d.packages[0]?.suggestion.name).toBe("depward-fixture-stable");
  });

  test("the command takes its strictest package, and reasons list deny before ask", async () => {
    const d = await checkCommand("npm i depward-fixture-stable depward-fixture-stabel && npx depward-fixture-missing", opts());
    expect(summary(d)).toEqual({
      action: "deny",
      packages: [
        ["depward-fixture-stable@2.0.0", "allow", []],
        ["depward-fixture-stabel@2.0.1", "ask", ["typosquat-suspect", "low-downloads"]],
        ["depward-fixture-missing@latest", "deny", ["package-not-found"]],
      ],
    });
    // stabel has no tarball fixture: its 404 is the third ask (onError).
    expect(d.reasons.map((r) => r.replace(/ — .*/, ""))).toEqual([
      "deny depward-fixture-missing@latest: package-not-found",
      "ask depward-fixture-stabel@2.0.1: typosquat-suspect",
      "ask depward-fixture-stabel@2.0.1: low-downloads",
      "ask depward-fixture-stabel@2.0.1: lookup failed (NETWORK); onError is ask",
    ]);
  });

  test("the same package requested twice is checked once", async () => {
    const registry = fixtures();
    const d = await checkCommand("npm i depward-fixture-stable; npm i depward-fixture-stable", opts({ registry }));
    expect(d.packages).toHaveLength(1);
    expect(tgzRequests(registry)).toBe(1);
  });

  test("non-registry sources ask; workspace specs are allowed without lookups", async () => {
    const registry = fixtures();
    const d = await checkCommand("npm i github:example/repo && pnpm add my-lib@workspace:*", opts({ registry }));
    expect(summary(d)).toEqual({
      action: "ask",
      packages: [["github:example/repo@github:example/repo", "ask", ["non-registry-source"]], ["my-lib@my-lib@workspace:*", "allow", []]],
    });
    expect(registry.requests).toEqual([]);
  });

  test("an unparseable command asks, with a command-level finding", async () => {
    const d = await checkCommand('npm i "$PKG"', opts());
    expect(d.action).toBe("ask");
    expect(d.packages).toEqual([]);
    expect(d.findings.map((x) => [x.finding.id, x.action])).toEqual([["unparseable-command", "ask"]]);
    expect(d.reasons[0]).toMatch(/^ask unparseable-command — /);
  });

  test("a global install of a clean package is allowed (global-install is a note)", async () => {
    const d = await checkCommand("npm i -g depward-fixture-stable", opts());
    expect(d.action).toBe("allow");
    expect(d.packages[0]?.findings.map((x) => [x.finding.id, x.action])).toEqual([["global-install", "allow"]]);
  });
});

describe("config", () => {
  test("policy overrides apply", async () => {
    const d = await checkCommand("npm i github:example/repo", opts({ config: { policy: { "non-registry-source": "allow" } } }));
    expect(d.action).toBe("allow");
  });

  test("thresholds from the config reach the registry checks", async () => {
    // With every threshold at 0, the fresh package passes the registry stage, so its
    // (absent) tarball is fetched: the 404 is a lookup failure and costs onError.
    const registry = fixtures();
    const config = { thresholds: { minVersionAgeDays: 0, minPackageAgeDays: 0, minWeeklyDownloads: 0 } };
    const d = await checkCommand("npm i depward-fixture-fresh", opts({ registry, config }));
    expect(d.packages[0]?.findings).toEqual([]);
    expect(d.packages[0]?.errors.map((e) => e.code)).toEqual(["NETWORK"]);
    expect(d.action).toBe("ask");
    expect(d.reasons).toEqual(["ask depward-fixture-fresh@1.0.0: lookup failed (NETWORK); onError is ask"]);
    expect(tgzRequests(registry)).toBe(1);
  });

  test("an allow-listed package is allowed and its tarball is not fetched", async () => {
    const registry = fixtures();
    const d = await checkCommand("npm i depward-fixture-stabel", opts({ registry, config: { allow: ["depward-fixture-stab*"] } }));
    expect(d.action).toBe("allow");
    expect(d.packages[0]?.listed).toEqual({ list: "allow", entry: "depward-fixture-stab*" });
    expect(d.packages[0]?.findings.map((x) => x.finding.id)).toEqual(["typosquat-suspect", "low-downloads"]);
    expect(tgzRequests(registry)).toBe(0);
  });

  test("a scope glob on the allow list", async () => {
    const d = await checkCommand("npm i @depward-fixture/scoped", opts({ config: { allow: ["@depward-fixture/*"] } }));
    expect(d.action).toBe("allow");
  });

  test("a name on the deny list is denied without any registry request", async () => {
    const registry = fixtures();
    const d = await checkCommand("npm i depward-fixture-stable", opts({ registry, config: { deny: ["depward-fixture-stable"] } }));
    expect(summary(d)).toEqual({ action: "deny", packages: [["depward-fixture-stable@latest", "deny", ["denylisted"]]] });
    expect(registry.requests).toEqual([]);
  });

  test("an exact name@version on the deny list resolves the version, then skips the tarball", async () => {
    const registry = fixtures();
    const config = { deny: ["depward-fixture-stable@2.0.0"] };
    expect((await checkCommand("npm i depward-fixture-stable", opts({ registry, config }))).action).toBe("deny");
    expect(tgzRequests(registry)).toBe(0);
    expect((await checkCommand("npm i depward-fixture-stable@legacy", opts({ config }))).packages[0]?.version).toBe("1.1.0");
  });

  test("a precompiled policy can be reused", async () => {
    const policy = createPolicy(parseConfig({ deny: ["depward-fixture-*"] }, "x"));
    expect((await checkCommand("npm i depward-fixture-stable", opts({ policy }))).action).toBe("deny");
  });

  test("malformed list entries are INVALID_CONFIG", async () => {
    await expect(checkCommand("npm i x", opts({ config: { allow: ["x@^1"] } }))).rejects.toMatchObject({ code: "INVALID_CONFIG" });
  });
});

const failing = (code: "TIMEOUT" | "NETWORK"): RegistryClient => ({
  ...fixtures(),
  packument: () => Promise.reject(new DepwardError(code, "registry unreachable")),
  weeklyDownloads: () => Promise.reject(new DepwardError(code, "registry unreachable")),
});

describe("onError", () => {
  test("a timeout asks by default", async () => {
    const d = await checkCommand("npm i depward-fixture-stable", opts({ registry: failing("TIMEOUT") }));
    expect(d.action).toBe("ask");
    expect(d.packages[0]?.errorAction).toBe("ask");
    expect(d.reasons).toEqual(["ask depward-fixture-stable@latest: lookup failed (TIMEOUT); onError is ask"]);
  });

  test("onError: deny", async () => {
    const d = await checkCommand("npm i depward-fixture-stable", opts({ registry: failing("NETWORK"), config: { onError: "deny" } }));
    expect(d.action).toBe("deny");
  });

  test("a deny from data that needs no network survives a registry outage", async () => {
    const d = await checkCommand("npm i depward-fixture-hallucinated", opts({ registry: failing("NETWORK"), config: { onError: "allow" } }));
    expect(d.action).toBe("deny");
  });

  test("offline mode with an empty cache asks (OFFLINE), and never fetches", async () => {
    const fx = createFixtureRegistryClient(FIXTURES, { cache: createMemoryCache(), offline: true });
    const d = await checkCommand("npm i depward-fixture-stable", opts({ registry: fx }));
    expect(d.action).toBe("ask");
    expect(d.packages[0]?.errors.map((e) => e.code)).toContain("OFFLINE");
    expect(fx.requests).toEqual([]);
  });

  test("offline mode with a warm cache gives the online answer", async () => {
    const cache = createMemoryCache();
    const online = createFixtureRegistryClient(FIXTURES, { cache });
    expect((await checkCommand("npm i depward-fixture-stable", opts({ registry: online }))).action).toBe("allow");
    const offline = createFixtureRegistryClient(FIXTURES, { cache, offline: true });
    expect((await checkCommand("npm i depward-fixture-stable", opts({ registry: offline }))).action).toBe("allow");
    expect(offline.requests).toEqual([]);
  });
});

describe("checkSpecs", () => {
  test("checks specs as written for npm install", async () => {
    const d = await checkSpecs(["depward-fixture-stable@^2", "alias@npm:depward-fixture-missing@1", "./local-dir"], opts());
    expect(summary(d)).toEqual({
      action: "deny",
      packages: [
        ["depward-fixture-stable@2.0.0", "allow", []],
        ["depward-fixture-missing@1", "deny", ["package-not-found"]],
        ["./local-dir@./local-dir", "ask", ["non-registry-source"]],
      ],
    });
  });

  test("no specs: allow", async () => {
    expect((await checkSpecs([], opts())).action).toBe("allow");
  });

  test("an invalid spec is INVALID_ARGUMENT", async () => {
    await expect(checkSpecs(["Not A Name"], opts())).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });
});

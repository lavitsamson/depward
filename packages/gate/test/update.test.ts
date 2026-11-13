// The update path (M3.6) on the gate side: what the gate hands `diffUpdate`, when it
// calls it, and how its result reaches the decision. The callback here is a fake; the
// real one (diff's createUpdateDiff) is tested end to end in packages/diff.

import { fileURLToPath } from "node:url";
import { DepwardError, findingDocsUrl, parseConfig, type Finding, type Severity } from "@depward/core";
import { createFixtureRegistryClient } from "@depward/core/testing";
import { beforeAll, describe, expect, test } from "vitest";
import {
  checkSpecs,
  createGateData,
  preloadAnalyzer,
  serializeDecision,
  type GateOptions,
  type UpdateDiff,
  type UpdateRequest,
} from "../src/index.ts";

const FIXTURES = fileURLToPath(new URL("../../../fixtures/registry", import.meta.url));
const NOW = Date.parse("2026-11-10T12:00:00.000Z");
const data = createGateData(
  [
    { name: "depward-fixture-stable", weeklyDownloads: 1_234_567 },
    { name: "depward-fixture-takeover", weeklyDownloads: 250_000 },
  ],
  [{ name: "depward-fixture-hallucinated", ecosystem: "npm", firstSeen: "2025-01-01", source: "https://example.invalid/report", suggestion: "depward-fixture-stable" }],
);

beforeAll(async () => {
  await preloadAnalyzer();
});

function diff(id: string, severity: Severity, pkg = "depward-fixture-stable", version = "2.0.0"): Finding {
  return { id, severity, package: pkg, version, message: `${id} since 1.0.0`, evidence: [], docsUrl: findingDocsUrl(id) };
}

/** A fake callback that records its calls and answers with `findings` against 1.0.0. */
function fake(findings: Finding[] = [], errors: DepwardError[] = []): { diffUpdate: UpdateDiff; calls: UpdateRequest[] } {
  const calls: UpdateRequest[] = [];
  return {
    calls,
    diffUpdate: async (request) => {
      calls.push(request);
      return { from: "1.0.0", lockfile: "pnpm-lock.yaml", findings, errors };
    },
  };
}

function opts(diffUpdate: UpdateDiff, config: Record<string, unknown> = {}): GateOptions {
  return { registry: createFixtureRegistryClient(FIXTURES), data, now: () => NOW, diffUpdate, config: parseConfig(config, "depward.config.json") };
}

const actions = (d: Awaited<ReturnType<typeof checkSpecs>>) =>
  Object.fromEntries((d.packages[0]?.findings ?? []).map((x) => [x.finding.id, `${x.action}/${x.source}`]));

describe("the update path", () => {
  test("the callback gets the resolved version, its metadata, and the gate's own profile of it", async () => {
    const { diffUpdate, calls } = fake();
    const d = await checkSpecs(["depward-fixture-stable@^2"], opts(diffUpdate));
    expect(calls.map((c) => [c.name, c.version, c.meta.version])).toEqual([["depward-fixture-stable", "2.0.0", "2.0.0"]]);
    const profile = await calls[0]?.profile;
    expect(profile?.name).toBe("depward-fixture-stable");
    expect(profile?.version).toBe("2.0.0");
    expect(d.action).toBe("allow");
    expect(d.packages[0]?.update).toEqual({ from: "1.0.0", lockfile: "pnpm-lock.yaml" });
    expect(serializeDecision(d).packages[0]?.update).toEqual({ from: "1.0.0", lockfile: "pnpm-lock.yaml" });
  });

  test("a callback answering null means no update: the decision is as without it", async () => {
    const d = await checkSpecs(["depward-fixture-stable"], opts(async () => null));
    expect(d.action).toBe("allow");
    expect(d.packages[0]?.update).toBeNull();
  });

  test("one high diff finding asks; the update shows in the reason", async () => {
    const d = await checkSpecs(["depward-fixture-stable"], opts(fake([diff("diff-new-sensitive-env", "high")]).diffUpdate));
    expect(d.action).toBe("ask");
    expect(actions(d)).toEqual({ "diff-new-sensitive-env": "ask/default" });
    expect(d.reasons).toEqual([
      "ask depward-fixture-stable@2.0.0 (update from 1.0.0): diff-new-sensitive-env — diff-new-sensitive-env since 1.0.0",
    ]);
  });

  test("two high diff findings deny both (the diff's two-highs rule); medium ones don't count", async () => {
    const findings = [diff("diff-new-install-script", "high"), diff("diff-new-network-in-non-network-pkg", "high"), diff("diff-new-capability", "medium")];
    const d = await checkSpecs(["depward-fixture-stable"], opts(fake(findings).diffUpdate));
    expect(d.action).toBe("deny");
    expect(actions(d)).toEqual({
      "diff-new-install-script": "deny/escalation",
      "diff-new-network-in-non-network-pkg": "deny/escalation",
      "diff-new-capability": "ask/default",
    });
  });

  test("a config override beats the two-highs escalation", async () => {
    const findings = [diff("diff-new-install-script", "high"), diff("diff-new-network-in-non-network-pkg", "high")];
    const d = await checkSpecs(["depward-fixture-stable"], opts(fake(findings).diffUpdate, { policy: { "diff-new-install-script": "allow" } }));
    expect(actions(d)).toEqual({ "diff-new-install-script": "allow/config", "diff-new-network-in-non-network-pkg": "deny/escalation" });
  });

  test("new obfuscation is critical, so it denies on its own", async () => {
    const d = await checkSpecs(["depward-fixture-stable"], opts(fake([diff("diff-new-obfuscation", "critical")]).diffUpdate));
    expect(d.action).toBe("deny");
  });

  test("diff copies of registry findings are dropped", async () => {
    // depward-fixture-takeover@1.1.0 already gets publisher-changed from the registry checks.
    const findings = [diff("diff-publisher-changed", "high", "depward-fixture-takeover", "1.1.0"), diff("diff-new-dependency", "low", "depward-fixture-takeover", "1.1.0")];
    const d = await checkSpecs(["depward-fixture-takeover"], opts(fake(findings).diffUpdate));
    const ids = d.packages[0]?.findings.map((x) => x.finding.id) ?? [];
    expect(ids).toContain("publisher-changed");
    expect(ids).toContain("diff-new-dependency");
    expect(ids).not.toContain("diff-publisher-changed");
  });

  test("failed lookups while diffing, and a callback that throws, cost onError", async () => {
    const failed = await checkSpecs(["depward-fixture-stable"], opts(fake([], [new DepwardError("NETWORK", "offline")]).diffUpdate));
    expect(failed.packages[0]?.errorAction).toBe("ask");
    expect(failed.action).toBe("ask");

    const thrown = await checkSpecs(["depward-fixture-stable"], opts(async () => {
      throw new Error("boom");
    }, { onError: "deny" }));
    expect(thrown.packages[0]?.errors.map((e) => e.code)).toEqual(["INTERNAL"]);
    expect(thrown.packages[0]?.update).toBeNull();
    expect(thrown.action).toBe("deny");
  });

  test("not called when the registry stage decides, or the package is allow-listed", async () => {
    const { diffUpdate, calls } = fake([diff("diff-new-obfuscation", "critical")]);
    await checkSpecs(["depward-fixture-hallucinated"], opts(diffUpdate));
    const allowed = await checkSpecs(["depward-fixture-stable"], opts(diffUpdate, { allow: ["depward-fixture-stable"] }));
    expect(calls).toEqual([]);
    expect(allowed.action).toBe("allow");
  });
});

import { findingDocsUrl, parseConfig, type Finding, type Severity } from "@depward/core";
import { createPolicy } from "@depward/gate";
import { describe, expect, test } from "vitest";
import { applyPolicy, reachesFailOn, type PackageChangeResult } from "../src/index.ts";

const f = (id: string, severity: Severity): Finding => ({ id, severity, package: "fx-a", version: "1.0.1", message: id, evidence: [], docsUrl: findingDocsUrl(id) });
const result = (findings: Finding[], extra: Partial<PackageChangeResult> = {}): PackageChangeResult => ({
  kind: "updated",
  name: "fx-a",
  from: "1.0.0",
  to: "1.0.1",
  lockfiles: ["package-lock.json"],
  findings,
  errors: [],
  risk: "critical",
  ...extra,
});
const policy = (config: Record<string, unknown> = {}) => createPolicy(parseConfig(config, "depward.config.json"));
const ids = (fs: readonly Finding[] | undefined) => (fs ?? []).map((x) => x.id);

describe("applyPolicy", () => {
  const two = [f("diff-new-install-script", "high"), f("diff-publisher-changed", "high"), f("diff-new-endpoint", "medium")];

  test("without config, risk follows the diff rules", () => {
    const r = applyPolicy(result(two), policy());
    expect(r.risk).toBe("critical");
    expect(ids(r.findings)).toEqual(["diff-new-install-script", "diff-publisher-changed", "diff-new-endpoint"]);
    expect(r.allowedFindings).toEqual([]);
    expect(r.listed).toBeNull();
  });

  test("a policy override to allow moves the finding out of the risk", () => {
    const r = applyPolicy(result(two), policy({ policy: { "diff-publisher-changed": "allow" } }));
    expect(ids(r.findings)).toEqual(["diff-new-install-script", "diff-new-endpoint"]);
    expect(ids(r.allowedFindings)).toEqual(["diff-publisher-changed"]);
    expect(r.risk).toBe("high");
  });

  test("ask and deny overrides don't change diff risk", () => {
    const r = applyPolicy(result([f("diff-new-endpoint", "medium")], { risk: "medium" }), policy({ policy: { "diff-new-endpoint": "deny" } }));
    expect(r.risk).toBe("medium");
    expect(ids(r.findings)).toEqual(["diff-new-endpoint"]);
  });

  test("an allow-listed package is reported but counts nothing", () => {
    const r = applyPolicy(result(two), policy({ allow: ["fx-*"] }));
    expect(r.findings).toEqual([]);
    expect(ids(r.allowedFindings)).toHaveLength(3);
    expect(r.risk).toBe("info");
    expect(r.listed).toEqual({ list: "allow", entry: "fx-*" });
  });

  test("a deny-listed version is critical and gets denylisted", () => {
    const r = applyPolicy(result([], { risk: "info" }), policy({ deny: ["fx-a@1.0.1"] }));
    expect(ids(r.findings)).toEqual(["denylisted"]);
    expect(r.risk).toBe("critical");
    expect(applyPolicy(result([], { risk: "info" }), policy({ deny: ["fx-a@1.0.0"] })).risk).toBe("info");
  });

  test("added packages keep plain max-severity risk (no two-high escalation)", () => {
    const r = applyPolicy(result([f("env-sensitive-read", "high"), f("install-script-network", "high")], { kind: "added", risk: "high" }), policy());
    expect(r.risk).toBe("high");
  });
});

const pkgs = (risk: Severity, findings: Finding[] = [f("x", risk)]) => [result(findings, { risk })];

describe("reachesFailOn", () => {
  test.each([
    ["critical", "critical", true],
    ["high", "critical", false],
    ["high", "high", true],
    ["medium", "high", false],
    ["low", "info", true],
    ["critical", "none", false],
  ] as const)("risk %s with --fail-on %s fails: %s", (risk, failOn, want) => {
    expect(reachesFailOn(pkgs(risk), failOn)).toBe(want);
  });

  test("a package without findings never fails, even at info", () => {
    expect(reachesFailOn(pkgs("info", []), "info")).toBe(false);
  });

  test("a deny-listed package fails at critical", () => {
    const denied = applyPolicy(result([], { risk: "info" }), policy({ deny: ["fx-a"] }));
    expect(reachesFailOn([denied], "critical")).toBe(true);
  });
});

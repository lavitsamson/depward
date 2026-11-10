// Policy engine: default actions, escalations, config overrides, allow/deny lists, and
// onError. Pure; no registry involved.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { SIGNAL_SEVERITY } from "@depward/analyzer";
import { DepwardError, defaultConfig, parseConfig, type Finding, type Severity } from "@depward/core";
import { describe, expect, test } from "vitest";
import { DEFAULT_ACTIONS, compileList, createPolicy, defaultAction, strictest } from "../src/index.ts";

const CATALOG = fileURLToPath(new URL("../../../docs/findings.md", import.meta.url));

function f(id: string, severity: Severity = "medium", pkg = "pkg"): Finding {
  return { id, severity, package: pkg, message: id, evidence: [], docsUrl: "" };
}

const config = (value: Record<string, unknown>) => parseConfig(value, "test");
const decide = (findings: Finding[], value: Record<string, unknown> = {}, errors: DepwardError[] = []) =>
  createPolicy(config(value)).decidePackage({ name: "pkg", version: "1.0.0", findings, errors });
const actions = (v: ReturnType<typeof decide>) => Object.fromEntries(v.findings.map((d) => [d.finding.id, `${d.action}/${d.source}`]));

describe("default actions", () => {
  test("every finding ID in docs/findings.md has a default action, and the catalog agrees with it", () => {
    const md = readFileSync(CATALOG, "utf8").replaceAll("\r\n", "\n");
    const ids = [...md.matchAll(/^### ([a-z0-9-]+)$/gm)].map((m) => m[1] as string);
    const documented = new Map(
      [...md.matchAll(/^### ([a-z0-9-]+)\n\n- \*\*Default severity:\*\* [a-z]+ \(default action: ([a-z]+)/gm)].map((m) => [m[1], m[2]]),
    );
    const emitted = ids.filter((id) => id !== "unsupported-lockfile"); // core lockfile notice, not a gate finding
    for (const id of emitted) expect(DEFAULT_ACTIONS, id).toHaveProperty([id]);
    for (const [id, action] of documented) expect(DEFAULT_ACTIONS[id as string], id).toBe(action);
    expect(Object.keys(DEFAULT_ACTIONS).toSorted()).toEqual(emitted.toSorted());
  });

  test("analyzer signals follow severity, except env-sensitive-read", () => {
    const bySeverity = { critical: "deny", high: "ask", medium: "allow", low: "allow", info: "allow" } as const;
    for (const [id, severity] of Object.entries(SIGNAL_SEVERITY)) {
      const expected = id === "env-sensitive-read" ? "allow" : bySeverity[severity];
      expect(DEFAULT_ACTIONS[id], id).toBe(expected);
    }
  });

  test("an unknown ID falls back to its severity", () => {
    expect(defaultAction(f("future-thing", "critical"))).toBe("deny");
    expect(defaultAction(f("future-thing", "high"))).toBe("ask");
    expect(defaultAction(f("future-thing", "medium"))).toBe("allow");
    expect(defaultAction(f("__proto__", "info"))).toBe("allow");
  });

  test("strictest: deny > ask > allow, and nothing means allow", () => {
    expect(strictest([])).toBe("allow");
    expect(strictest(["allow", "ask", "allow"])).toBe("ask");
    expect(strictest(["ask", "deny", "allow"])).toBe("deny");
  });

  test("a package with no findings is allowed; the package takes its strictest finding", () => {
    expect(decide([]).action).toBe("allow");
    expect(decide([f("deprecated", "low"), f("version-too-new")]).action).toBe("ask");
    expect(decide([f("version-too-new"), f("package-not-found", "high")]).action).toBe("deny");
  });
});

describe("escalations", () => {
  test("low-downloads + package-too-new → both deny; either alone asks", () => {
    expect(actions(decide([f("low-downloads"), f("package-too-new")]))).toEqual({
      "low-downloads": "deny/escalation", "package-too-new": "deny/escalation",
    });
    expect(decide([f("low-downloads")]).action).toBe("ask");
    expect(decide([f("package-too-new")]).action).toBe("ask");
  });

  test("install-script + package-too-new or low-downloads → deny", () => {
    expect(actions(decide([f("install-script"), f("package-too-new")]))["install-script"]).toBe("deny/escalation");
    expect(actions(decide([f("install-script"), f("low-downloads")]))["install-script"]).toBe("deny/escalation");
    expect(decide([f("install-script")]).action).toBe("allow");
  });

  test("any critical finding denies, whatever its ID", () => {
    expect(actions(decide([f("future-thing", "critical")]))).toEqual({ "future-thing": "deny/default" });
    expect(actions(decide([f("hardcoded-endpoint", "critical")]))).toEqual({ "hardcoded-endpoint": "deny/escalation" });
  });

  test("escalations only look at the same package's findings", () => {
    const policy = createPolicy();
    expect(policy.decidePackage({ name: "a", version: null, findings: [f("low-downloads", "medium", "a")], errors: [] }).action).toBe("ask");
    expect(policy.decidePackage({ name: "b", version: null, findings: [f("package-too-new", "medium", "b")], errors: [] }).action).toBe("ask");
  });
});

describe("config overrides", () => {
  test("policy overrides replace the default action", () => {
    expect(actions(decide([f("version-too-new")], { policy: { "version-too-new": "allow" } }))).toEqual({ "version-too-new": "allow/config" });
    expect(decide([f("install-script")], { policy: { "install-script": "deny" } }).action).toBe("deny");
  });

  test("an explicit override beats an escalation", () => {
    const v = decide([f("low-downloads"), f("package-too-new")], { policy: { "package-too-new": "allow" } });
    expect(actions(v)).toEqual({ "low-downloads": "deny/escalation", "package-too-new": "allow/config" });
    expect(decide([f("env-exfil-pattern", "critical")], { policy: { "env-exfil-pattern": "ask" } }).action).toBe("ask");
  });

  test("an override for an ID that isn't present changes nothing", () => {
    expect(decide([], { policy: { "package-not-found": "deny" } }).action).toBe("allow");
  });
});

describe("allow and deny lists", () => {
  test("allow-listed packages are allowed, findings kept for the report", () => {
    const v = decide([f("package-not-found", "high"), f("env-exfil-pattern", "critical")], { allow: ["pkg"] });
    expect(v.action).toBe("allow");
    expect(v.listed).toEqual({ list: "allow", entry: "pkg" });
    expect(actions(v)).toEqual({ "package-not-found": "allow/allow-list", "env-exfil-pattern": "allow/allow-list" });
  });

  test("deny-listed packages are denied with a denylisted finding first", () => {
    const v = decide([f("deprecated", "low")], { deny: ["pkg@1.0.0"] });
    expect(v.action).toBe("deny");
    expect(v.listed).toEqual({ list: "deny", entry: "pkg@1.0.0" });
    expect(v.findings[0]).toMatchObject({ action: "deny", source: "deny-list", finding: { id: "denylisted", package: "pkg", version: "1.0.0" } });
    expect(v.findings[0]?.finding.docsUrl).toMatch(/findings\.md#denylisted$/);
  });

  test("deny wins when both lists match", () => {
    expect(decide([], { allow: ["pkg"], deny: ["pkg"] }).action).toBe("deny");
    expect(decide([], { allow: ["p*"], deny: ["pkg@1.0.0"] }).listed).toEqual({ list: "deny", entry: "pkg@1.0.0" });
  });

  test("an override can't un-deny a deny-listed package", () => {
    expect(decide([], { deny: ["pkg"], policy: { denylisted: "allow" } }).action).toBe("deny");
  });

  test.each([
    ["@myorg/*", "@myorg/ui", null, true],
    ["@myorg/*", "@myorg-evil/ui", null, false],
    ["@myorg/*", "@other/ui", null, false],
    ["@myorg/*", "myorg", null, false],
    ["@*/eslint-config", "@acme/eslint-config", null, true],
    ["lodash.*", "lodash.merge", null, true],
    ["lodash.*", "lodash", null, false],
    ["left-pa?", "left-pad", null, true],
    ["left-pa?", "left-pa", null, false],
    ["*", "left-pad", null, true],
    ["*", "@scope/x", null, false],
    ["**", "@scope/x", null, true],
    ["left-pad", "left-pad", "1.3.0", true],
    ["left-pad", "left-pad-evil", "1.3.0", false],
    ["left-pad", "LEFT-PAD", "1.3.0", false],
    ["event-stream@3.3.6", "event-stream", "3.3.6", true],
    ["event-stream@3.3.6", "event-stream", "3.3.5", false],
    ["event-stream@3.3.6", "event-stream", null, false],
    ["@scope/x@1.0.0-beta.1", "@scope/x", "1.0.0-beta.1", true],
    ["@myorg/*@1.0.0", "@myorg/ui", "1.0.0", true],
    ["a.b", "axb", null, false],
  ])("%s matches %s@%s: %s", (entry, name, version, expected) => {
    expect(compileList([entry], "allow").match(name, version) !== null).toBe(expected);
  });

  test("deniedByName only reports entries that hold for every version", () => {
    const policy = createPolicy(config({ deny: ["evil", "pinned@1.0.0", "@bad/*"] }));
    expect(policy.deniedByName("evil")).toEqual({ list: "deny", entry: "evil" });
    expect(policy.deniedByName("@bad/thing")).toEqual({ list: "deny", entry: "@bad/*" });
    expect(policy.deniedByName("pinned")).toBeNull();
  });

  test.each(["foo@", "foo bar", "foo@^1.0.0", "foo@1.x || 2", "@scope", "@/x", "a/b/c", "foo@1.0.0@2"])(
    "malformed entry %s is INVALID_CONFIG",
    (entry) => {
      expect(() => createPolicy(config({ allow: [entry] }))).toThrow(expect.objectContaining({ code: "INVALID_CONFIG" }));
    },
  );
});

describe("onError", () => {
  const timeout = new DepwardError("TIMEOUT", "slow");

  test("a failed lookup asks by default, never silently allows", () => {
    const v = decide([], {}, [timeout]);
    expect(v.errorAction).toBe("ask");
    expect(v.action).toBe("ask");
    expect(defaultConfig().onError).toBe("ask");
  });

  test("onError is configurable, and a deny finding still wins over it", () => {
    expect(decide([], { onError: "deny" }, [timeout]).action).toBe("deny");
    expect(decide([], { onError: "allow" }, [timeout]).action).toBe("allow");
    expect(decide([f("package-not-found", "high")], { onError: "allow" }, [timeout]).action).toBe("deny");
  });

  test("allow-listed packages don't pay onError", () => {
    const v = decide([], { allow: ["pkg"], onError: "deny" }, [timeout]);
    expect(v.errorAction).toBeNull();
    expect(v.action).toBe("allow");
  });
});

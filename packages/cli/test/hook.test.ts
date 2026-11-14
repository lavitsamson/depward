// `depward hook claude`: golden stdin → stdout files, plus timeout, config, and input
// edge cases. Offline: the registry is the recorded fixture registry.
//
// Golden files: test/golden/claude/<case>.stdin and <case>.stdout (exact bytes; an empty
// .stdout means "no opinion"). To regenerate after an intended change, run with
// DEPWARD_UPDATE_GOLDEN=1 and review the diff by hand.

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { createFixtureRegistryClient } from "@depward/core/testing";
import { claudeAdapter, createGateData, hookVerdict, preloadAnalyzer, type Decision } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { fakeRegistry } from "../../diff/test/fake-registry.ts";
import { readStdin } from "../src/hook.ts";
import { EXIT, main, type Io } from "../src/index.ts";

const FIXTURES = fileURLToPath(new URL("../../../fixtures/registry", import.meta.url));
const GOLDEN = fileURLToPath(new URL("./golden/claude", import.meta.url));
const NOW = Date.parse("2026-11-10T12:00:00.000Z");
const data = createGateData(
  [{ name: "depward-fixture-stable", weeklyDownloads: 1_234_567 }],
  [{
    name: "depward-fixture-hallucinated",
    ecosystem: "npm",
    firstSeen: "2025-01-01",
    source: "https://example.invalid/report",
    suggestion: "depward-fixture-stable",
  }],
);

// The gate loads the analyzer on first use. Load it here, so vitest's one-time transform
// of the analyzer sources isn't timed as part of the first test that needs it.
beforeAll(async () => {
  await preloadAnalyzer();
});

async function hook(stdin: string, io: Partial<Io> = {}, argv: string[] = ["hook", "claude"]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, {
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    stdin: () => Promise.resolve(stdin),
    cwd: "/nonexistent/depward-golden-project",
    env: {},
    isTTY: false,
    // Generous, so results never depend on machine speed; budget tests set their own.
    hookBudgetMs: 60_000,
    gate: { registry: createFixtureRegistryClient(FIXTURES), data, now: () => NOW },
    ...io,
  });
  return { code, out: out.join(""), err: err.join("") };
}

const payload = (command: string, extra: Record<string, unknown> = {}): string =>
  JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, cwd: "/nonexistent/x", ...extra });

const decisionOf = (out: string) =>
  (JSON.parse(out) as { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string; additionalContext?: string } }).hookSpecificOutput;

describe("golden files", () => {
  const cases = readdirSync(GOLDEN).filter((f) => f.endsWith(".stdin")).map((f) => f.slice(0, -".stdin".length)).toSorted();

  test("there is a case for every outcome", () => {
    for (const prefix of ["allow-", "ask-", "deny-", "ignore-", "invalid-"]) expect(cases.some((c) => c.startsWith(prefix)), prefix).toBe(true);
  });

  test.each(cases)("%s", async (name) => {
    const stdin = readFileSync(join(GOLDEN, `${name}.stdin`), "utf8");
    const r = await hook(stdin);
    const expectedFile = join(GOLDEN, `${name}.stdout`);
    if (process.env["DEPWARD_UPDATE_GOLDEN"] === "1") writeFileSync(expectedFile, r.out);
    expect(existsSync(expectedFile), `${name}.stdout missing`).toBe(true);
    expect(r.out).toBe(readFileSync(expectedFile, "utf8").replaceAll("\r\n", "\n"));
    expect(r.code).toBe(0);

    const prefix = name.split("-")[0];
    if (prefix === "allow" || prefix === "ignore") {
      expect(r.out).toBe("");
      expect(r.err).toBe("");
    } else {
      const d = decisionOf(r.out);
      expect(d.permissionDecision).toBe(prefix === "invalid" ? "ask" : prefix);
      expect(r.err).toBe(`${d.permissionDecisionReason}\n`);
    }
  });
});

describe("decisions", () => {
  test("deny reasons name the package, the finding, and the suggestion", async () => {
    const d = decisionOf((await hook(payload("npm i depward-fixture-hallucinated"))).out);
    expect(d.permissionDecisionReason).toMatch(/^depward: deny depward-fixture-hallucinated@latest: known-hallucinated-name — .*Did you mean depward-fixture-stable\?/);
    expect(d.permissionDecisionReason).toMatch(/Don't work around this check\./);
    expect(d.additionalContext).toBeUndefined();
  });

  test("ask also gives Claude the reason as additionalContext", async () => {
    const d = decisionOf((await hook(payload("npm i github:example/repo"))).out);
    expect(d.permissionDecision).toBe("ask");
    expect(d.additionalContext).toBe(d.permissionDecisionReason);
  });

  test("never answers allow: a clean install leaves the decision to Claude Code", async () => {
    expect((await hook(payload("npm i depward-fixture-stable"))).out).toBe("");
  });
});

describe("config", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "depward-hook-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  test("CLAUDE_PROJECT_DIR wins over the payload's cwd", async () => {
    await writeFile(join(dir, "depward.config.json"), JSON.stringify({ deny: ["depward-fixture-stable"] }));
    const r = await hook(payload("npm i depward-fixture-stable", { cwd: join(dir, "sub") }), { env: { CLAUDE_PROJECT_DIR: dir } });
    expect(decisionOf(r.out).permissionDecision).toBe("deny");
  });

  test("the update path reads the lockfile in CLAUDE_PROJECT_DIR", async () => {
    const entry = { version: "1.1.0", resolved: "https://registry.npmjs.org/depward-fixture-stable/-/depward-fixture-stable-1.1.0.tgz", integrity: `sha512-${"A".repeat(86)}==` };
    await writeFile(join(dir, "package-lock.json"), JSON.stringify({ name: "root", lockfileVersion: 3, packages: { "": { name: "root" }, "node_modules/depward-fixture-stable": entry } }));
    const r = await hook(payload("npm i depward-fixture-stable@2.0.0", { cwd: join(dir, "sub") }), { env: { CLAUDE_PROJECT_DIR: dir } });
    // The fixtures record no 1.1.0 tarball, so the diff's lookup fails and asks (onError).
    const d = decisionOf(r.out);
    expect(d.permissionDecision).toBe("ask");
    expect(d.permissionDecisionReason).toContain("depward-fixture-stable@2.0.0 (update from 1.1.0): lookup failed");
  });

  test("the payload's cwd is used without CLAUDE_PROJECT_DIR", async () => {
    await writeFile(join(dir, "depward.config.json"), JSON.stringify({ policy: { "non-registry-source": "allow" } }));
    expect((await hook(payload("npm i github:example/repo", { cwd: dir }))).out).toBe("");
  });

  test("--config is read relative to the project directory", async () => {
    await writeFile(join(dir, "strict.json"), JSON.stringify({ policy: { "non-registry-source": "deny" } }));
    const r = await hook(payload("npm i github:example/repo", { cwd: dir }), {}, ["hook", "claude", "--config", "strict.json"]);
    expect(decisionOf(r.out).permissionDecision).toBe("deny");
  });

  test("an invalid config asks instead of failing open", async () => {
    await writeFile(join(dir, "depward.config.json"), "{ nope");
    const r = await hook(payload("npm i depward-fixture-stable", { cwd: dir }));
    const d = decisionOf(r.out);
    expect(d.permissionDecision).toBe("ask");
    expect(d.permissionDecisionReason).toMatch(/^depward: the config can't be loaded: INVALID_CONFIG: /);
    expect(r.code).toBe(0);
  });

  test("onError: deny applies to a timeout", async () => {
    await writeFile(join(dir, "depward.config.json"), JSON.stringify({ onError: "deny" }));
    const slow = { ...createFixtureRegistryClient(FIXTURES), packument: () => new Promise<never>(() => {}) };
    const r = await hook(payload("npm i depward-fixture-stable", { cwd: dir }), { hookBudgetMs: 50, gate: { registry: slow, data, now: () => NOW } });
    const d = decisionOf(r.out);
    expect(d.permissionDecision).toBe("deny");
    expect(d.permissionDecisionReason).toMatch(/^depward: the check didn't finish within 0\.05 s \(onError: deny\)/);
  });
});

describe("time budget and failures", () => {
  test("a check that runs out of time asks (onError default), within the budget", async () => {
    const slow = { ...createFixtureRegistryClient(FIXTURES), packument: () => new Promise<never>(() => {}) };
    const started = performance.now();
    const r = await hook(payload("npm i depward-fixture-stable"), { hookBudgetMs: 100, gate: { registry: slow, data, now: () => NOW } });
    expect(performance.now() - started).toBeLessThan(2000);
    expect(decisionOf(r.out).permissionDecision).toBe("ask");
  });

  test("a package that takes long to analyze is cut off near the budget, not when analysis ends", async () => {
    // Analysis is synchronous, so the budget timer can't fire during it; the analyzer
    // checks the deadline between files. This package takes several seconds to analyze.
    const files: Record<string, string> = {};
    for (let i = 0; i < 60; i++) files[`lib/f${i}.js`] = `var a${i} = [${"1,".repeat(100_000)}];\n`;
    const reg = fakeRegistry({ "fx-heavy": { versions: { "1.0.0": { files } } } });
    const started = performance.now();
    const r = await hook(payload("npm i fx-heavy"), { hookBudgetMs: 300, gate: { registry: reg.client, data, now: () => NOW } });
    const elapsed = performance.now() - started;
    const d = decisionOf(r.out);
    expect(d.permissionDecision).toBe("ask");
    expect(d.permissionDecisionReason).toMatch(/TIMEOUT|didn't finish/);
    expect(elapsed).toBeLessThan(2500);
  }, 60_000);

  test("commands with no package manager don't wait on the registry at all", async () => {
    const slow = { ...createFixtureRegistryClient(FIXTURES), packument: () => new Promise<never>(() => {}) };
    expect((await hook(payload("echo hi"), { hookBudgetMs: 60_000, gate: { registry: slow, data } })).out).toBe("");
  });

  test("a failing stdin read asks", async () => {
    const r = await hook("", { stdin: () => Promise.reject(new Error("EPIPE")) });
    expect(decisionOf(r.out).permissionDecisionReason).toMatch(/^depward: the hook failed: EPIPE/);
    expect(r.code).toBe(0);
  });

  test("usage errors exit 1 (Claude Code shows a hook error)", async () => {
    expect((await hook("{}", {}, ["hook"])).code).toBe(EXIT.error);
    expect((await hook("{}", {}, ["hook", "cursor"])).err).toContain('unknown agent "cursor"');
    expect((await hook("{}", {}, ["hook", "claude", "extra"])).code).toBe(EXIT.error);
  });

  test("--help", async () => {
    const r = await hook("", {}, ["hook", "--help"]);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toContain("Usage: depward hook <agent>");
  });
});

describe("readStdin", () => {
  test("reads everything as UTF-8", async () => {
    expect(await readStdin(Readable.from([Buffer.from("{\"a\":"), Buffer.from("\"ü\"}")]))).toBe('{"a":"ü"}');
  });

  test("refuses input over 1 MB", async () => {
    await expect(readStdin(Readable.from([Buffer.alloc(1024 * 1024 + 1)]))).rejects.toThrow(/larger than/);
  });
});

describe("claudeAdapter and hookVerdict", () => {
  test("parse classifies payloads", () => {
    expect(claudeAdapter.parse({ tool_name: "Bash", tool_input: { command: "ls" } })).toEqual({ kind: "check", request: { command: "ls" } });
    expect(claudeAdapter.parse({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, cwd: "/p" }))
      .toEqual({ kind: "check", request: { command: "ls", cwd: "/p" } });
    expect(claudeAdapter.parse({ hook_event_name: "PreToolUse", tool_name: "Read" })).toEqual({ kind: "ignore" });
    expect(claudeAdapter.parse({ hook_event_name: "Stop", tool_name: "Bash" })).toEqual({ kind: "ignore" });
    expect(claudeAdapter.parse([])).toMatchObject({ kind: "invalid" });
    expect(claudeAdapter.parse({ tool_name: "Bash", tool_input: { command: 42 } })).toMatchObject({ kind: "invalid" });
  });

  test("respond: allow is silent; ask and deny are one JSON line", () => {
    expect(claudeAdapter.respond({ action: "allow", reason: "" })).toEqual({ stdout: "", exitCode: 0 });
    const deny = claudeAdapter.respond({ action: "deny", reason: "r" });
    expect(deny.stdout).toBe('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"r"}}\n');
    expect(deny.exitCode).toBe(0);
  });

  test("hookVerdict caps the reasons at five lines plus a pointer to the full report", () => {
    const decision: Decision = { action: "ask", packages: [], findings: [], reasons: Array.from({ length: 8 }, (_, i) => `ask p${i}: x`) };
    const lines = hookVerdict(decision).reason.split("\n");
    expect(lines).toHaveLength(6);
    expect(lines[5]).toBe("depward: (+3 more; run `depward check --command …` for the full report)");
    const long: Decision = { action: "deny", packages: [], findings: [], reasons: ["x".repeat(5000)] };
    expect(hookVerdict(long).reason.length).toBe(2000);
  });
});

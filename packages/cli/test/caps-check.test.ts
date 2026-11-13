import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGateData, preloadAnalyzer } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { fakeRegistry, type FakeRegistry } from "../../diff/test/fake-registry.ts";
import { EXIT, main } from "../src/index.ts";

const NOW = Date.parse("2026-11-13T12:00:00.000Z");
const data = createGateData([], []);

function registry(): FakeRegistry {
  return fakeRegistry({
    "fx-net": {
      versions: {
        "1.0.0": { files: { "index.js": 'module.exports = () => fetch("https://api.example.invalid/");\n' } },
        "2.0.0": { files: { "index.js": 'const cp = require("child_process");\nmodule.exports = () => { cp.execSync("id"); return fetch("https://api.example.invalid/"); };\n' } },
      },
    },
    "fx-pure": { versions: { "1.0.0": {} } },
  });
}

let cwd: string;
beforeAll(async () => {
  await preloadAnalyzer();
});
beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), "depward-cli-caps-check-"));
});
afterEach(async () => {
  await rm(cwd, { recursive: true, force: true });
});

async function lock(reg: FakeRegistry, packages: Record<string, string>): Promise<void> {
  const out: Record<string, unknown> = { "": { name: "root" } };
  for (const [name, version] of Object.entries(packages)) {
    out[`node_modules/${name}`] = { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: reg.integrity(name, version) };
  }
  await writeFile(join(cwd, "package-lock.json"), JSON.stringify({ name: "root", lockfileVersion: 3, packages: out }, null, 2));
}

const BASELINE = `{
  "version": 1,
  "packages": {
    "fx-net@1.0.0": { "capabilities": ["net"], "approvedBy": "static", "approvedAt": "2026-11-01" },
    "fx-pure@1.0.0": { "capabilities": [] }
  }
}
`;

async function run(argv: string[], reg: FakeRegistry) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, {
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    cwd,
    env: {},
    isTTY: false,
    now: () => 0,
    gate: { registry: reg.client, data, now: () => NOW },
  });
  return { code, out: out.join(""), err: err.join("") };
}

describe("caps check", () => {
  test("passes when every capability is approved", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "1.0.0", "fx-pure": "1.0.0" });
    await writeFile(join(cwd, "capabilities.lock.json"), BASELINE);
    const r = await run(["caps", "check"], reg);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toBe("depward caps check: info (no dependency changes)\n\n2 packages checked; 0 packages with unapproved capabilities.\n");
  });

  test("an update with a new capability fails with exit 20 (terminal report)", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0", "fx-pure": "1.0.0" });
    await writeFile(join(cwd, "capabilities.lock.json"), BASELINE);
    const r = await run(["caps", "check"], reg);
    expect(r.code).toBe(EXIT.deny);
    expect(r.out).toMatchInlineSnapshot(`
      "depward caps check: high (1 package change: 1 high)

        HIGH      fx-net 1.0.0 → 2.0.0  (updated)
                  caps-unapproved [high]: uses child_process, which is not approved: the approved entry for 1.0.0 does not list it
                    at index.js:1

      2 packages checked; 1 package with unapproved capabilities.
      Review the uses, then run: depward caps approve <name>[@version] [--cap <cap>] [--reason <text>]
      "
    `);
  });

  test("markdown and json formats", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0" });
    await writeFile(join(cwd, "capabilities.lock.json"), BASELINE);
    const md = await run(["caps", "check", "--format", "markdown"], reg);
    expect(md.code).toBe(EXIT.deny);
    expect(md.out.split("\n")[0]).toBe("## depward caps check: 1 dependency change, 1 needs review");
    expect(md.out).toContain("caps-unapproved");
    const json = await run(["caps", "check", "--json"], reg);
    const doc = JSON.parse(json.out) as { failed: boolean; counts: unknown; packages: { name: string; from: string; to: string }[] };
    expect(doc.failed).toBe(true);
    expect(doc.counts).toEqual({ checked: 1, unapproved: 1 });
    expect(doc.packages.map((p) => [p.name, p.from, p.to])).toEqual([["fx-net", "1.0.0", "2.0.0"]]);
  });

  test("the config's allow list keeps it passing", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0" });
    await writeFile(join(cwd, "capabilities.lock.json"), BASELINE);
    await writeFile(join(cwd, "depward.config.json"), JSON.stringify({ allow: ["fx-net"] }));
    const r = await run(["caps", "check"], reg);
    expect(r.code).toBe(EXIT.allow);
  });

  test("a missing capability lockfile is an error that points at scan", async () => {
    const reg = registry();
    await lock(reg, { "fx-pure": "1.0.0" });
    const r = await run(["caps", "check"], reg);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain('capabilities.lock.json not found; create it with "depward caps scan"');
  });

  test.each([
    [["caps", "check", "fx-net"], "takes no package arguments"],
    [["caps", "check", "--format", "html"], "--format must be one of"],
    [["caps", "check", "--fail-on", "severe"], "--fail-on must be one of"],
  ])("%j is a usage error", async (argv, message) => {
    const r = await run(argv, registry());
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(message);
  });
});

describe("caps approve", () => {
  test("approves the locked version, after which check passes", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0", "fx-pure": "1.0.0" });
    await writeFile(join(cwd, "capabilities.lock.json"), BASELINE);
    const r = await run(["caps", "approve", "fx-net", "--by", "alice", "--reason", "runs its helper"], reg);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toBe("Approved child_process, net for fx-net@2.0.0.\nWrote capabilities.lock.json.\n");
    const written = JSON.parse(await readFile(join(cwd, "capabilities.lock.json"), "utf8")) as { packages: Record<string, unknown> };
    expect(written.packages["fx-net@2.0.0"]).toEqual({ capabilities: ["child_process", "net"], approvedBy: "alice", approvedAt: "2026-11-13", reason: "runs its helper" });
    expect(written.packages["fx-net@1.0.0"]).toBeDefined();
    expect((await run(["caps", "check"], reg)).code).toBe(EXIT.allow);
  });

  test("--cap approves part; the rest still fails check", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0" });
    await writeFile(join(cwd, "capabilities.lock.json"), '{"version":1,"packages":{}}\n');
    const r = await run(["caps", "approve", "fx-net@2.0.0", "--cap", "net", "--by", "bob"], reg);
    expect(r.out).toBe("Approved net for fx-net@2.0.0. Still unapproved: child_process.\nWrote capabilities.lock.json.\n");
    expect((await run(["caps", "check"], reg)).code).toBe(EXIT.deny);
  });

  test("without --by, approvedBy comes from git or is manual", async () => {
    const reg = registry();
    await lock(reg, { "fx-pure": "1.0.0", "fx-net": "1.0.0" });
    const r = await run(["caps", "approve", "fx-net"], reg);
    expect(r.code).toBe(EXIT.allow);
    const written = JSON.parse(await readFile(join(cwd, "capabilities.lock.json"), "utf8")) as { packages: Record<string, { approvedBy?: string }> };
    expect(written.packages["fx-net@1.0.0"]?.approvedBy).toMatch(/\S/);
  });

  test("errors write nothing", async () => {
    const reg = registry();
    await lock(reg, { "fx-pure": "1.0.0" });
    await writeFile(join(cwd, "capabilities.lock.json"), BASELINE);
    const notLocked = await run(["caps", "approve", "fx-net"], reg);
    expect(notLocked.code).toBe(EXIT.error);
    expect(notLocked.err).toContain("fx-net is not locked as a registry package");
    const unused = await run(["caps", "approve", "fx-pure", "--cap", "net"], reg);
    expect(unused.code).toBe(EXIT.error);
    expect(unused.err).toContain("fx-pure@1.0.0 does not use net");
    expect(await readFile(join(cwd, "capabilities.lock.json"), "utf8")).toBe(BASELINE);
  });

  test("needs a package", async () => {
    const r = await run(["caps", "approve"], registry());
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain("give at least one package");
  });
});

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DepwardError } from "@depward/core";
import { createGateData, preloadAnalyzer } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { fakeRegistry, type FakeRegistry } from "../../diff/test/fake-registry.ts";
import { EXIT, main } from "../src/index.ts";

const NOW = Date.parse("2026-11-13T12:00:00.000Z");
const data = createGateData([], []);

function registry(): FakeRegistry {
  return fakeRegistry({
    "fx-net": { versions: { "1.0.0": { files: { "index.js": 'module.exports = () => fetch("https://api.example.invalid/");\n' } } } },
    "fx-pure": { versions: { "1.0.0": {} } },
  });
}

let cwd: string;
beforeAll(async () => {
  await preloadAnalyzer();
});
beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), "depward-cli-caps-"));
});
afterEach(async () => {
  await rm(cwd, { recursive: true, force: true });
});

async function lock(reg: FakeRegistry, packages: Record<string, string>, extra: Record<string, unknown> = {}): Promise<void> {
  const out: Record<string, unknown> = { "": { name: "root" }, ...extra };
  for (const [name, version] of Object.entries(packages)) {
    out[`node_modules/${name}`] = { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: reg.integrity(name, version) };
  }
  await writeFile(join(cwd, "package-lock.json"), JSON.stringify({ name: "root", lockfileVersion: 3, packages: out }));
}

async function run(argv: string[], reg: FakeRegistry = registry()) {
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

const EXPECTED = `{
  "version": 1,
  "packages": {
    "fx-net@1.0.0": {
      "capabilities": [
        "net"
      ],
      "approvedBy": "static",
      "approvedAt": "2026-11-13"
    },
    "fx-pure@1.0.0": {
      "capabilities": []
    }
  }
}
`;

describe("caps: arguments", () => {
  test("--help prints the caps usage", async () => {
    const r = await run(["caps", "--help"]);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toContain("Usage: depward caps scan");
  });

  test.each([
    [["caps"], "give a subcommand: scan"],
    [["caps", "approve"], "unknown caps subcommand"],
    [["caps", "scan", "left-pad"], "takes no package arguments"],
    [["caps", "scan", "--concurrency", "0"], "--concurrency must be"],
    [["caps", "scan", "--output", "-", "--json"], "--json conflicts with --output -"],
  ])("%j is a usage error", async (argv, message) => {
    const r = await run(argv);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(message);
    expect(r.err).toContain("Usage: depward caps scan");
  });
});

describe("caps scan", () => {
  test("writes capabilities.lock.json and prints a summary", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "1.0.0", "fx-pure": "1.0.0" }, { "node_modules/local": { resolved: "packages/local", link: true } });
    const r = await run(["caps", "scan"], reg);
    expect(r.code).toBe(EXIT.allow);
    expect(await readFile(join(cwd, "capabilities.lock.json"), "utf8")).toBe(EXPECTED);
    expect(r.out).toBe(
      "Scanned 2 packages from package-lock.json: 1 with capabilities.\nSkipped 1 non-registry entry (link).\nWrote capabilities.lock.json.\n",
    );
  });

  test("a re-scan keeps approvals and is byte-stable", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "1.0.0", "fx-pure": "1.0.0" });
    const approved = EXPECTED.replace('"approvedBy": "static",\n      "approvedAt": "2026-11-13"', '"approvedBy": "alice",\n      "approvedAt": "2026-10-01",\n      "reason": "api client"');
    await writeFile(join(cwd, "capabilities.lock.json"), approved);
    const r = await run(["caps", "scan"], reg);
    expect(r.code).toBe(EXIT.allow);
    expect(await readFile(join(cwd, "capabilities.lock.json"), "utf8")).toBe(approved);
    expect(r.out).toContain("Kept 1 approval; dropped 0 entries no longer locked.");
  });

  test("--output - prints the lockfile and moves the summary to stderr", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "1.0.0", "fx-pure": "1.0.0" });
    const r = await run(["caps", "scan", "--output", "-"], reg);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toBe(EXPECTED);
    expect(r.err).toContain("Wrote stdout.");
  });

  test("--json prints the summary as JSON", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "1.0.0" });
    const r = await run(["caps", "scan", "--json", "--output", "caps.json"], reg);
    expect(r.code).toBe(EXIT.allow);
    expect(JSON.parse(r.out)).toEqual({
      output: "caps.json",
      lockfiles: ["package-lock.json"],
      counts: { scanned: 1, withCapabilities: 1, kept: 0, dropped: 0 },
      skipped: [],
    });
    expect(await readFile(join(cwd, "caps.json"), "utf8")).toContain('"fx-net@1.0.0"');
  });

  test("a package that can't be analyzed fails the scan and nothing is written", async () => {
    const reg = registry();
    await lock(reg, { "fx-pure": "1.0.0" }, { "node_modules/fx-gone": { version: "1.0.0", resolved: "https://registry.npmjs.org/fx-gone/-/fx-gone-1.0.0.tgz", integrity: "sha512-AAAA" } });
    await writeFile(join(cwd, "capabilities.lock.json"), '{"version":1,"packages":{}}\n');
    const r = await run(["caps", "scan"], reg);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain("fx-gone@1.0.0");
    expect(r.err).toContain("nothing was written");
    expect(await readFile(join(cwd, "capabilities.lock.json"), "utf8")).toBe('{"version":1,"packages":{}}\n');
  });

  test("a network failure suggests running the scan again", async () => {
    const reg = registry();
    await lock(reg, { "fx-pure": "1.0.0" });
    const timingOut: FakeRegistry = {
      ...reg,
      client: {
        ...reg.client,
        tarball: async () => {
          throw new DepwardError("TIMEOUT", "request timed out after 8000 ms");
        },
      },
    };
    const r = await run(["caps", "scan"], timingOut);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain("TIMEOUT: fx-pure@1.0.0: request timed out");
    expect(r.err).toContain("running the scan again continues where this one stopped");
  });

  test("an invalid existing capability lockfile is an error, not overwritten", async () => {
    const reg = registry();
    await lock(reg, { "fx-pure": "1.0.0" });
    await writeFile(join(cwd, "capabilities.lock.json"), '{"version":9}');
    const r = await run(["caps", "scan"], reg);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain("INVALID_LOCKFILE: capabilities.lock.json: unsupported version 9");
    expect(await readFile(join(cwd, "capabilities.lock.json"), "utf8")).toBe('{"version":9}');
  });

  test("no lockfile is an error", async () => {
    const r = await run(["caps", "scan"]);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain("NOT_FOUND: no lockfile");
  });
});
